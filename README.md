# dkim-milter

Postfix **milter** in Go that DKIM-signs each message with the key of its `From:` domain. One process, one job: keys per domain from a database table, private keys encrypted with Vault Transit, signing in memory.

Licensed under **AGPLv3**, see [LICENSE](LICENSE).

## Why

| Signer | Why not |
|:---|:---|
| OpenDKIM | no release since 2018 |
| dkimpy-milter | no release since 2023 |
| go-msgauth `dkim-milter` | signs every domain with one key |
| maddy, mox | whole mail servers |

## How it signs

- The domain is the one of the first address in `From:`. `From:` and the envelope sender must already agree; `mailfrom-milter` runs before it and refuses a message where they do not.
- `relaxed/simple` canonicalization; RSA or Ed25519, by the key.
- Signed fields: `From` (twice, so a `From` added later breaks the signature), `Reply-To`, `Subject`, `Date`, `To`, `Cc`, `Message-ID`, `In-Reply-To`, `References`, `MIME-Version`, `Content-Type`, `Content-Transfer-Encoding`, `List-Id`, `List-Unsubscribe`, `List-Unsubscribe-Post`.
- The `DKIM-Signature` field is inserted at the top of the header.
- The body is streamed into the signature as it arrives and never held, so memory does not grow with `message_size_limit`. A message that will not be signed is accepted at the end of its headers, and Postfix sends this milter no body for it.
- A message it cannot sign (no `From` domain, no key for the domain, a signing error) is accepted unsigned with one log line; the milter never holds or refuses mail.

## Keys

One row per domain in the table `dkim` ([schema/postgres.sql](schema/postgres.sql), [schema/mysql.sql](schema/mysql.sql)): `domain`, `selector`, `public_key`, `private_key_enc`. With `KEY_DECRYPT=vault`, `private_key_enc` is the PEM private key encrypted with the Vault Transit key `dkim`: the database, its dumps and its backups hold ciphertext only, and the encryption key never leaves Vault.

At start the signer logs in to Vault with its ServiceAccount token, decrypts every key in one batch request and keeps them in memory. `/readyz` answers 200 once that has happened. Every `KEY_RELOAD_SECONDS` it reads the table again and decrypts only rows it has not seen; a row removed from the table stops signing. A reload that fails (database or Vault unreachable, Vault sealed) keeps the loaded keys: a sealed Vault blocks only a restart of the signer, not signing. A key that does not decrypt or parse is skipped with a log line; the other domains sign.

When a domain has two rows, the first the query returns is used and a warning names the other.

### Adding a domain

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out example.org.key
openssl pkey -in example.org.key -pubout -outform DER | base64 -w0 > example.org.pub
vault write -field=ciphertext transit/encrypt/dkim plaintext="$(base64 -w0 < example.org.key)" > example.org.enc
```

```sql
INSERT INTO dkim (domain, selector, public_key, private_key_enc)
VALUES ('example.org', 's2026', '<example.org.pub>', '<example.org.enc>');
```

DNS: `s2026._domainkey.example.org. TXT "v=DKIM1; k=rsa; p=<example.org.pub>"`. For Ed25519, `openssl genpkey -algorithm ED25519`, and `k=ed25519` with the raw 32-byte public key in `p=`. Delete `example.org.key` once the row is in.

### Vault

```sh
vault secrets enable transit
vault write -f transit/keys/dkim
vault policy write dkim-milter - <<'EOF'
path "transit/decrypt/dkim" { capabilities = ["update"] }
EOF
vault write auth/kubernetes/role/dkim-milter \
  bound_service_account_names=dkim-milter \
  bound_service_account_namespaces=<namespace> \
  policies=dkim-milter ttl=10m
```

The signer only decrypts; whoever adds keys needs `transit/encrypt/dkim`.

## Postfix

```
smtpd_milters = inet:mailfrom-milter:10031, inet:dkim-milter:8891
non_smtpd_milters = inet:dkim-milter:8891
milter_default_action = tempfail
```

`tempfail` keeps mail queued while the signer is down instead of sending it unsigned.

## Environment

| Variable | Default | What |
|:---|:---|:---|
| `LISTEN_ADDR` | `0.0.0.0:8891` | milter listener |
| `METRICS_ADDR` | `0.0.0.0:8081` | `/healthz`, `/readyz`, `/metrics` |
| `DB_DRIVER` | `postgres` | `postgres` or `mysql` |
| `DB_DSN` | --- | `postgres://user:pass@host:5432/db?sslmode=...`, or for MySQL `user:pass@tcp(host:3306)/db` |
| `DKIM_SQL_QUERY` | `SELECT domain, selector, private_key_enc FROM dkim` | three columns: domain, selector, stored private key |
| `KEY_DECRYPT` | `vault` | `vault`: the column is Vault Transit ciphertext; `none`: the column is PEM (logged as a warning) |
| `KEY_RELOAD_SECONDS` | `60` | seconds between reloads; `0` loads once |
| `VAULT_ADDR` | --- | required with `vault` |
| `VAULT_ROLE` | --- | Kubernetes auth role, required with `vault` |
| `VAULT_AUTH_PATH` | `kubernetes` | auth mount |
| `VAULT_SA_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | ServiceAccount token |
| `VAULT_TRANSIT_PATH` | `transit` | Transit mount |
| `VAULT_TRANSIT_KEY` | `dkim` | Transit key |
| `VAULT_CACERT` | --- | CA file for Vault's certificate |
| `LOG_LEVEL` | --- | `debug` for more |

Logs are JSON on stdout. One line per message: `dkim: signed` with domain, selector and queue id, or the reason it was not.

## Metrics

| Metric | What |
|:---|:---|
| `dkim_messages_total{result}` | `signed`, `no_key`, `no_from`, `error` |
| `dkim_keys_loaded` | domains with a usable key |
| `dkim_keys_loaded_timestamp_seconds` | last successful load |
| `dkim_key_load_errors_total` | loads that failed as a whole |
| `dkim_key_row_errors_total` | keys that did not decrypt or parse |

## Helm

| Value | Default | What |
|:---|:---|:---|
| `image.repository` / `.tag` / `.pullPolicy` | `docker.io/0kaba0/dkim-milter` / the chart's `appVersion` / `IfNotPresent` | image; Docker Hub keeps every release, GHCR (`ghcr.io/yarilomail/dkim-milter`) is the pruned CI working set the stand pulls `develop` from |
| `replicaCount` | `1` | stateless, any number |
| `milterPort` / `metricsPort` | `8891` / `8081` | ports |
| `db.driver` | `postgres` | `postgres` or `mysql` |
| `db.dsnSecret.name` / `.key` | --- / `DB_DSN` | Secret with the DSN |
| `db.query` | as `DKIM_SQL_QUERY` | key query |
| `keyDecrypt` | `vault` | `vault` or `none` |
| `keyReloadSeconds` | `60` | reload interval |
| `vault.addr`, `vault.role` | --- | required with `vault` |
| `vault.authPath`, `.transitPath`, `.transitKey` | `kubernetes`, `transit`, `dkim` | mounts and key |
| `vault.caCertSecret` | --- | Secret with `ca.crt` |
| `logLevel` | --- | `debug` |

The chart creates the ServiceAccount `dkim-milter`; its token is mounted only with `keyDecrypt: vault`. `helm_values/values-sandbox.yaml` reads the yarilo stand's MySQL table with keys in the clear; `helm_values/values-keptemail.yaml` reads PostgreSQL with Vault Transit.

The DSN Secret:

```sh
kubectl create secret generic dkim-milter-db -n <namespace> \
  --from-literal=DB_DSN='postgres://dkim:<password>@postgres-rw.postgres.svc:5432/yarilo?sslmode=require'
```

## Build and release

`app/go`, Go 1.27. `go test ./...` covers signing and verification for RSA and Ed25519, the From oversigning, key parsing, reloads, Vault Transit and a full milter conversation. Work lands on `develop` through pull requests; `main` takes releases only. Both branches accept changes by pull request alone, with Lint and Test green, no force-push and no deletion.

- `develop` carries `-dev.N` in `helm/Chart.yaml` (both `version` and `appVersion`, bumped in the PR that changes the image). Each merge builds the image tagged with the commit, `develop` and the `-dev.N` version.
- A merge of `develop` into `main` with a release version builds the image tagged with the commit, `latest` and `v<version>`, and creates the GitHub release with notes from git-cliff.
