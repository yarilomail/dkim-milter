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

Keys load on demand. The first message of a domain reads its row (`SELECT … WHERE domain = ?`, by the index on `domain`), decrypts that one key with Vault Transit and keeps it in an LRU cache of `KEY_CACHE_SIZE` entries; concurrent first messages of one domain share that one query and decrypt. A cached key is used until `KEY_CACHE_TTL_SECONDS` have passed, then the row is read again: a new selector shows within that time, and an unchanged row is not decrypted again. A domain with no row (or a key that does not decrypt or parse) is remembered as keyless for `KEY_CACHE_MISS_TTL_SECONDS` and its mail goes unsigned.

When the database or Vault fails (down, sealed), a domain with a key in the cache signs on, also past its TTL; a domain without one gets tempfail at the end of its headers, and the MTA keeps the message and retries. There is no setting for that: sending such mail unsigned would be the silent failure `milter_default_action = tempfail` is there to avoid.

The Kubernetes-auth token is kept until four fifths of its TTL and taken again on a 403. `/readyz` answers 200 once the database answers and, with Vault, one login has succeeded; no key is loaded before the first message.

Memory: a parsed RSA-2048 key takes about 5 KB of heap with its cache entry, Ed25519 under 1 KB. The default of 10 000 RSA keys is about 50 MB; the chart's limit of 128Mi leaves room for it and the process.

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
| `DKIM_SQL_QUERY` | `SELECT domain, selector, private_key_enc FROM dkim WHERE domain = $1` (`?` for mysql) | one domain's row: domain, selector, stored private key; one placeholder, the domain |
| `KEY_DECRYPT` | `vault` | `vault`: the column is Vault Transit ciphertext; `none`: the column is PEM (logged as a warning) |
| `KEY_CACHE_SIZE` | `10000` | keys held, least recently used dropped first |
| `KEY_CACHE_TTL_SECONDS` | `600` | a cached key is read again after this |
| `KEY_CACHE_MISS_TTL_SECONDS` | `60` | a keyless domain is remembered this long |
| `VAULT_ADDR` | --- | required with `vault` |
| `VAULT_ROLE` | --- | Kubernetes auth role, required with `vault` |
| `VAULT_AUTH_PATH` | `kubernetes` | auth mount |
| `VAULT_SA_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | ServiceAccount token |
| `VAULT_TRANSIT_PATH` | `transit` | Transit mount |
| `VAULT_TRANSIT_KEY` | `dkim` | Transit key |
| `VAULT_CACERT` | --- | CA file for Vault's certificate |
| `LOG_LEVEL` | --- | `debug` for more |

Logs are JSON on stdout. One line per message: `dkim: signed` with domain, selector and queue id, or the reason it was not. The queue id is the macro `i` at the end of the message (`milter_end_of_data_macros`, whose Postfix default holds `i`), or at the end of the headers for a message accepted there; at `MAIL FROM` Postfix has none yet, since `smtpd_delay_open_until_valid_rcpt` creates the queue file at the first accepted `RCPT`.

## Metrics

| Metric | What |
|:---|:---|
| `dkim_messages_total{result}` | `signed`, `no_key`, `no_from`, `tempfail`, `error` |
| `dkim_keys_loaded` | domains with a key in the cache |
| `dkim_key_cache_lookups_total{result}` | `hit`, `negative_hit` (cached as keyless), `miss` |
| `dkim_key_fetch_errors_total{stage}` | `db`, `vault`, `parse` |

## Helm

| Value | Default | What |
|:---|:---|:---|
| `image.repository` / `.tag` / `.pullPolicy` | `docker.io/0kaba0/dkim-milter` / the chart's `appVersion` / `IfNotPresent` | image; Docker Hub keeps every release, GHCR (`ghcr.io/yarilomail/dkim-milter`) is the pruned CI working set the stand pulls `develop` from |
| `replicaCount` | `1` | stateless, any number |
| `milterPort` / `metricsPort` | `8891` / `8081` | ports |
| `db.driver` | `postgres` | `postgres` or `mysql` |
| `db.dsnSecret.name` / `.key` | --- / `DB_DSN` | Secret with the DSN |
| `db.query` | --- (the driver's default) | as `DKIM_SQL_QUERY` |
| `keyDecrypt` | `vault` | `vault` or `none` |
| `keyCache.size` / `.ttlSeconds` / `.missTtlSeconds` | `10000` / `600` / `60` | as `KEY_CACHE_SIZE`, `KEY_CACHE_TTL_SECONDS`, `KEY_CACHE_MISS_TTL_SECONDS` |
| `resources.limits.memory` | `128Mi` | room for `keyCache.size` keys, see Keys |
| `vault.addr`, `vault.role` | --- | required with `vault` |
| `vault.authPath`, `.transitPath`, `.transitKey` | `kubernetes`, `transit`, `dkim` | mounts and key |
| `vault.caCertSecret` | --- | Secret with `ca.crt` |
| `vault.caCertificate.issuerRef.name` / `.kind` | --- / `Issuer` | with a name, the chart makes a cert-manager Certificate that writes `vault.caCertSecret`, whose `ca.crt` is that issuer's CA |
| `logLevel` | --- | `debug` |

The stand installs it with `helm upgrade` in `yarilo-relay`, beside yarilo-postfix; keptemail's ArgoCD application lives in `k8s_keptemail` with the cluster's other applications. The chart creates the ServiceAccount `dkim-milter`; its token is mounted only with `keyDecrypt: vault`. `helm_values/values-sandbox.yaml` reads the yarilo stand's MySQL table with Vault Transit ciphertext in `private_key_enc`, from the stand's Vault over TLS; `helm_values/values-keptemail.yaml` reads PostgreSQL with Vault Transit.

### The stand

The stand's Vault (seconddns/k8s_vault, namespace `vault`) is signed by the Issuer `yarilo-internal-ca`, which also exists in `yarilo-relay`; the chart's Certificate `dkim-milter-vault-ca` takes its `ca.crt` from there. The DSN Secret is made once from the parts of yarilo-postfix's `yarilo-mysql`, with the host OpenDKIM uses (that Secret's own `dsn` key names a host that no longer resolves):

```sh
g() { kubectl -n yarilo-relay get secret yarilo-mysql -o jsonpath="{.data.$1}" | base64 -d; }
kubectl -n yarilo-relay create secret generic dkim-milter-db \
  --from-literal=DB_DSN="$(g MYSQL_USER):$(g MYSQL_PASSWORD)@tcp(mysql.db.svc.cluster.local:3306)/$(g MYSQL_DATABASE)?parseTime=true&charset=utf8mb4"
helm upgrade --install dkim-milter helm -n yarilo-relay -f helm_values/values-sandbox.yaml
```

The DSN Secret elsewhere:

```sh
kubectl create secret generic dkim-milter-db -n <namespace> \
  --from-literal=DB_DSN='postgres://dkim:<password>@postgres-rw.postgres.svc:5432/yarilo?sslmode=require'
```

## Build and release

`app/go`, Go 1.27. `go test ./...` covers signing and verification for RSA and Ed25519, the From oversigning, key parsing, the key cache (hits, shared misses, TTL and selector rotation, keyless domains, eviction, Vault or the database down), Vault Transit with its kept token and a full milter conversation. Work lands on `develop` through pull requests; `main` takes releases only. Both branches accept changes by pull request alone, with Lint and Test green, no force-push and no deletion.

- `develop` carries `-dev.N` in `helm/Chart.yaml` (both `version` and `appVersion`, bumped in the PR that changes the image). Each merge builds the image tagged with the commit, `develop` and the `-dev.N` version.
- A merge of `develop` into `main` with a release version builds the image tagged with the commit, `latest` and `v<version>`, and creates the GitHub release with notes from git-cliff.
