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

## Who may have mail signed

Only a client that logged in with SASL has mail signed; Postfix's `{auth_authen}` says who. `SIGN_AUTH` sets which logins:

- `aligned` (default): the login's domain is the `From:` domain (`bob@example.org` for `From: alice@example.org`; case ignored, a subdomain is another domain).
- `any`: every login, `From:` not compared. For a listener where only trusted accounts can authenticate, so the listener has already done the check.

Any other message (no login, a login of another domain under `aligned`, mail from a local `sendmail`) is accepted unsigned with the log line `dkim: not signed, the client may not sign for the From domain` and counted as `unauthorized`; its key is not even read. In neither mode is mail signed without a login, and there is no setting for it: a signer that signs whatever reaches its port would sign for anyone who reaches Postfix.

yarilo-postfix runs two releases:

- `dkim-milter` with `aligned` for `relay-mta`. yarilo logs in to its submission listener as the sending user, so Postfix's `sasl_username` (hence `{auth_authen}`) is that user's address, e.g. `u51@d00002.test` on the stand.
- `dkim-milter-fwd` with `any` and `SIGN_DOMAIN` for `relay-fwd`'s submission listener (587). Only yarilo's technical account logs in there; see below which key signs what.

## Forwarded mail

`relay-fwd` carries two kinds of mail: messages yarilo makes (vacation, notify, reports) and messages it passes on (a Sieve `redirect`). A redirected copy did not come from its author's domain, so that domain's key must not sign it. With `SIGN_DOMAIN` (values `signDomain`) set, the milter tells the two apart by the `Received` fields:

- Postfix does not pass the milter the `Received` it adds itself (MILTER_README, Details: hidden for Sendmail compatibility), but it does pass those of earlier hops. `SIGN_HOPS_BEFORE` (values `signHopsBefore`, default 0) is the number of Postfix hops between yarilo and this signer: every message brings their `Received`. A message with no more than that was made by yarilo and is signed with its `From` domain's key.
- A message with more `Received` was forwarded: it came in through another hop (the inbound MX, yarilo's LMTP delivery, the user's submission). It is signed with `SIGN_DOMAIN`'s key, `d=` that domain, whatever its `From` says. The author's own signature, if any, stays as it was.

The number belongs to the topology: every hop added between yarilo and the signer raises it by one. When `relay-fwd` passes mail to `relay-fwd-out`, which signs, it is 1 (`relay-fwd`'s `Received`); the `-fwd` overlays set 1.

Seen on the stand (docs-internal#266), with `relay-fwd` signing, the milter gets no `Received` with a vacation reply, three with a redirect of an external message and four with a redirect of the user's own mail; behind `relay-fwd` each count is one higher. A redirect can also bring a single `Received`, when the message reached yarilo's LMTP with no Postfix hop before it, so the number must match the layout: 0 while `relay-fwd` signs, 1 behind it. The `-fwd` overlays carry 1 and go out with `relay-fwd-out`. A wrong call can only go one way: yarilo writes the headers of its own mail, so a `Received` there is never forged, and a misread message gets the forwarder's key, never the user's.

A login is still required, and `SIGN_DOMAIN` needs its own row in the `dkim` table (selector and key as for any domain) plus its DNS record. Without a row, forwarded mail goes unsigned as `no_key`. Without `SIGN_DOMAIN` the `Received` fields change nothing.

`SIGN_DOMAIN` belongs only on the listener where yarilo's Sieve sender logs in. Never set it on a listener for mail clients: a client's own MTA, a smarthost or yarilo's submission adds a `Received`, and the user's mail would be signed with the forwarder's key. On those listeners `aligned` decides by the login alone.

On a single host one Postfix takes every role, with the milter set per listener in `master.cf` (`-o smtpd_milters=...`):

| Listener | Who connects | Signer |
|:---|:---|:---|
| 587, 465 | mail clients, SASL login | `dkim-milter`, `aligned`, no `SIGN_DOMAIN` |
| yarilo's Sieve sender (submission, its technical account) | yarilo only | `dkim-milter-fwd`, `any`, `SIGN_DOMAIN` |
| 25 | inbound mail | none |

`relay-fwd`'s port 25 runs no signer. Postfix sends `{auth_authen}` with `MAIL FROM` by default (`milter_mail_macros`).

## Keys

Rows in the table `dkim` ([schema/postgres.sql](schema/postgres.sql), [schema/mysql.sql](schema/mysql.sql)): `domain`, `selector`, `public_key`, `private_key_enc`, `created_at`. A domain may have one row per selector; its newest row signs (`ORDER BY created_at DESC, id DESC`), and the domain is compared without case and surrounding spaces, so `Example.ORG ` in the table still signs mail of `example.org`. With `KEY_DECRYPT=vault`, `private_key_enc` is the PEM private key encrypted with the Vault Transit key `dkim`: the database, its dumps and its backups hold ciphertext only, and the encryption key never leaves Vault.

Keys load on demand. The first message of a domain reads its row (by the index on `lower(trim(domain))`), decrypts that one key with Vault Transit and keeps it in an LRU cache of `KEY_CACHE_SIZE` entries; concurrent first messages of one domain share that one query and decrypt. Only that first message waits on the database and Vault. Once `KEY_CACHE_TTL_SECONDS` have passed, the cached key goes on signing while one background read takes the row again: a new selector shows within that time, an unchanged row is not decrypted again, and a slow database or a restart of it holds no message. A domain with no row (or a key that does not decrypt or parse) is remembered as keyless for `KEY_CACHE_MISS_TTL_SECONDS` and its mail goes unsigned. The pool holds `DB_MAX_OPEN_CONNS` connections.

When the database or Vault fails (down, sealed), the cache keeps answering from what it has, also past the TTLs: a domain with a key signs on, a domain cached as keyless goes unsigned as before. Only a domain the cache has not seen gets tempfail at the end of its headers, and the MTA keeps the message and retries. There is no setting for that: sending such mail unsigned would be the silent failure `milter_default_action = tempfail` is there to avoid.

The Kubernetes-auth token is kept until four fifths of its TTL (for good, when Vault gives it no TTL) and taken again on a 403.

`/readyz` answers 200 once the key query has run for the domain `readiness-probe.invalid` (no row is the expected answer) and, with Vault, a login has succeeded and Vault says that token may `update` `transit/decrypt/<key>`. A wrong `DKIM_SQL_QUERY`, a missing table or column, or a policy without decrypt keep the pod not ready, with the reason logged, instead of a ready pod that tempfails every message. No key is loaded before the first message.

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

### Rotating a selector

1. Publish the new selector's TXT record and wait until it resolves.
2. Insert the new row for the domain. Being the newest, it signs from the next read of the row, within `KEY_CACHE_TTL_SECONDS`.
3. Once the old selector's last signatures are older than the TXT record's TTL plus `KEY_CACHE_TTL_SECONDS`, delete the old row, then its TXT record.

In that order every signature a receiver sees has its key in DNS.

### Vault

```sh
vault secrets enable transit
vault write -f transit/keys/dkim
vault policy write dkim-milter - <<'EOF'
path "transit/decrypt/dkim" { capabilities = ["update"] }
EOF
vault write auth/kubernetes/role/dkim-milter \
  bound_service_account_names=dkim-milter,dkim-milter-fwd \
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
| `DB_MAX_OPEN_CONNS` | `10` | database connections |
| `DKIM_SQL_QUERY` | `SELECT domain, selector, private_key_enc FROM dkim WHERE lower(trim(domain)) = $1 ORDER BY created_at DESC, id DESC LIMIT 1` (`?` for mysql) | one domain's row: domain, selector, stored private key; one placeholder, the lower-case domain |
| `MILTER_READ_TIMEOUT_SECONDS` | `3600` | a milter connection silent this long is closed; Postfix keeps one per SMTP session and is silent on it while the client sends |
| `MILTER_WRITE_TIMEOUT_SECONDS` | `60` | a reply Postfix does not take this long closes the connection |
| `SIGN_AUTH` | `aligned` | `aligned`: a login of the From domain; `any`: every login |
| `SIGN_DOMAIN` | --- | the forwarder's domain: forwarded mail is signed with its key (see Forwarded mail) |
| `SIGN_HOPS_BEFORE` | `0` | Postfix hops between yarilo and this signer; a message with more `Received` was forwarded (see Forwarded mail) |
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
| `dkim_messages_total{result}` | `signed`, `no_key`, `no_from`, `unauthorized` (the login may not sign for the From domain), `tempfail` (no key cached and none readable), `error` (a key that would not sign) |
| `dkim_keys_loaded` | domains with a key in the cache |
| `dkim_key_cache_lookups_total{result}` | `hit`, `negative_hit` (cached as keyless), `stale` (past its TTL, served while read again), `miss` |
| `dkim_key_fetch_errors_total{stage}` | `db`, `vault`, `parse` |

## Helm

| Value | Default | What |
|:---|:---|:---|
| `image.repository` / `.tag` / `.pullPolicy` | `docker.io/0kaba0/dkim-milter` / the chart's `appVersion` / `IfNotPresent` | image; Docker Hub keeps every release, GHCR (`ghcr.io/yarilomail/dkim-milter`) is the pruned CI working set the stand pulls `develop` from |
| `replicaCount` | `1` | stateless, any number |
| `milterPort` / `metricsPort` | `8891` / `8081` | ports |
| `milterReadTimeoutSeconds` / `milterWriteTimeoutSeconds` | `3600` / `60` | as `MILTER_READ_TIMEOUT_SECONDS`, `MILTER_WRITE_TIMEOUT_SECONDS` |
| `networkPolicy.enabled` | `false` | a NetworkPolicy: the milter port only from the Postfix pods, the metrics port from anywhere |
| `networkPolicy.postfix.podSelector` / `.namespaceSelector` | --- / --- (this namespace) | the Postfix pods that run the milter; required when enabled |
| `db.driver` | `postgres` | `postgres` or `mysql` |
| `db.dsnSecret.name` / `.key` | --- / `DB_DSN` | Secret with the DSN |
| `db.query` | --- (the driver's default) | as `DKIM_SQL_QUERY` |
| `db.maxOpenConns` | `10` | as `DB_MAX_OPEN_CONNS` |
| `keyDecrypt` | `vault` | `vault` or `none` |
| `signAuth` | `aligned` | as `SIGN_AUTH` |
| `signDomain` | `""` | as `SIGN_DOMAIN`; the `-fwd` overlays set `fwd.d00001.test` (stand) and `fwd.keptemail.com` |
| `signHopsBefore` | `0` | as `SIGN_HOPS_BEFORE`; the `-fwd` overlays set 1 |
| `keyCache.size` / `.ttlSeconds` / `.missTtlSeconds` | `10000` / `600` / `60` | as `KEY_CACHE_SIZE`, `KEY_CACHE_TTL_SECONDS`, `KEY_CACHE_MISS_TTL_SECONDS` |
| `resources.limits.memory` | `128Mi` | room for `keyCache.size` keys, see Keys |
| `vault.addr`, `vault.role` | --- | required with `vault` |
| `vault.authPath`, `.transitPath`, `.transitKey` | `kubernetes`, `transit`, `dkim` | mounts and key |
| `vault.caCertSecret` | --- | Secret with `ca.crt` |
| `vault.caCertificate.issuerRef.name` / `.kind` | --- / `Issuer` | with a name, the chart makes a cert-manager Certificate that writes `vault.caCertSecret`, whose `ca.crt` is that issuer's CA |
| `logLevel` | --- | `debug` |

The chart's defaults are the code's; a test holds them equal.

The NetworkPolicy is enforced only by a CNI that implements it: Calico (the stand), Cilium, or the kube-router built into k3s (keptemail). With flannel alone it is accepted and ignored. `values-sandbox.yaml` and `values-keptemail.yaml` enable it for yarilo-postfix's `relay-mta` and `relay-fwd` in the same namespace. The `-fwd` files narrow the second release to `relay-fwd`.

The stand installs it with `helm upgrade` in `yarilo-relay`, beside yarilo-postfix; keptemail's ArgoCD application lives in `k8s_keptemail` with the cluster's other applications. Every resource is named after the release, so two releases share a namespace. The ServiceAccount is the release's name, and the Vault role binds both (see Vault). Its token is mounted only with `keyDecrypt: vault`. `helm_values/values-sandbox.yaml` reads the yarilo stand's MySQL table with Vault Transit ciphertext in `private_key_enc`, from the stand's Vault over TLS; `helm_values/values-keptemail.yaml` reads PostgreSQL with Vault Transit.

### Upgrading a table from before 0.1.0-dev.5

The key query reads `created_at` and uses the index on `lower(trim(domain))`. A table made before (the stand's has no `created_at`) takes, for MySQL:

```sql
ALTER TABLE dkim
  ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD KEY idx_domain_lookup ((lower(trim(domain))), created_at, id),
  DROP KEY idx_domain;
```

and for PostgreSQL:

```sql
ALTER TABLE dkim ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS dkim_domain_lookup ON dkim (lower(trim(domain)), created_at DESC, id DESC);
DROP INDEX IF EXISTS dkim_domain;
UPDATE dkim SET domain = lower(trim(domain)) WHERE domain <> lower(trim(domain));
ALTER TABLE dkim ADD CONSTRAINT dkim_domain_normalized CHECK (domain = lower(trim(domain)));
```

Run it before the new image: until then the new pod's key query fails and it stays not ready, while the old pod keeps signing.

### The stand

The stand's Vault (seconddns/k8s_vault, namespace `vault`) is signed by the Issuer `yarilo-internal-ca`, which also exists in `yarilo-relay`; the chart's Certificate `dkim-milter-vault-ca` takes its `ca.crt` from there. The DSN Secret is made once from the parts of yarilo-postfix's `yarilo-mysql`, with the host OpenDKIM uses (that Secret's own `dsn` key names a host that no longer resolves):

```sh
g() { kubectl -n yarilo-relay get secret yarilo-mysql -o jsonpath="{.data.$1}" | base64 -d; }
kubectl -n yarilo-relay create secret generic dkim-milter-db \
  --from-literal=DB_DSN="$(g MYSQL_USER):$(g MYSQL_PASSWORD)@tcp(mysql.db.svc.cluster.local:3306)/$(g MYSQL_DATABASE)?parseTime=true&charset=utf8mb4"
helm upgrade --install dkim-milter helm -n yarilo-relay -f helm_values/values-sandbox.yaml
helm upgrade --install dkim-milter-fwd helm -n yarilo-relay \
  -f helm_values/values-sandbox.yaml -f helm_values/values-sandbox-fwd.yaml
```

The DSN Secret elsewhere:

```sh
kubectl create secret generic dkim-milter-db -n <namespace> \
  --from-literal=DB_DSN='postgres://dkim:<password>@postgres-rw.postgres.svc:5432/yarilo?sslmode=require'
```

## Build and release

`app/go`, Go 1.27. `go test ./...` covers signing and verification for RSA and Ed25519, the From oversigning, key parsing, who may have mail signed (`aligned`, `any`, no login), the key cache (hits, shared misses, the expired key served while it is read again, selector rotation, keyless domains, eviction, a failed refresh of an evicted entry, Vault or the database down), Vault Transit with its kept token and the decrypt check, readiness on the key query, the milter read timeout, the chart's defaults against the code's, and a full milter conversation. Work lands on `develop` through pull requests; `main` takes releases only. Both branches accept changes by pull request alone, with Lint and Test green, no force-push and no deletion.

- `develop` carries `-dev.N` in `helm/Chart.yaml` (both `version` and `appVersion`, bumped in the PR that changes the image). Each merge builds the image tagged with the commit, `develop` and the `-dev.N` version, in GHCR only.
- A merge of `develop` into `main` with a release version builds the image tagged with the commit, `latest` and `<version>` in GHCR, and `latest` and `<version>` on Docker Hub (no `v`: the chart's default image tag is `appVersion`), and creates the git tag and GitHub release `v<version>` with notes from git-cliff.
- Docker Hub keeps releases and `latest` only. The manual workflow Prune Docker Hub lists every other tag (anything but `latest` and `X.Y.Z`) there and deletes them when run with `confirm`.
