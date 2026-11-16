# dkim-milter

Postfix **milter** in Go that DKIM-signs each message with the key of its `From:` domain. One process, one job: keys per domain from a database table, private keys encrypted with Vault Transit, signing in memory.

Licensed under **AGPLv3**, see [LICENSE](LICENSE). **Website:** [yarilomail.org](https://yarilomail.org) · **Docs:** [DKIM signing](https://doc.yarilomail.org/main/relay/dkim_milter.html) on doc.yarilomail.org

[![CI](https://github.com/yarilomail/dkim-milter/actions/workflows/ci.yaml/badge.svg?branch=develop)](https://github.com/yarilomail/dkim-milter/actions/workflows/ci.yaml) [![Go 1.27](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](app/go/go.mod) [![Container](https://img.shields.io/badge/ghcr.io-dkim--milter-blue?logo=github)](https://github.com/yarilomail/dkim-milter/pkgs/container/dkim-milter) [![Docker Hub](https://img.shields.io/docker/pulls/0kaba0/dkim-milter?logo=docker&logoColor=white)](https://hub.docker.com/r/0kaba0/dkim-milter) [![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE) ![Status: stable](https://img.shields.io/badge/status-stable-brightgreen)

## What it does

- Signs each message with the DKIM key of its `From:` domain, RSA or Ed25519, `relaxed/simple`, `From` oversigned.
- Signs only for a client that logged in with SASL: by default a login of the `From:` domain.
- Signs a forwarded message (a Sieve `redirect`) with the forwarder's own domain instead of the author's.
- Reads keys per domain from a `dkim` table in PostgreSQL or MySQL, private keys encrypted with Vault Transit, into a bounded cache that keeps signing while the database or Vault is down.
- Never refuses mail; a message it cannot sign goes out unsigned, and only a domain it has never read waits for the key.

## Documentation

Everything about running it is on [doc.yarilomail.org](https://doc.yarilomail.org/main/relay/dkim_milter.html):

- [Signing a message](https://doc.yarilomail.org/main/relay/dkim_milter.html#signing-a-message), [who may have mail signed](https://doc.yarilomail.org/main/relay/dkim_milter.html#who-may-have-mail-signed), [forwarded mail](https://doc.yarilomail.org/main/relay/dkim_milter.html#forwarded-mail)
- [Keys](https://doc.yarilomail.org/main/relay/dkim_milter.html#keys): adding a domain, rotating a selector, upgrading an older key table
- [Vault Transit](https://doc.yarilomail.org/main/relay/dkim_milter.html#vault-transit), [Postfix configuration](https://doc.yarilomail.org/main/relay/dkim_milter.html#postfix-configuration), [readiness](https://doc.yarilomail.org/main/relay/dkim_milter.html#readiness)
- [Environment](https://doc.yarilomail.org/main/relay/dkim_milter.html#environment), [Helm chart](https://doc.yarilomail.org/main/relay/dkim_milter.html#helm-chart), [logs and metrics](https://doc.yarilomail.org/main/relay/dkim_milter.html#logs-and-metrics)

## Repository

| Path | What |
|:---|:---|
| `app/go` | the milter, Go 1.27, `go test ./...` |
| `helm` | the chart |
| `helm_values` | values for the yarilo stand and keptemail |
| `schema` | the `dkim` table for PostgreSQL and MySQL |

## Development and release

Work lands on `develop` through pull requests, with Lint and Test green; `main` takes releases only. `develop` carries `-dev.N` in `helm/Chart.yaml`, bumped in the PR that changes the image, and each merge builds the image in GHCR. A merge into `main` with a release version publishes `<version>` and `latest` to GHCR and Docker Hub and creates the release `v<version>`.
