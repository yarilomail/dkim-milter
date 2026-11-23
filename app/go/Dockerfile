# Bases pinned by digest, the same as the yarilo image; dependabot moves them.
FROM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

# A newer go.mod must fail the build, not fetch a toolchain.
ENV GOTOOLCHAIN=local
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -trimpath -o dkim-milter .

# Named so CI can rebuild it without its layer cache: a cached apk upgrade
# keeps the packages of its first build until the base digest moves.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS runtime
# hadolint ignore=DL3018,DL3019
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /build/dkim-milter .

USER 65534:65534
EXPOSE 8891/tcp 8081/tcp

CMD ["/app/dkim-milter"]
