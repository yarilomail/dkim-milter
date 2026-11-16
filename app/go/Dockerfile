# Bases pinned by digest, the same as the yarilo image; dependabot moves them.
FROM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

# A newer go.mod must fail the build, not fetch a toolchain.
ENV GOTOOLCHAIN=local
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -trimpath -o dkim-milter .

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# hadolint ignore=DL3018,DL3019
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /build/dkim-milter .

USER 65534:65534
EXPOSE 8891/tcp 8081/tcp

CMD ["/app/dkim-milter"]
