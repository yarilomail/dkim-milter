// Copyright (c) 2026 The dkim-milter Authors. All rights reserved.
// Use of this source code is governed by a GNU AGPLv3 style
// license that can be found in the LICENSE file.

// dkim-milter is a Postfix milter that DKIM-signs each message with the key
// of its From domain. Settings are environment variables, listed in README.md.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/0kaba0hub/go-milter"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	level := slog.LevelInfo
	if strings.ToLower(os.Getenv("LOG_LEVEL")) == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
	if err := run(); err != nil {
		slog.Error("dkim-milter: exiting", "err", err)
		os.Exit(1)
	}
}

func openDB(cfg config) (*sql.DB, error) {
	driver := map[string]string{"postgres": "pgx", "mysql": "mysql"}[cfg.dbDriver]
	db, err := sql.Open(driver, cfg.dbDSN)
	if err != nil {
		return nil, fmt.Errorf("db: open %s: %w", cfg.dbDriver, err)
	}
	db.SetMaxOpenConns(cfg.dbMaxOpen)
	db.SetMaxIdleConns(cfg.dbMaxOpen)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return db, nil
}

func newDecryptor(cfg config) (decryptor, error) {
	if cfg.decrypt == "none" {
		slog.Warn("keys: KEY_DECRYPT=none, the database holds private keys in the clear")
		return plainKeys{}, nil
	}
	return newVaultTransit(cfg.vault)
}

// checker is a decryptor that can say whether it is reachable.
type checker interface{ Check(context.Context) error }

// readyProbeDomain is looked up by waitReady: no row has it, so the key
// query answers with no row once it runs.
const readyProbeDomain = "readiness-probe.invalid"

// waitReady sets ready once the key query runs and, with Vault, the token
// may decrypt with the Transit key; keys load on demand after that.
func waitReady(ctx context.Context, fetch func(context.Context, string) (row, bool, error), dec decryptor, ready *atomic.Bool) {
	backoff := time.Second
	for {
		_, _, err := fetch(ctx, readyProbeDomain)
		if c, ok := dec.(checker); ok && err == nil {
			err = c.Check(ctx)
		}
		if err == nil {
			ready.Store(true)
			slog.Info("dkim-milter: ready, keys load on demand")
			return
		}
		slog.Error("dkim-milter: not ready", "err", err, "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// newMilterServer is the milter listener's server: one session per
// connection, adding only the signature header.
func newMilterServer(cfg config, cache *keyCache) *milter.Server {
	return &milter.Server{
		NewMilter: func() milter.Milter { return &session{keys: cache} },
		Actions:   milter.OptAddHeader,
		Protocol:  milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo,
		// Bounds a connection that stops talking; the library also refuses
		// packets over 1 MiB, so a peer cannot make it allocate more.
		ReadTimeout:  cfg.milterRead,
		WriteTimeout: cfg.milterWrite,
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	db, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	dec, err := newDecryptor(cfg)
	if err != nil {
		return err
	}
	fetch := sqlRow(db, cfg.query)
	cache := newKeyCache(fetch, dec, cfg.cacheSize, cfg.cacheTTL, cfg.cacheMissTTL)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var ready atomic.Bool
	go waitReady(ctx, fetch, dec, &ready)

	hs := &http.Server{Addr: cfg.metricsAddr, Handler: metricsMux(ready.Load), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("dkim-milter: metrics listener", "err", err)
		}
	}()

	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("milter: listen %s: %w", cfg.listenAddr, err)
	}
	srv := newMilterServer(cfg, cache)
	slog.Info("dkim-milter: listening", "addr", cfg.listenAddr, "db", cfg.dbDriver, "decrypt", cfg.decrypt,
		"db_max_open", cfg.dbMaxOpen, "read_timeout", cfg.milterRead.String(),
		"cache_size", cfg.cacheSize, "cache_ttl", cfg.cacheTTL.String(), "miss_ttl", cfg.cacheMissTTL.String())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		slog.Info("dkim-milter: shutting down")
		_ = srv.Close()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shut)
		return nil
	case err := <-errc:
		return fmt.Errorf("milter: serve: %w", err)
	}
}
