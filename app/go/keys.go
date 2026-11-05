package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// key is one domain's signing key.
type key struct {
	domain, selector string
	signer           crypto.Signer
}

// row is one record of the key query: domain, selector and the stored
// private key, ciphertext under Vault Transit or PEM when KEY_DECRYPT=none.
type row struct{ domain, selector, stored string }

// decryptor turns stored private keys into PEM; an item it cannot decrypt is nil
// and then fails to parse like any unusable key.
type decryptor interface {
	Decrypt(ctx context.Context, stored []string) ([][]byte, error)
}

// plainKeys is KEY_DECRYPT=none: the column holds the PEM itself.
type plainKeys struct{}

func (plainKeys) Decrypt(_ context.Context, stored []string) ([][]byte, error) {
	out := make([][]byte, len(stored))
	for i, s := range stored {
		out[i] = []byte(s)
	}
	return out, nil
}

// keyStore holds the keys in memory; a failed reload keeps the last good set.
type keyStore struct {
	read func(context.Context) ([]row, error)
	dec  decryptor

	mu     sync.Mutex
	byRow  map[string]key // sha256(domain, selector, stored) -> parsed key
	cur    atomic.Pointer[map[string]key]
	loaded atomic.Bool
}

func newKeyStore(read func(context.Context) ([]row, error), dec decryptor) *keyStore {
	s := &keyStore{read: read, dec: dec, byRow: map[string]key{}}
	empty := map[string]key{}
	s.cur.Store(&empty)
	return s
}

// lookup is the key for a domain, or false.
func (s *keyStore) lookup(domain string) (key, bool) {
	k, ok := (*s.cur.Load())[strings.ToLower(domain)]
	return k, ok
}

func rowID(r row) string {
	h := sha256.Sum256([]byte(r.domain + "\x00" + r.selector + "\x00" + r.stored))
	return string(h[:])
}

// load reads every row and decrypts only rows not seen before, so an
// unchanged table costs one query and no Vault call.
func (s *keyStore) load(ctx context.Context) error {
	rows, err := s.read(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []row
	for _, r := range rows {
		if _, ok := s.byRow[rowID(r)]; !ok {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) > 0 {
		stored := make([]string, len(fresh))
		for i, r := range fresh {
			stored[i] = r.stored
		}
		pems, err := s.dec.Decrypt(ctx, stored)
		if err != nil {
			return fmt.Errorf("keys: decrypt %d keys: %w", len(fresh), err)
		}
		for i, r := range fresh {
			sg, err := parsePrivateKey(pems[i])
			if err != nil {
				keyRowErrors.Inc()
				slog.Error("keys: unusable private key, the domain is not signed", "domain", r.domain, "selector", r.selector, "err", err)
				continue
			}
			s.byRow[rowID(r)] = key{domain: r.domain, selector: r.selector, signer: sg}
		}
	}
	next := map[string]key{}
	keep := map[string]key{}
	for _, r := range rows {
		id := rowID(r)
		k, ok := s.byRow[id]
		if !ok {
			continue
		}
		keep[id] = k
		if prev, dup := next[r.domain]; dup {
			slog.Warn("keys: more than one key for a domain, the first row is used", "domain", r.domain, "used", prev.selector, "ignored", r.selector)
			continue
		}
		next[r.domain] = k
	}
	s.byRow = keep
	s.cur.Store(&next)
	s.loaded.Store(true)
	keysLoaded.Set(float64(len(next)))
	keysLoadedAt.SetToCurrentTime()
	return nil
}

// sqlRows reads the key query; a row with an empty field is skipped.
func sqlRows(db *sql.DB, query string) func(context.Context) ([]row, error) {
	return func(ctx context.Context) ([]row, error) { return readRows(ctx, db, query) }
}

func readRows(ctx context.Context, db *sql.DB, query string) ([]row, error) {
	rs, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("keys: query: %w", err)
	}
	defer func() { _ = rs.Close() }()
	var out []row
	for rs.Next() {
		var r row
		var stored sql.NullString
		if err := rs.Scan(&r.domain, &r.selector, &stored); err != nil {
			return nil, fmt.Errorf("keys: scan: %w", err)
		}
		r.domain = strings.ToLower(strings.TrimSpace(r.domain))
		r.selector = strings.TrimSpace(r.selector)
		if r.domain == "" || r.selector == "" || !stored.Valid || stored.String == "" {
			continue
		}
		r.stored = stored.String
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("keys: rows: %w", err)
	}
	return out, nil
}

// run reloads on every tick until ctx ends; 0 loads once.
func (s *keyStore) run(ctx context.Context, every time.Duration) {
	backoff := time.Second
	for !s.loaded.Load() {
		if err := s.load(ctx); err != nil {
			keyLoadErrors.Inc()
			slog.Error("keys: first load failed, not ready", "err", err, "retry_in", backoff.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		slog.Info("keys: loaded", "domains", len(*s.cur.Load()))
	}
	if every == 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.load(ctx); err != nil {
				keyLoadErrors.Inc()
				slog.Error("keys: reload failed, the loaded keys stay in use", "err", err)
			}
		}
	}
}

// parsePrivateKey reads PKCS#8 (RSA or Ed25519) or PKCS#1 RSA, as PEM or bare base64 DER.
func parsePrivateKey(b []byte) (crypto.Signer, error) {
	der := b
	if blk, _ := pem.Decode(b); blk != nil {
		der = blk.Bytes
	} else if raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(b)), "")); err == nil {
		der = raw
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch v := k.(type) {
		case *rsa.PrivateKey:
			return v, nil
		case ed25519.PrivateKey:
			return v, nil
		}
		return nil, errors.New("keys: PKCS#8 key is neither RSA nor Ed25519")
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("keys: not a PKCS#8 or PKCS#1 private key")
}
