package main

import (
	"container/list"
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
	"time"
)

// key is one domain's signing key.
type key struct {
	domain, selector string
	signer           crypto.Signer
}

// row is the key query's answer for one domain: selector and the stored
// private key, Vault Transit ciphertext or PEM when KEY_DECRYPT=none.
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

// errUnavailable is a lookup that could not be answered: the database or
// Vault failed for a domain with nothing in the cache.
var errUnavailable = errors.New("keys: unavailable")

// entry is one cached answer: a key, or that the domain has none.
type entry struct {
	domain  string
	k       key
	has     bool
	rowID   [32]byte
	expires time.Time
	elem    *list.Element
}

// call is one in-flight fetch that concurrent misses for a domain wait on.
type call struct {
	done chan struct{}
	e    *entry
	err  error
}

// keyCache holds the keys of recently signed domains, at most size of them.
// A miss reads the domain's row and decrypts that one key; concurrent misses
// share one fetch. An entry past ttl (missTTL for a domain with no row) is
// still served at once while one background fetch reads the row again, so a
// new selector shows within ttl and no message waits on a refresh. When the
// database or Vault fails, a cached key keeps signing.
type keyCache struct {
	fetch   func(context.Context, string) (row, bool, error)
	dec     decryptor
	size    int
	ttl     time.Duration
	missTTL time.Duration
	now     func() time.Time

	mu       sync.Mutex
	entries  map[string]*entry
	lru      *list.List
	inflight map[string]*call
	withKey  int
	bg       sync.WaitGroup
}

func newKeyCache(fetch func(context.Context, string) (row, bool, error), dec decryptor, size int, ttl, missTTL time.Duration) *keyCache {
	return &keyCache{fetch: fetch, dec: dec, size: size, ttl: ttl, missTTL: missTTL, now: time.Now,
		entries: map[string]*entry{}, lru: list.New(), inflight: map[string]*call{}}
}

func rowID(r row) [32]byte {
	return sha256.Sum256([]byte(r.selector + "\x00" + r.stored))
}

// lookup is the domain's key, false when it has none, or errUnavailable.
// Only a domain with nothing cached waits for the database and Vault.
func (c *keyCache) lookup(ctx context.Context, domain string) (key, bool, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	c.mu.Lock()
	if e := c.entries[domain]; e != nil {
		c.lru.MoveToFront(e.elem)
		label := hitLabel(e)
		if !c.now().Before(e.expires) {
			label = "stale"
			if _, busy := c.inflight[domain]; !busy {
				cl := &call{done: make(chan struct{})}
				c.inflight[domain] = cl
				c.bg.Add(1)
				go c.revalidate(domain, e, cl)
			}
		}
		c.mu.Unlock()
		cacheLookups.WithLabelValues(label).Inc()
		return e.k, e.has, nil
	}
	cl, waiting := c.inflight[domain]
	if !waiting {
		cl = &call{done: make(chan struct{})}
		c.inflight[domain] = cl
	}
	c.mu.Unlock()
	cacheLookups.WithLabelValues("miss").Inc()

	if !waiting {
		c.finish(domain, cl, func() (*entry, error) { return c.refresh(ctx, domain, nil) })
	} else {
		select {
		case <-cl.done:
		case <-ctx.Done():
			return key{}, false, fmt.Errorf("%w: %w", errUnavailable, ctx.Err())
		}
	}
	if cl.err != nil {
		return key{}, false, cl.err
	}
	return cl.e.k, cl.e.has, nil
}

// revalidate reads an expired entry's row again in the background; the
// entry is served meanwhile and stays when the read fails.
func (c *keyCache) revalidate(domain string, prev *entry, cl *call) {
	defer c.bg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	c.finish(domain, cl, func() (*entry, error) { return c.refresh(ctx, domain, prev) })
}

func (c *keyCache) finish(domain string, cl *call, fetch func() (*entry, error)) {
	cl.e, cl.err = fetch()
	c.mu.Lock()
	delete(c.inflight, domain)
	c.mu.Unlock()
	close(cl.done)
}

func hitLabel(e *entry) string {
	if e.has {
		return "hit"
	}
	return "negative_hit"
}

// refresh reads the domain's row; prev is the expired entry, kept and served
// when the database or Vault fails, and reused when the row did not change.
func (c *keyCache) refresh(ctx context.Context, domain string, prev *entry) (*entry, error) {
	r, found, err := c.fetch(ctx, domain)
	if err != nil {
		keyFetchErrors.WithLabelValues("db").Inc()
		return c.stale(domain, prev, fmt.Errorf("%w: database: %w", errUnavailable, err))
	}
	if !found {
		return c.store(&entry{domain: domain, expires: c.now().Add(c.missTTL)}), nil
	}
	id := rowID(r)
	if prev != nil && prev.has && prev.rowID == id {
		return c.store(&entry{domain: domain, k: prev.k, has: true, rowID: id, expires: c.now().Add(c.ttl)}), nil
	}
	pems, err := c.dec.Decrypt(ctx, []string{r.stored})
	if err != nil {
		keyFetchErrors.WithLabelValues("vault").Inc()
		return c.stale(domain, prev, fmt.Errorf("%w: decrypt: %w", errUnavailable, err))
	}
	sg, err := parsePrivateKey(pems[0])
	if err != nil {
		keyFetchErrors.WithLabelValues("parse").Inc()
		slog.Error("keys: unusable private key, the domain is not signed", "domain", domain, "selector", r.selector, "err", err)
		return c.store(&entry{domain: domain, expires: c.now().Add(c.missTTL)}), nil
	}
	if prev != nil && prev.has && prev.k.selector != r.selector {
		slog.Info("keys: selector changed", "domain", domain, "from", prev.k.selector, "to", r.selector)
	}
	return c.store(&entry{domain: domain, k: key{domain: domain, selector: r.selector, signer: sg}, has: true, rowID: id,
		expires: c.now().Add(c.ttl)}), nil
}

// stale keeps an expired answer when it cannot be read again: a key signs
// on, a keyless domain stays unsigned, and the row is tried again after
// missTTL. An answer evicted meanwhile goes back into the cache; one replaced
// by a newer answer gives way to it. Only a domain the cache never saw is
// unavailable.
func (c *keyCache) stale(domain string, prev *entry, err error) (*entry, error) {
	if prev == nil {
		return nil, err
	}
	slog.Warn("keys: refresh failed, the cached answer stays in use", "domain", domain, "err", err)
	c.mu.Lock()
	defer c.mu.Unlock()
	switch cur := c.entries[domain]; cur {
	case nil:
		prev.expires = c.now().Add(c.missTTL)
		c.insertLocked(prev)
	case prev:
		prev.expires = c.now().Add(c.missTTL)
	default:
		return cur, nil
	}
	return prev, nil
}

func (c *keyCache) store(e *entry) *entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.entries[e.domain]; old != nil {
		c.drop(old)
	}
	c.insertLocked(e)
	return e
}

func (c *keyCache) insertLocked(e *entry) {
	e.elem = c.lru.PushFront(e)
	c.entries[e.domain] = e
	if e.has {
		c.withKey++
	}
	for c.lru.Len() > c.size {
		c.drop(c.lru.Back().Value.(*entry))
	}
	keysLoaded.Set(float64(c.withKey))
}

func (c *keyCache) drop(e *entry) {
	c.lru.Remove(e.elem)
	delete(c.entries, e.domain)
	if e.has {
		c.withKey--
	}
}

// sqlRow reads one domain's row with the key query, its one placeholder the domain.
func sqlRow(db *sql.DB, query string) func(context.Context, string) (row, bool, error) {
	return func(ctx context.Context, domain string) (row, bool, error) {
		var r row
		var stored sql.NullString
		err := db.QueryRowContext(ctx, query, domain).Scan(&r.domain, &r.selector, &stored)
		if errors.Is(err, sql.ErrNoRows) {
			return row{}, false, nil
		}
		if err != nil {
			return row{}, false, fmt.Errorf("keys: query: %w", err)
		}
		r.selector = strings.TrimSpace(r.selector)
		if r.selector == "" || !stored.Valid || stored.String == "" {
			return row{}, false, nil
		}
		r.stored = stored.String
		return r, true, nil
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
