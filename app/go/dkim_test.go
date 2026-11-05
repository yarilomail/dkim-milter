package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0kaba0hub/go-milter"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/emersion/go-msgauth/dkim"
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func edKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pkcs8PEM(t *testing.T, k crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// txtRecord is the DNS record a verifier reads for the key.
func txtRecord(t *testing.T, k crypto.Signer) string {
	t.Helper()
	switch pub := k.Public().(type) {
	case *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	case ed25519.PublicKey:
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)
	}
	t.Fatalf("unknown key type %T", k)
	return ""
}

// verify checks a signed message as a receiver does, with the record in place of DNS.
func verify(t *testing.T, msg []byte, record string) error {
	t.Helper()
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(msg), &dkim.VerifyOptions{
		LookupTXT: func(string) ([]string, error) { return []string{record}, nil },
	})
	if err != nil {
		return err
	}
	if len(vs) != 1 {
		return errors.New("want exactly one signature")
	}
	return vs[0].Err
}

const testHeaders = "From: Alice <alice@example.org>\r\nTo: bob@example.net\r\nSubject: hello\r\n" +
	"Date: Thu, 05 Nov 2026 12:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n"

const testBody = "line one\r\nline two\r\n"

// A signature over the message verifies with the domain's record, for RSA and
// Ed25519, and a changed body or an added From breaks it.
func TestSignVerifies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signer crypto.Signer
	}{{"rsa", rsaKey(t)}, {"ed25519", edKey(t)}} {
		t.Run(tc.name, func(t *testing.T) {
			k := key{domain: "example.org", selector: "s1", signer: tc.signer}
			v, err := sign(k, []byte(testHeaders), []byte(testBody))
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("DKIM-Signature: " + v + "\r\n" + testHeaders + "\r\n" + testBody)
			rec := txtRecord(t, tc.signer)
			if err := verify(t, msg, rec); err != nil {
				t.Fatalf("signed message does not verify: %v\n%s", err, msg)
			}
			tampered := bytes.Replace(msg, []byte("line two"), []byte("line 2"), 1)
			if verify(t, tampered, rec) == nil {
				t.Error("a changed body still verifies")
			}
			extra := []byte("DKIM-Signature: " + v + "\r\nFrom: mallory@evil.example\r\n" + testHeaders + "\r\n" + testBody)
			if verify(t, extra, rec) == nil {
				t.Error("a From added after signing still verifies: From is not oversigned")
			}
		})
	}
}

func TestFromDomain(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Alice <alice@Example.ORG>", "example.org"},
		{"alice@example.org", "example.org"},
		{`"Doe, J" <j@sub.example.org>, b@other.example`, "sub.example.org"},
		{"", ""},
		{"not an address", ""},
	} {
		if got := fromDomain(tc.in); got != tc.want {
			t.Errorf("fromDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParsePrivateKey(t *testing.T) {
	r := rsaKey(t)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r)}))
	der, _ := x509.MarshalPKCS8PrivateKey(r)
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"PKCS#8 RSA PEM", pkcs8PEM(t, r), true},
		{"PKCS#8 Ed25519 PEM", pkcs8PEM(t, edKey(t)), true},
		{"PKCS#1 RSA PEM", pkcs1, true},
		{"bare base64 DER", base64.StdEncoding.EncodeToString(der), true},
		{"garbage", "not a key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePrivateKey([]byte(tc.in)); (err == nil) != tc.ok {
				t.Errorf("err = %v, ok want %v", err, tc.ok)
			}
		})
	}
}

// countingDecryptor is plainKeys that counts calls and can fail.
type countingDecryptor struct {
	calls, items atomic.Int32
	fail         atomic.Bool
	nilFor       string
	delay        time.Duration
}

func (d *countingDecryptor) Decrypt(_ context.Context, stored []string) ([][]byte, error) {
	d.calls.Add(1)
	d.items.Add(int32(len(stored)))
	time.Sleep(d.delay)
	if d.fail.Load() {
		return nil, errors.New("sealed")
	}
	out := make([][]byte, len(stored))
	for i, s := range stored {
		if s != d.nilFor {
			out[i] = []byte(s)
		}
	}
	return out, nil
}

// table is a key table in memory that counts its queries and can fail.
type table struct {
	mu      sync.Mutex
	rows    map[string]row
	queries int
	fail    bool
	// gate, when set before the cache is used, holds every query until it closes.
	gate chan struct{}
}

func (tb *table) fetch(_ context.Context, domain string) (row, bool, error) {
	if tb.gate != nil {
		<-tb.gate
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.queries++
	if tb.fail {
		return row{}, false, errors.New("database down")
	}
	r, ok := tb.rows[domain]
	return r, ok, nil
}

func (tb *table) set(d string, r row) { tb.mu.Lock(); tb.rows[d] = r; tb.mu.Unlock() }
func (tb *table) count() int          { tb.mu.Lock(); defer tb.mu.Unlock(); return tb.queries }

// clock is a settable now for TTLs.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestCache(tb *table, dec decryptor, size int) (*keyCache, *clock) {
	c := newKeyCache(tb.fetch, dec, size, 10*time.Minute, time.Minute)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c.now = ck.now
	return c, ck
}

// A miss reads one row and decrypts one key; a hit does neither.
func TestKeyCacheMissThenHit(t *testing.T) {
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", pkcs8PEM(t, edKey(t))}}}
	dec := &countingDecryptor{}
	c, _ := newTestCache(tb, dec, 10)
	for i := 0; i < 3; i++ {
		k, ok, err := c.lookup(t.Context(), "A.Example")
		if err != nil || !ok || k.selector != "s1" {
			t.Fatalf("lookup %d: %+v %v %v", i, k, ok, err)
		}
	}
	if tb.count() != 1 || dec.calls.Load() != 1 {
		t.Errorf("three lookups: %d queries, %d decrypts; want 1 and 1", tb.count(), dec.calls.Load())
	}
}

// Concurrent misses for one domain share one query and one decrypt.
func TestKeyCacheSingleflight(t *testing.T) {
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", pkcs8PEM(t, edKey(t))}}}
	dec := &countingDecryptor{delay: 50 * time.Millisecond}
	c, _ := newTestCache(tb, dec, 10)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := c.lookup(t.Context(), "a.example"); err != nil || !ok {
				t.Errorf("lookup: %v %v", ok, err)
			}
		}()
	}
	wg.Wait()
	if tb.count() != 1 || dec.calls.Load() != 1 {
		t.Errorf("50 concurrent misses: %d queries, %d decrypts; want 1 and 1", tb.count(), dec.calls.Load())
	}
}

// Past the TTL the cached key is served at once and the row is read again
// in the background: a new selector shows then, an unchanged row is not
// decrypted again.
func TestKeyCacheTTLAndRotation(t *testing.T) {
	k1 := pkcs8PEM(t, edKey(t))
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", k1}}}
	dec := &countingDecryptor{}
	c, ck := newTestCache(tb, dec, 10)
	_, _, _ = c.lookup(t.Context(), "a.example")
	ck.add(11 * time.Minute)
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s1" {
		t.Errorf("past the TTL: selector %q, want the cached s1", k.selector)
	}
	c.bg.Wait()
	if tb.count() != 2 || dec.calls.Load() != 1 {
		t.Errorf("unchanged row after TTL: %d queries, %d decrypts; want 2, 1", tb.count(), dec.calls.Load())
	}
	tb.set("a.example", row{"a.example", "s2", pkcs8PEM(t, edKey(t))})
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s1" {
		t.Errorf("rotation visible before the TTL: %q", k.selector)
	}
	ck.add(11 * time.Minute)
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s1" {
		t.Errorf("the lookup that starts the refresh: %q, want s1 served meanwhile", k.selector)
	}
	c.bg.Wait()
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s2" || dec.calls.Load() != 2 {
		t.Errorf("after the refresh: selector %q, %d decrypts; want s2, 2", k.selector, dec.calls.Load())
	}
}

// A message never waits on a refresh: with the database hanging, an expired
// key is served at once, and many such lookups start one query.
func TestKeyCacheStaleDoesNotWaitOnTheDatabase(t *testing.T) {
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", pkcs8PEM(t, edKey(t))}}}
	c, ck := newTestCache(tb, &countingDecryptor{}, 10)
	_, _, _ = c.lookup(t.Context(), "a.example")
	ck.add(11 * time.Minute)
	tb.gate = make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			if k, ok, err := c.lookup(t.Context(), "a.example"); err != nil || !ok || k.selector != "s1" {
				t.Errorf("lookup %d: %+v %v %v", i, k, ok, err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lookups of an expired key waited on the database")
	}
	close(tb.gate)
	c.bg.Wait()
	if tb.count() != 2 {
		t.Errorf("20 lookups past the TTL: %d queries in all, want 2 (the first load and one refresh)", tb.count())
	}
}

// A domain with no row is remembered for the miss TTL, then read again.
func TestKeyCacheNegative(t *testing.T) {
	tb := &table{rows: map[string]row{}}
	c, ck := newTestCache(tb, &countingDecryptor{}, 10)
	for i := 0; i < 3; i++ {
		if _, ok, err := c.lookup(t.Context(), "none.example"); ok || err != nil {
			t.Fatalf("lookup %d: %v %v", i, ok, err)
		}
	}
	if tb.count() != 1 {
		t.Errorf("three lookups of a keyless domain: %d queries, want 1", tb.count())
	}
	tb.set("none.example", row{"none.example", "s1", pkcs8PEM(t, edKey(t))})
	ck.add(61 * time.Second)
	_, _, _ = c.lookup(t.Context(), "none.example")
	c.bg.Wait()
	if _, ok, _ := c.lookup(t.Context(), "none.example"); !ok {
		t.Error("a row added after the miss TTL is not seen")
	}
}

// A refresh that fails after its entry was evicted puts the entry back:
// the key keeps signing instead of the domain going to tempfail.
func TestKeyCacheFailedRefreshOfAnEvictedEntry(t *testing.T) {
	tb := &table{rows: map[string]row{
		"a.example": {"a.example", "s1", pkcs8PEM(t, edKey(t))},
		"b.example": {"b.example", "s1", pkcs8PEM(t, edKey(t))},
	}}
	dec := &countingDecryptor{}
	c, ck := newTestCache(tb, dec, 1)
	_, _, _ = c.lookup(t.Context(), "a.example")
	ck.add(11 * time.Minute)
	dec.fail.Store(true)
	tb.set("a.example", row{"a.example", "s2", pkcs8PEM(t, edKey(t))}) // the refresh must decrypt, and fails
	tb.gate = make(chan struct{})
	_, _, _ = c.lookup(t.Context(), "a.example") // starts the refresh, held at the query
	c.mu.Lock()
	c.drop(c.entries["a.example"]) // evicted while the refresh runs
	c.mu.Unlock()
	close(tb.gate)
	c.bg.Wait()
	tb.mu.Lock()
	tb.fail = true
	tb.mu.Unlock()
	if k, ok, err := c.lookup(t.Context(), "a.example"); err != nil || !ok || k.selector != "s1" {
		t.Errorf("after a failed refresh of an evicted entry: %+v %v %v, want the cached s1", k, ok, err)
	}
	if c.withKey != 1 || len(c.entries) != 1 {
		t.Errorf("%d keys counted, %d entries; want 1 and 1", c.withKey, len(c.entries))
	}
}

// With Vault or the database down: a cached key signs on, also past its TTL;
// a domain not in the cache is unavailable, which the session turns into tempfail.
func TestKeyCacheUnavailable(t *testing.T) {
	tb := &table{rows: map[string]row{
		"cached.example": {"cached.example", "s1", pkcs8PEM(t, edKey(t))},
		"new.example":    {"new.example", "s1", pkcs8PEM(t, edKey(t))},
	}}
	dec := &countingDecryptor{}
	c, ck := newTestCache(tb, dec, 10)
	_, _, _ = c.lookup(t.Context(), "cached.example")
	_, _, _ = c.lookup(t.Context(), "keyless.example")
	for _, failure := range []string{"vault", "db"} {
		t.Run(failure, func(t *testing.T) {
			dec.fail.Store(failure == "vault")
			tb.mu.Lock()
			tb.fail = failure == "db"
			tb.mu.Unlock()
			if _, _, err := c.lookup(t.Context(), "new.example"); !errors.Is(err, errUnavailable) {
				t.Errorf("new domain: %v, want errUnavailable", err)
			}
			ck.add(11 * time.Minute)
			if k, ok, err := c.lookup(t.Context(), "cached.example"); err != nil || !ok || k.selector != "s1" {
				t.Errorf("cached domain past its TTL: %+v %v %v, want the cached key", k, ok, err)
			}
			if _, ok, err := c.lookup(t.Context(), "keyless.example"); err != nil || ok {
				t.Errorf("keyless domain past its miss TTL: %v %v, want keyless, not unavailable", ok, err)
			}
			c.bg.Wait()
			ck.add(11 * time.Minute)
			if k, ok, err := c.lookup(t.Context(), "cached.example"); err != nil || !ok || k.selector != "s1" {
				t.Errorf("cached domain after a failed refresh: %+v %v %v, want the cached key", k, ok, err)
			}
			c.bg.Wait()
		})
	}
}

// The cache holds at most size entries, dropping the least recently used.
func TestKeyCacheEviction(t *testing.T) {
	tb := &table{rows: map[string]row{}}
	for _, d := range []string{"a", "b", "c"} {
		tb.rows[d+".example"] = row{d + ".example", "s1", pkcs8PEM(t, edKey(t))}
	}
	c, _ := newTestCache(tb, &countingDecryptor{}, 2)
	_, _, _ = c.lookup(t.Context(), "a.example")
	_, _, _ = c.lookup(t.Context(), "b.example")
	_, _, _ = c.lookup(t.Context(), "a.example")
	_, _, _ = c.lookup(t.Context(), "c.example")
	before := tb.count()
	_, _, _ = c.lookup(t.Context(), "a.example")
	if tb.count() != before {
		t.Error("a, used last, was evicted")
	}
	_, _, _ = c.lookup(t.Context(), "b.example")
	if tb.count() != before+1 {
		t.Error("b, least recently used, was kept beyond the size")
	}
	if len(c.entries) != 2 || c.lru.Len() != 2 {
		t.Errorf("%d entries, %d in the list; want 2", len(c.entries), c.lru.Len())
	}
}

func TestVaultTransit(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("sa-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			if in["role"] != "dkim" || in["jwt"] != "sa-jwt" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok"}}`))
		case "/v1/transit/decrypt/dkim":
			if r.Header.Get("X-Vault-Token") != "tok" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var res []map[string]string
			for _, it := range in["batch_input"].([]any) {
				ct := it.(map[string]any)["ciphertext"].(string)
				if ct == "vault:v1:bad" {
					res = append(res, map[string]string{"error": "cipher: message authentication failed"})
					continue
				}
				res = append(res, map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("pem-of-" + ct))})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"batch_results": res}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := vaultConfig{addr: srv.URL, authPath: "kubernetes", role: "dkim", tokenFile: tokenFile, transitPath: "transit", transitKey: "dkim"}

	v, err := newVaultTransit(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := v.Decrypt(t.Context(), []string{"vault:v1:a", "vault:v1:bad", " vault:v1:b\n"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "pem-of-vault:v1:a" || out[1] != nil || string(out[2]) != "pem-of-vault:v1:b" {
		t.Errorf("results %q", out)
	}

	cfg.role = "other"
	v, _ = newVaultTransit(cfg)
	if _, err := v.Decrypt(t.Context(), []string{"vault:v1:a"}); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("a refused login gave %v", err)
	}
}

// Through a real milter conversation: the signer inserts one DKIM-Signature
// at the top, and the message with it verifies; a domain without a key passes unsigned.
func TestMilterSignsThroughTheProtocol(t *testing.T) {
	k := edKey(t)
	s, _ := newTestCache(&table{rows: map[string]row{"example.org": {"example.org", "s1", pkcs8PEM(t, k)}}}, plainKeys{}, 10)
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &milter.Server{NewMilter: func() milter.Milter { return &session{keys: s, signAuth: signAuthAligned} },
		Actions: milter.OptAddHeader, Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	big := strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123\r\n", 3<<20/66)
	for _, tc := range []struct {
		name, from, body string
		signed           bool
	}{
		{"key", "Alice <alice@example.org>", testBody, true},
		{"3 MB body in many chunks", "Alice <alice@example.org>", big, true},
		{"no key", "carol@nokey.example", testBody, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := milter.NewClientWithOptions("tcp", ln.Addr().String(), milter.ClientOptions{
				ActionMask: milter.OptAddHeader, ProtocolMask: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo,
				ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
			})
			t.Cleanup(func() { _ = cl.Close() })
			sess, err := cl.Session()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sess.Close() }()
			if err := sess.Macros(milter.CodeMail, "{auth_authen}", "user@"+fromDomain(tc.from)); err != nil {
				t.Fatal(err)
			}
			if _, err := sess.Mail("<alice@example.org>", nil); err != nil {
				t.Fatal(err)
			}
			headers := strings.Replace(testHeaders, "From: Alice <alice@example.org>", "From: "+tc.from, 1)
			for _, line := range strings.Split(strings.TrimSuffix(headers, "\r\n"), "\r\n") {
				name, value, _ := strings.Cut(line, ": ")
				if _, err := sess.HeaderField(name, value); err != nil {
					t.Fatal(err)
				}
			}
			eoh, err := sess.HeaderEnd()
			if err != nil {
				t.Fatal(err)
			}
			if !tc.signed {
				// Accepted at the end of the headers: the MTA sends no body for it.
				if eoh.Code != milter.ActAccept {
					t.Errorf("end of headers answered %c, want accept", eoh.Code)
				}
				return
			}
			mods, _, err := sess.BodyReadFrom(strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			var sig []milter.ModifyAction
			for _, m := range mods {
				if m.Code == milter.ActInsertHeader && m.HeaderName == "DKIM-Signature" {
					sig = append(sig, m)
				}
			}
			if !tc.signed {
				if len(sig) != 0 {
					t.Errorf("a domain without a key was signed: %+v", sig)
				}
				return
			}
			if len(sig) != 1 || sig[0].HeaderIndex != 0 {
				t.Fatalf("want one DKIM-Signature inserted at the top, got %+v", mods)
			}
			v := strings.ReplaceAll(sig[0].HeaderValue, "\n", "\r\n")
			msg := []byte("DKIM-Signature: " + v + "\r\n" + headers + "\r\n" + tc.body)
			if err := verify(t, msg, txtRecord(t, k)); err != nil {
				t.Errorf("the inserted signature does not verify: %v\n%s", err, msg)
			}
		})
	}
}

// Postfix has no queue id at MAIL FROM (smtpd_delay_open_until_valid_rcpt)
// and sends it with the end-of-data macros: the signed line must carry it.
func TestQueueIDFromTheEndOfData(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	k := edKey(t)
	s, _ := newTestCache(&table{rows: map[string]row{"example.org": {"example.org", "s1", pkcs8PEM(t, k)}}}, plainKeys{}, 10)
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &milter.Server{NewMilter: func() milter.Milter { return &session{keys: s, signAuth: signAuthAligned} },
		Actions: milter.OptAddHeader, Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	cl := milter.NewClientWithOptions("tcp", ln.Addr().String(), milter.ClientOptions{
		ActionMask: milter.OptAddHeader, ProtocolMask: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
	})
	t.Cleanup(func() { _ = cl.Close() })
	sess, err := cl.Session()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Macros(milter.CodeMail, "{mail_addr}", "alice@example.org", "{auth_authen}", "alice@example.org"); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Mail("<alice@example.org>", nil); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(testHeaders, "\r\n"), "\r\n") {
		name, value, _ := strings.Cut(line, ": ")
		if _, err := sess.HeaderField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sess.HeaderEnd(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Macros(milter.CodeEOB, "i", "4QzX1y2Kq9"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sess.BodyReadFrom(strings.NewReader(testBody)); err != nil {
		t.Fatal(err)
	}
	var signed map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, `"msg":"dkim: signed"`) {
			if err := json.Unmarshal([]byte(line), &signed); err != nil {
				t.Fatal(err)
			}
		}
	}
	if signed == nil {
		t.Fatalf("no signed line:\n%s", buf.String())
	}
	if signed["queue_id"] != "4QzX1y2Kq9" {
		t.Errorf("signed line queue_id = %v, want the end-of-data id 4QzX1y2Kq9", signed["queue_id"])
	}
}

// The Kubernetes-auth token is kept between decrypts, taken again near the
// end of its TTL and at once on a 403.
func TestVaultTokenReuse(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logins, decrypts atomic.Int32
	var revoked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			n := logins.Add(1)
			_, _ = fmt.Fprintf(w, `{"auth":{"client_token":"tok%d","lease_duration":600}}`, n)
		case "/v1/transit/decrypt/dkim":
			decrypts.Add(1)
			if revoked.Load() && r.Header.Get("X-Vault-Token") == "tok1" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"batch_results":[{"plaintext":"cGVt"}]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	v, err := newVaultTransit(vaultConfig{addr: srv.URL, authPath: "kubernetes", role: "dkim", tokenFile: tokenFile, transitPath: "transit", transitKey: "dkim"})
	if err != nil {
		t.Fatal(err)
	}
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	v.now = ck.now
	for i := 0; i < 3; i++ {
		if _, err := v.Decrypt(t.Context(), []string{"vault:v1:x"}); err != nil {
			t.Fatal(err)
		}
	}
	if logins.Load() != 1 {
		t.Errorf("three decrypts within the TTL: %d logins, want 1", logins.Load())
	}
	revoked.Store(true)
	if _, err := v.Decrypt(t.Context(), []string{"vault:v1:x"}); err != nil {
		t.Fatalf("after a 403: %v", err)
	}
	if logins.Load() != 2 {
		t.Errorf("a 403: %d logins, want 2 (one fresh login, then the retry)", logins.Load())
	}
	ck.add(9 * time.Minute)
	if _, err := v.Decrypt(t.Context(), []string{"vault:v1:x"}); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 3 {
		t.Errorf("past four fifths of the TTL: %d logins, want 3", logins.Load())
	}
}

// Through the protocol with Vault down: a domain with no key in the cache gets
// tempfail at the end of the headers; a cached one is signed.
func TestMilterTempfailsAnUncachedDomainWhenVaultIsDown(t *testing.T) {
	cached, fresh := edKey(t), edKey(t)
	dec := &countingDecryptor{}
	tb := &table{rows: map[string]row{
		"example.org": {"example.org", "s1", pkcs8PEM(t, cached)},
		"new.example": {"new.example", "s1", pkcs8PEM(t, fresh)},
	}}
	c, _ := newTestCache(tb, dec, 10)
	if _, _, err := c.lookup(t.Context(), "example.org"); err != nil {
		t.Fatal(err)
	}
	dec.fail.Store(true)

	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &milter.Server{NewMilter: func() milter.Milter { return &session{keys: c, signAuth: signAuthAligned} },
		Actions: milter.OptAddHeader, Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	for _, tc := range []struct {
		from string
		want milter.ActionCode
	}{{"alice@example.org", milter.ActContinue}, {"bob@new.example", milter.ActTempFail}} {
		t.Run(tc.from, func(t *testing.T) {
			cl := milter.NewClientWithOptions("tcp", ln.Addr().String(), milter.ClientOptions{
				ActionMask: milter.OptAddHeader, ProtocolMask: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo,
				ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
			})
			t.Cleanup(func() { _ = cl.Close() })
			sess, err := cl.Session()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sess.Close() }()
			if err := sess.Macros(milter.CodeMail, "{auth_authen}", tc.from); err != nil {
				t.Fatal(err)
			}
			if _, err := sess.Mail("<"+tc.from+">", nil); err != nil {
				t.Fatal(err)
			}
			if _, err := sess.HeaderField("From", tc.from); err != nil {
				t.Fatal(err)
			}
			act, err := sess.HeaderEnd()
			if err != nil {
				t.Fatal(err)
			}
			if act.Code != tc.want {
				t.Errorf("end of headers answered %c, want %c", act.Code, tc.want)
			}
		})
	}
}

// A lease of 0 is a token without a TTL: one login, however long it is used.
func TestVaultTokenWithoutTTL(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok","lease_duration":0}}`))
		case "/v1/transit/decrypt/dkim":
			_, _ = w.Write([]byte(`{"data":{"batch_results":[{"plaintext":"cGVt"}]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	v, err := newVaultTransit(vaultConfig{addr: srv.URL, authPath: "kubernetes", role: "dkim", tokenFile: tokenFile, transitPath: "transit", transitKey: "dkim"})
	if err != nil {
		t.Fatal(err)
	}
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	v.now = ck.now
	for i := 0; i < 3; i++ {
		if _, err := v.Decrypt(t.Context(), []string{"vault:v1:x"}); err != nil {
			t.Fatal(err)
		}
		ck.add(24 * time.Hour)
	}
	if logins.Load() != 1 {
		t.Errorf("three decrypts a day apart with lease 0: %d logins, want 1", logins.Load())
	}
}

// Check passes only when Vault says the token may update the Transit key's
// decrypt path: a login alone is not enough.
func TestVaultCheckNeedsDecrypt(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, answer string
		code         int
		ok           bool
	}{
		{"update", `{"capabilities":["update"],"transit/decrypt/dkim":["update"]}`, 200, true},
		{"root", `{"capabilities":["root"],"transit/decrypt/dkim":["root"]}`, 200, true},
		{"read only", `{"capabilities":["read"],"transit/decrypt/dkim":["read"]}`, 200, false},
		{"deny", `{"capabilities":["deny"],"transit/decrypt/dkim":["deny"]}`, 200, false},
		{"other path only", `{"capabilities":["update"],"transit/decrypt/other":["update"]}`, 200, false},
		{"refused", `{"errors":["permission denied"]}`, 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/kubernetes/login":
					_, _ = w.Write([]byte(`{"auth":{"client_token":"tok","lease_duration":600}}`))
				case "/v1/sys/capabilities-self":
					var in struct{ Paths []string }
					if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.Paths) != 1 || in.Paths[0] != "transit/decrypt/dkim" {
						t.Errorf("capabilities asked for %v (%v), want transit/decrypt/dkim", in.Paths, err)
					}
					w.WriteHeader(tc.code)
					_, _ = w.Write([]byte(tc.answer))
				}
			}))
			defer srv.Close()
			v, err := newVaultTransit(vaultConfig{addr: srv.URL, authPath: "kubernetes", role: "dkim", tokenFile: tokenFile, transitPath: "transit", transitKey: "dkim"})
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Check(t.Context()); (err == nil) != tc.ok {
				t.Errorf("Check: %v, want ok = %v", err, tc.ok)
			}
		})
	}
}

// /readyz waits for the key query itself: a query that fails (a wrong
// DKIM_SQL_QUERY, a missing table) keeps the pod not ready; one that answers,
// with no row for the probe domain, makes it ready.
func TestWaitReadyRunsTheKeyQuery(t *testing.T) {
	var asked atomic.Value
	var fail atomic.Bool
	fail.Store(true)
	fetch := func(_ context.Context, domain string) (row, bool, error) {
		asked.Store(domain)
		if fail.Load() {
			return row{}, false, errors.New("Table 'yarilo.dkim' doesn't exist")
		}
		return row{}, false, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var ready atomic.Bool
	done := make(chan struct{})
	go func() { waitReady(ctx, fetch, plainKeys{}, &ready); close(done) }()
	time.Sleep(200 * time.Millisecond)
	if ready.Load() {
		t.Fatal("ready while the key query fails")
	}
	fail.Store(false)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not ready after the key query answered")
	}
	if !ready.Load() || asked.Load() != readyProbeDomain {
		t.Errorf("ready %v after asking for %v", ready.Load(), asked.Load())
	}
}

// The default queries take the domain's newest row, its domain compared
// without case and spaces. The SQL itself ran against MySQL 8.4 and
// PostgreSQL 18 with the schema's index; here it is pinned.
func TestDefaultQueriesTakeTheNewestRow(t *testing.T) {
	for driver, ph := range map[string]string{"postgres": "$1", "mysql": "?"} {
		q := defaultQueries[driver]
		for _, part := range []string{"WHERE lower(trim(domain)) = " + ph, "ORDER BY created_at DESC, id DESC LIMIT 1"} {
			if !strings.Contains(q, part) {
				t.Errorf("%s query %q lacks %q", driver, q, part)
			}
		}
	}
}

// The milter server run() starts closes a connection that stays silent past
// MILTER_READ_TIMEOUT_SECONDS.
func TestMilterServerClosesASilentConnection(t *testing.T) {
	c, _ := newTestCache(&table{rows: map[string]row{}}, &countingDecryptor{}, 10)
	srv := newMilterServer(config{milterRead: 200 * time.Millisecond, milterWrite: time.Second}, c)
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a silent connection: %v, want it closed by the server", err)
	}
}

// valuesScalars reads values.yaml's scalar leaves as dotted paths.
func valuesScalars(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	type level struct {
		indent int
		key    string
	}
	var stack []level
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "- ") {
			continue
		}
		indent := len(line) - len(trimmed)
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		var parts []string
		for _, l := range stack {
			parts = append(parts, l.key)
		}
		parts = append(parts, k)
		if v = strings.TrimSpace(v); v == "" {
			stack = append(stack, level{indent, k})
			continue
		}
		out[strings.Join(parts, ".")] = v
	}
	return out
}

// The chart's defaults are the code's, and each reaches the container as the
// variable loadConfig reads.
func TestChartDefaultsMatchTheCode(t *testing.T) {
	values := valuesScalars(t, "../../helm/values.yaml")
	if values["signAuth"] != signAuthAligned {
		t.Errorf("signAuth = %q in values.yaml, %q in the code", values["signAuth"], signAuthAligned)
	}
	tmpl, err := os.ReadFile("../../helm/templates/deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value, env string
		want       int
	}{
		{"keyCache.size", "KEY_CACHE_SIZE", defaultCacheSize},
		{"keyCache.ttlSeconds", "KEY_CACHE_TTL_SECONDS", defaultCacheTTL},
		{"keyCache.missTtlSeconds", "KEY_CACHE_MISS_TTL_SECONDS", defaultCacheMissTTL},
		{"db.maxOpenConns", "DB_MAX_OPEN_CONNS", defaultDBMaxOpen},
		{"milterReadTimeoutSeconds", "MILTER_READ_TIMEOUT_SECONDS", defaultMilterRead},
		{"milterWriteTimeoutSeconds", "MILTER_WRITE_TIMEOUT_SECONDS", defaultMilterWrite},
	} {
		got, ok := values[tc.value]
		if !ok {
			t.Errorf("%s not in values.yaml", tc.value)
			continue
		}
		if got != strconv.Itoa(tc.want) {
			t.Errorf("%s = %s in values.yaml, %d in the code", tc.value, got, tc.want)
		}
		wire := regexp.MustCompile(`- name: ` + tc.env + `\n\s+value: \{\{ \.Values\.` + regexp.QuoteMeta(tc.value) + ` \| quote \}\}`)
		if !wire.Match(tmpl) {
			t.Errorf("deployment.yaml does not pass %s as %s", tc.value, tc.env)
		}
	}
}

// Without a login nothing is signed. aligned signs a login of the From
// domain only; any signs every login, a foreign From too. A message not
// signed is counted as unauthorized and its key is not looked up.
func TestSigningNeedsAuth(t *testing.T) {
	tb := &table{rows: map[string]row{"example.org": {"example.org", "s1", pkcs8PEM(t, edKey(t))}}}
	c, _ := newTestCache(tb, plainKeys{}, 10)
	addr := map[string]string{}
	for _, mode := range []string{signAuthAligned, signAuthAny} {
		ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := newMilterServer(config{milterRead: time.Minute, milterWrite: time.Minute, signAuth: mode}, c)
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		addr[mode] = ln.Addr().String()
	}
	for _, tc := range []struct {
		mode, name, auth string
		signed           bool
	}{
		{signAuthAligned, "own domain", "bob@example.org", true},
		{signAuthAligned, "own domain, other case", "Bob@Example.ORG", true},
		{signAuthAligned, "foreign From", "mallory@evil.example", false},
		{signAuthAligned, "subdomain login", "bob@sub.example.org", false},
		{signAuthAligned, "domain as a suffix", "bob@notexample.org", false},
		{signAuthAligned, "login without a domain", "yarilo", false},
		{signAuthAligned, "no login", "", false},
		{signAuthAny, "foreign From", "yarilo-fwd@relay.example", true},
		{signAuthAny, "login without a domain", "yarilo", true},
		{signAuthAny, "no login", "", false},
	} {
		t.Run(tc.mode+"/"+tc.name, func(t *testing.T) {
			before := testutil.ToFloat64(signResults.WithLabelValues("unauthorized"))
			queries := tb.count()
			cl := milter.NewClientWithOptions("tcp", addr[tc.mode], milter.ClientOptions{
				ActionMask: milter.OptAddHeader, ProtocolMask: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo,
				ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
			})
			t.Cleanup(func() { _ = cl.Close() })
			sess, err := cl.Session()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sess.Close() }()
			if tc.auth != "" {
				if err := sess.Macros(milter.CodeMail, "{auth_authen}", tc.auth); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := sess.Mail("<alice@example.org>", nil); err != nil {
				t.Fatal(err)
			}
			if _, err := sess.HeaderField("From", "alice@example.org"); err != nil {
				t.Fatal(err)
			}
			act, err := sess.HeaderEnd()
			if err != nil {
				t.Fatal(err)
			}
			if got := act.Code == milter.ActContinue; got != tc.signed {
				t.Fatalf("end of headers answered %c, signing = %v, want %v", act.Code, got, tc.signed)
			}
			unauth := testutil.ToFloat64(signResults.WithLabelValues("unauthorized")) - before
			if tc.signed && unauth != 0 || !tc.signed && unauth != 1 {
				t.Errorf("unauthorized counter moved by %v", unauth)
			}
			if !tc.signed && tb.count() != queries {
				t.Error("the key was looked up for a client that may not use it")
			}
		})
	}
}

// The login from one message does not carry into the next on the connection.
func TestAuthDoesNotCarryOverToTheNextMessage(t *testing.T) {
	s := &session{signAuth: signAuthAligned}
	m := &milter.Modifier{Macros: map[string]string{"{auth_authen}": "bob@example.org"}}
	_, _ = s.MailFrom("<bob@example.org>", m)
	if !s.mayUse("example.org") {
		t.Fatal("the logged-in user may not sign")
	}
	_, _ = s.MailFrom("<x@example.org>", &milter.Modifier{Macros: map[string]string{}})
	if s.mayUse("example.org") {
		t.Error("the previous message's login still signs")
	}
}

// SIGN_AUTH: aligned by default, any accepted, anything else refused.
func TestSignAuthFromTheEnvironment(t *testing.T) {
	t.Setenv("DB_DSN", "x")
	t.Setenv("KEY_DECRYPT", "none")
	for _, tc := range []struct{ set, want string }{{"", signAuthAligned}, {"ANY", signAuthAny}, {"aligned", signAuthAligned}, {"none", ""}} {
		if tc.set != "" {
			t.Setenv("SIGN_AUTH", tc.set)
		}
		c, err := loadConfig()
		if tc.want == "" {
			if err == nil {
				t.Errorf("SIGN_AUTH %q accepted", tc.set)
			}
			continue
		}
		if err != nil || c.signAuth != tc.want {
			t.Errorf("SIGN_AUTH %q: %q %v, want %q", tc.set, c.signAuth, err, tc.want)
		}
	}
}

// Every chart resource is named after the release, so a second release
// (dkim-milter-fwd) can share the namespace.
func TestChartNamesFollowTheRelease(t *testing.T) {
	files, err := filepath.Glob("../../helm/templates/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v %v", files, err)
	}
	fixed := regexp.MustCompile(`(?m)^\s*(name|app|serviceAccountName|commonName|- ): ?dkim-milter\s*$`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range fixed.FindAll(raw, -1) {
			if strings.TrimSpace(string(m)) == "- name: dkim-milter" {
				continue // the container's name, not a resource
			}
			t.Errorf("%s: %q is fixed, not {{ .Release.Name }}", filepath.Base(f), strings.TrimSpace(string(m)))
		}
	}
}
