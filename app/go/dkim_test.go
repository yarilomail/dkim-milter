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
}

func (tb *table) fetch(_ context.Context, domain string) (row, bool, error) {
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

// After the TTL the row is read again: a new selector shows, an unchanged
// row is not decrypted again.
func TestKeyCacheTTLAndRotation(t *testing.T) {
	k1 := pkcs8PEM(t, edKey(t))
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", k1}}}
	dec := &countingDecryptor{}
	c, ck := newTestCache(tb, dec, 10)
	_, _, _ = c.lookup(t.Context(), "a.example")
	ck.add(11 * time.Minute)
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s1" || tb.count() != 2 || dec.calls.Load() != 1 {
		t.Errorf("unchanged row after TTL: selector %q, %d queries, %d decrypts; want s1, 2, 1", k.selector, tb.count(), dec.calls.Load())
	}
	tb.set("a.example", row{"a.example", "s2", pkcs8PEM(t, edKey(t))})
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s1" {
		t.Errorf("rotation visible before the TTL: %q", k.selector)
	}
	ck.add(11 * time.Minute)
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s2" || dec.calls.Load() != 2 {
		t.Errorf("after the TTL: selector %q, %d decrypts; want s2, 2", k.selector, dec.calls.Load())
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
	if _, ok, _ := c.lookup(t.Context(), "none.example"); !ok {
		t.Error("a row added after the miss TTL is not seen")
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
	srv := &milter.Server{NewMilter: func() milter.Milter { return &session{keys: s} },
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
	srv := &milter.Server{NewMilter: func() milter.Milter { return &session{keys: s} },
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
	if err := sess.Macros(milter.CodeMail, "{mail_addr}", "alice@example.org"); err != nil {
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
	srv := &milter.Server{NewMilter: func() milter.Milter { return &session{keys: c} },
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

// The chart's defaults are the code's: values.yaml's keyCache block against
// the constants loadConfig falls back to.
func TestChartCacheDefaultsMatchTheCode(t *testing.T) {
	raw, err := os.ReadFile("../../helm/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	block := string(raw)[strings.Index(string(raw), "\nkeyCache:\n"):]
	for _, tc := range []struct {
		key  string
		want int
	}{{"size", defaultCacheSize}, {"ttlSeconds", defaultCacheTTL}, {"missTtlSeconds", defaultCacheMissTTL}} {
		m := regexp.MustCompile(`\n  ` + tc.key + `: (\d+)`).FindStringSubmatch(block)
		if m == nil {
			t.Errorf("keyCache.%s not in values.yaml", tc.key)
			continue
		}
		if m[1] != strconv.Itoa(tc.want) {
			t.Errorf("keyCache.%s = %s in values.yaml, %d in the code", tc.key, m[1], tc.want)
		}
	}
}
