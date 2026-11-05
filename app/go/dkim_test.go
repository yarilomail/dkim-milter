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
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
}

func (d *countingDecryptor) Decrypt(_ context.Context, stored []string) ([][]byte, error) {
	d.calls.Add(1)
	d.items.Add(int32(len(stored)))
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

func TestKeyStore(t *testing.T) {
	a, b, c := pkcs8PEM(t, edKey(t)), pkcs8PEM(t, edKey(t)), pkcs8PEM(t, edKey(t))
	var rows []row
	read := func(context.Context) ([]row, error) { return rows, nil }
	dec := &countingDecryptor{nilFor: c}
	s := newKeyStore(read, dec)
	ctx := t.Context()

	rows = []row{{"a.example", "s1", a}, {"b.example", "s1", b}, {"c.example", "s1", c}, {"a.example", "s2", b}}
	if err := s.load(ctx); err != nil {
		t.Fatal(err)
	}
	if k, ok := s.lookup("A.Example"); !ok || k.selector != "s1" {
		t.Errorf("a.example: %+v %v, want the first row's selector s1", k, ok)
	}
	if _, ok := s.lookup("c.example"); ok {
		t.Error("c.example signs although its key did not decrypt")
	}
	if dec.calls.Load() != 1 || dec.items.Load() != 4 {
		t.Errorf("first load: %d calls, %d items; want 1 and 4", dec.calls.Load(), dec.items.Load())
	}

	if err := s.load(ctx); err != nil {
		t.Fatal(err)
	}
	if dec.calls.Load() != 2 || dec.items.Load() != 5 {
		t.Errorf("unchanged table: %d calls, %d items; want only the undecryptable row again", dec.calls.Load(), dec.items.Load())
	}

	dec.fail.Store(true)
	rows = append(rows, row{"d.example", "s1", a})
	if err := s.load(ctx); err == nil {
		t.Error("a failed decrypt reported success")
	}
	if _, ok := s.lookup("b.example"); !ok {
		t.Error("a failed reload dropped the loaded keys")
	}

	dec.fail.Store(false)
	rows = []row{{"b.example", "s1", b}}
	if err := s.load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.lookup("a.example"); ok {
		t.Error("a removed row still signs")
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
	s := newKeyStore(func(context.Context) ([]row, error) {
		return []row{{"example.org", "s1", pkcs8PEM(t, k)}}, nil
	}, plainKeys{})
	if err := s.load(t.Context()); err != nil {
		t.Fatal(err)
	}
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
	s := newKeyStore(func(context.Context) ([]row, error) {
		return []row{{"example.org", "s1", pkcs8PEM(t, k)}}, nil
	}, plainKeys{})
	if err := s.load(t.Context()); err != nil {
		t.Fatal(err)
	}
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
