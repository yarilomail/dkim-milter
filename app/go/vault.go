package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// vaultTransit decrypts stored keys with Vault Transit. The Kubernetes-auth
// token is kept until shortly before its TTL ends and taken again on a 403.
type vaultTransit struct {
	cfg  vaultConfig
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// statusError is a Vault answer other than 200.
type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.code, e.msg) }

func newVaultTransit(cfg vaultConfig) (*vaultTransit, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.caCert != "" {
		pemBytes, err := os.ReadFile(cfg.caCert)
		if err != nil {
			return nil, fmt.Errorf("vault: read VAULT_CACERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("vault: VAULT_CACERT %s holds no certificate", cfg.caCert)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &vaultTransit{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 15 * time.Second}, now: time.Now}, nil
}

func (v *vaultTransit) call(ctx context.Context, path, token string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("vault: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(v.cfg.addr, "/")+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vault: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		return fmt.Errorf("vault: %s: %w", path, &statusError{code: resp.StatusCode, msg: strings.Join(e.Errors, "; ")})
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("vault: %s: decode: %w", path, err)
	}
	return nil
}

// tokenFor is the kept token, or a new one when it is missing or near its end.
func (v *vaultTransit) tokenFor(ctx context.Context, fresh bool) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !fresh && v.token != "" && v.now().Before(v.expires) {
		return v.token, nil
	}
	tok, ttl, err := v.login(ctx)
	if err != nil {
		v.token = ""
		return "", err
	}
	// Renew at four fifths of the TTL, so a token never runs out mid-request.
	v.token, v.expires = tok, v.now().Add(ttl*4/5)
	return tok, nil
}

// Check logs in: /readyz waits for one success.
func (v *vaultTransit) Check(ctx context.Context) error {
	_, err := v.tokenFor(ctx, false)
	return err
}

func (v *vaultTransit) login(ctx context.Context) (string, time.Duration, error) {
	jwt, err := os.ReadFile(v.cfg.tokenFile)
	if err != nil {
		return "", 0, fmt.Errorf("vault: read service-account token: %w", err)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	in := map[string]string{"role": v.cfg.role, "jwt": strings.TrimSpace(string(jwt))}
	if err := v.call(ctx, "auth/"+v.cfg.authPath+"/login", "", in, &out); err != nil {
		return "", 0, err
	}
	if out.Auth.ClientToken == "" {
		return "", 0, fmt.Errorf("vault: login returned no token")
	}
	return out.Auth.ClientToken, time.Duration(out.Auth.LeaseDuration) * time.Second, nil
}

// Decrypt sends every ciphertext in one batch request; an item that fails is nil.
func (v *vaultTransit) Decrypt(ctx context.Context, stored []string) ([][]byte, error) {
	token, err := v.tokenFor(ctx, false)
	if err != nil {
		return nil, err
	}
	type item struct {
		Ciphertext string `json:"ciphertext"`
	}
	in := struct {
		BatchInput []item `json:"batch_input"`
	}{}
	for _, s := range stored {
		in.BatchInput = append(in.BatchInput, item{Ciphertext: strings.TrimSpace(s)})
	}
	var out struct {
		Data struct {
			BatchResults []struct {
				Plaintext string `json:"plaintext"`
				Error     string `json:"error"`
			} `json:"batch_results"`
		} `json:"data"`
	}
	err = v.call(ctx, v.cfg.transitPath+"/decrypt/"+v.cfg.transitKey, token, in, &out)
	var se *statusError
	if errors.As(err, &se) && se.code == http.StatusForbidden {
		// The kept token was revoked or outlived: one fresh login, one retry.
		if token, err = v.tokenFor(ctx, true); err != nil {
			return nil, err
		}
		err = v.call(ctx, v.cfg.transitPath+"/decrypt/"+v.cfg.transitKey, token, in, &out)
	}
	if err != nil {
		return nil, err
	}
	if len(out.Data.BatchResults) != len(stored) {
		return nil, fmt.Errorf("vault: %d results for %d ciphertexts", len(out.Data.BatchResults), len(stored))
	}
	res := make([][]byte, len(stored))
	for i, r := range out.Data.BatchResults {
		if r.Error != "" {
			slog.Error("vault: a key did not decrypt, its domain is not signed", "item", i, "err", r.Error)
			continue
		}
		p, err := base64.StdEncoding.DecodeString(r.Plaintext)
		if err != nil {
			slog.Error("vault: a plaintext is not base64, its domain is not signed", "item", i, "err", err)
			continue
		}
		res[i] = p
	}
	return res, nil
}
