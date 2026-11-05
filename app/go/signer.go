package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/0kaba0hub/go-milter"
	"github.com/emersion/go-msgauth/dkim"
)

// lookupTimeout bounds one key lookup: a database query and a Vault decrypt.
const lookupTimeout = 10 * time.Second

// signedHeaders are the fields signed; From is listed twice so that a From
// added after signing breaks the signature (oversigning).
var signedHeaders = []string{
	"From", "From", "Reply-To", "Subject", "Date", "To", "Cc",
	"Message-ID", "In-Reply-To", "References", "MIME-Version",
	"Content-Type", "Content-Transfer-Encoding",
	"List-Id", "List-Unsubscribe", "List-Unsubscribe-Post",
}

// session signs one message as it streams: the signer is made at the end of
// the headers and the body goes straight into it, so no body is held.
type session struct {
	keys    *keyCache
	headers bytes.Buffer
	from    string
	queueID string

	signer *dkim.Signer
	key    key
	err    error
}

func (s *session) reset() {
	if s.signer != nil {
		_ = s.signer.Close()
	}
	s.headers.Reset()
	s.from, s.queueID = "", ""
	s.signer, s.key, s.err = nil, key{}, nil
}

func (s *session) Connect(string, string, uint16, net.IP, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *session) Helo(string, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

// MailFrom does not read the queue id: with smtpd_delay_open_until_valid_rcpt
// Postfix has none until the first accepted RCPT.
func (s *session) MailFrom(string, *milter.Modifier) (milter.Response, error) {
	s.reset()
	return milter.RespContinue, nil
}

func (s *session) RcptTo(string, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

// Header keeps the field as it came: the MTA hands folded values with LF.
func (s *session) Header(name, value string, _ *milter.Modifier) (milter.Response, error) {
	v := strings.ReplaceAll(value, "\r\n", "\n")
	v = strings.ReplaceAll(v, "\n", "\r\n")
	fmt.Fprintf(&s.headers, "%s: %s\r\n", name, v)
	if strings.EqualFold(name, "From") && s.from == "" {
		s.from = value
	}
	return milter.RespContinue, nil
}

// Headers picks the key; a message that will not be signed is accepted here,
// so the MTA sends this milter no body for it.
func (s *session) Headers(_ textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	s.queueID = m.Macros["i"]
	domain := fromDomain(s.from)
	log := slog.With("queue_id", s.queueID, "domain", domain)
	if domain == "" {
		signResults.WithLabelValues("no_from").Inc()
		log.Info("dkim: not signed, no From domain")
		return milter.RespAccept, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	k, ok, err := s.keys.lookup(ctx, domain)
	cancel()
	if err != nil {
		// lookup fails only as errUnavailable: no key in the cache and none to
		// be read now. The MTA keeps the message and tries again, rather than
		// sending it unsigned.
		signResults.WithLabelValues("tempfail").Inc()
		log.Warn("dkim: tempfail, the key cannot be read", "err", err)
		return milter.RespTempFail, nil
	}
	if !ok {
		signResults.WithLabelValues("no_key").Inc()
		log.Info("dkim: not signed, no key for the domain")
		return milter.RespAccept, nil
	}
	sg, err := newMessageSigner(k, s.headers.Bytes())
	if err != nil {
		signResults.WithLabelValues("error").Inc()
		log.Error("dkim: not signed", "err", err)
		return milter.RespAccept, nil
	}
	s.signer, s.key = sg, k
	return milter.RespContinue, nil
}

func (s *session) BodyChunk(chunk []byte, _ *milter.Modifier) (milter.Response, error) {
	if s.signer != nil && s.err == nil {
		if _, err := s.signer.Write(chunk); err != nil {
			s.err = fmt.Errorf("dkim: write body: %w", err)
		}
	}
	return milter.RespContinue, nil
}

// Body finishes the signature; a message the signer cannot sign is accepted
// unsigned, never held.
func (s *session) Body(m *milter.Modifier) (milter.Response, error) {
	defer s.reset()
	if q := m.Macros["i"]; q != "" {
		s.queueID = q
	}
	log := slog.With("queue_id", s.queueID, "domain", s.key.domain)
	if s.signer == nil {
		return milter.RespAccept, nil
	}
	sg := s.signer
	s.signer = nil
	value, err := finishSignature(sg, s.err)
	if err != nil {
		signResults.WithLabelValues("error").Inc()
		log.Error("dkim: not signed", "err", err)
		return milter.RespAccept, nil
	}
	if err := m.InsertHeader(0, "DKIM-Signature", value); err != nil {
		signResults.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("dkim: insert header: %w", err)
	}
	signResults.WithLabelValues("signed").Inc()
	log.Info("dkim: signed", "selector", s.key.selector)
	return milter.RespAccept, nil
}

func (s *session) Abort(*milter.Modifier) error {
	s.reset()
	return nil
}

// newMessageSigner starts a signature over the given header block.
func newMessageSigner(k key, headers []byte) (*dkim.Signer, error) {
	sg, err := dkim.NewSigner(&dkim.SignOptions{
		Domain:                 k.domain,
		Selector:               k.selector,
		Signer:                 k.signer,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationSimple,
		HeaderKeys:             signedHeaders,
	})
	if err != nil {
		return nil, fmt.Errorf("dkim: signer: %w", err)
	}
	if _, err := sg.Write(headers); err != nil {
		_ = sg.Close()
		return nil, fmt.Errorf("dkim: write headers: %w", err)
	}
	if _, err := sg.Write([]byte("\r\n")); err != nil {
		_ = sg.Close()
		return nil, fmt.Errorf("dkim: write: %w", err)
	}
	return sg, nil
}

// finishSignature closes the signer and returns the DKIM-Signature value.
func finishSignature(sg *dkim.Signer, writeErr error) (string, error) {
	closeErr := sg.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", fmt.Errorf("dkim: sign: %w", closeErr)
	}
	field := strings.TrimSuffix(sg.Signature(), "\r\n")
	name, value, ok := strings.Cut(field, ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), "DKIM-Signature") {
		return "", fmt.Errorf("dkim: unexpected signature field %q", field)
	}
	return strings.TrimLeft(value, " "), nil
}

// sign returns the DKIM-Signature field value for a whole message.
func sign(k key, headers, body []byte) (string, error) {
	sg, err := newMessageSigner(k, headers)
	if err != nil {
		return "", err
	}
	_, werr := sg.Write(body)
	return finishSignature(sg, werr)
}

// fromDomain is the domain of the first address in a From value, lower case.
func fromDomain(from string) string {
	if from == "" {
		return ""
	}
	addrs, err := mail.ParseAddressList(from)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	at := strings.LastIndexByte(addrs[0].Address, '@')
	if at < 0 {
		return ""
	}
	return strings.ToLower(addrs[0].Address[at+1:])
}
