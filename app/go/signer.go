package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/textproto"
	"strings"

	"github.com/0kaba0hub/go-milter"
	"github.com/emersion/go-msgauth/dkim"
)

// signedHeaders are the fields signed; From is listed twice so that a From
// added after signing breaks the signature (oversigning).
var signedHeaders = []string{
	"From", "From", "Reply-To", "Subject", "Date", "To", "Cc",
	"Message-ID", "In-Reply-To", "References", "MIME-Version",
	"Content-Type", "Content-Transfer-Encoding",
	"List-Id", "List-Unsubscribe", "List-Unsubscribe-Post",
}

// session collects one message and signs it at the end of the body.
type session struct {
	keys    *keyStore
	headers bytes.Buffer
	body    bytes.Buffer
	from    string
	queueID string
}

func (s *session) reset() {
	s.headers.Reset()
	s.body.Reset()
	s.from = ""
	s.queueID = ""
}

func (s *session) Connect(string, string, uint16, net.IP, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *session) Helo(string, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *session) MailFrom(_ string, m *milter.Modifier) (milter.Response, error) {
	s.reset()
	s.queueID = m.Macros["i"]
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

func (s *session) Headers(textproto.MIMEHeader, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *session) BodyChunk(chunk []byte, _ *milter.Modifier) (milter.Response, error) {
	s.body.Write(chunk)
	return milter.RespContinue, nil
}

// Body signs with the key of the From domain; a message the signer cannot
// sign is accepted unsigned, never held.
func (s *session) Body(m *milter.Modifier) (milter.Response, error) {
	defer s.reset()
	domain := fromDomain(s.from)
	log := slog.With("queue_id", s.queueID, "domain", domain)
	if domain == "" {
		signResults.WithLabelValues("no_from").Inc()
		log.Info("dkim: not signed, no From domain")
		return milter.RespAccept, nil
	}
	k, ok := s.keys.lookup(domain)
	if !ok {
		signResults.WithLabelValues("no_key").Inc()
		log.Info("dkim: not signed, no key for the domain")
		return milter.RespAccept, nil
	}
	value, err := sign(k, s.headers.Bytes(), s.body.Bytes())
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
	log.Info("dkim: signed", "selector", k.selector)
	return milter.RespAccept, nil
}

func (s *session) Abort(*milter.Modifier) error {
	s.reset()
	return nil
}

// sign returns the DKIM-Signature field value for the message.
func sign(k key, headers, body []byte) (string, error) {
	signer, err := dkim.NewSigner(&dkim.SignOptions{
		Domain:                 k.domain,
		Selector:               k.selector,
		Signer:                 k.signer,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationSimple,
		HeaderKeys:             signedHeaders,
	})
	if err != nil {
		return "", fmt.Errorf("dkim: signer: %w", err)
	}
	if _, err := signer.Write(headers); err != nil {
		return "", fmt.Errorf("dkim: write headers: %w", err)
	}
	if _, err := signer.Write([]byte("\r\n")); err != nil {
		return "", fmt.Errorf("dkim: write: %w", err)
	}
	if _, err := signer.Write(body); err != nil {
		return "", fmt.Errorf("dkim: write body: %w", err)
	}
	if err := signer.Close(); err != nil {
		return "", fmt.Errorf("dkim: sign: %w", err)
	}
	field := strings.TrimSuffix(signer.Signature(), "\r\n")
	name, value, ok := strings.Cut(field, ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), "DKIM-Signature") {
		return "", fmt.Errorf("dkim: unexpected signature field %q", field)
	}
	return strings.TrimLeft(value, " "), nil
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
