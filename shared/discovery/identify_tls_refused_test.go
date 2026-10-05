package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// A handshake the server ends with a TLS alert is still evidence about a TLS
// endpoint. These pin the three outcomes: refused before anything was sent
// (named TLS, nothing measured), refused after the certificate (measured,
// marked incomplete), and not TLS at all (left unidentified).

// startSNIRequiredServer is a loopback TLS listener that refuses a ClientHello
// without a server name — the alert crypto/tls sends for it (internal_error)
// is the one a name-routing reverse proxy answers an address scan with.
func startSNIRequiredServer(t *testing.T) (string, int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	named := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName == "" {
				return nil, errors.New("server name required")
			}
			return named, nil
		},
	}
	return speakServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tc.Handshake()
	})
}

func TestIdentify_TLSAlertWithoutServerNameIsRecordedAsTLS(t *testing.T) {
	host, port := startSNIRequiredServer(t)
	rec := &recordingDialer{}
	s := newIdentifyScanner(t, rec)

	obs, err := s.Identify(t.Context(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, port)
	if !o.Identified || o.Protocol != "TLS" {
		t.Fatalf("refused TLS port: identified=%v protocol=%q, want an identified TLS port", o.Identified, o.Protocol)
	}
	if o.Result != nil {
		t.Errorf("refused TLS port carries a prober result %+v; nothing was negotiated", o.Result)
	}
	if o.Notes != "tls-handshake-refused" {
		t.Errorf("notes=%q, want tls-handshake-refused", o.Notes)
	}
	if got := o.Metadata["tls_handshake_alert"]; got != "internal error" {
		t.Errorf("tls_handshake_alert=%v, want the alert the server sent (internal error)", got)
	}
	// The one speculative ClientHello and nothing after it: a refusal earns no
	// support or version-enumeration handshakes.
	if n, allTLS := rec.connsWithWrites(port); n != 1 || !allTLS {
		t.Errorf("%d connections with writes (TLS-framed=%v), want exactly 1 ClientHello", n, allTLS)
	}
}

func TestIdentify_SameServerNegotiatesWhenGivenAName(t *testing.T) {
	host, port := startSNIRequiredServer(t)
	s := newIdentifyScanner(t, &recordingDialer{})

	obs, err := s.Identify(t.Context(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{Hostname: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, port)
	if o.Result == nil || len(o.Result.Certificates) == 0 || o.Notes != "" {
		t.Fatalf("named TLS port: result=%v notes=%q, want a full TLS result", o.Result, o.Notes)
	}
}

func TestIdentify_NonTLSReplyToClientHelloStaysUnidentified(t *testing.T) {
	host, port := speakServer(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(buf); err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	s := newIdentifyScanner(t, &recordingDialer{})

	obs, err := s.Identify(t.Context(), hostScan(mustAddr(t, host), false, port), IdentifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	o := findObs(t, obs, port)
	if o.Identified || o.Protocol != "" {
		t.Fatalf("plaintext reply: identified=%v protocol=%q, want unidentified", o.Identified, o.Protocol)
	}
	if o.Notes != "tls-attempt-failed" {
		t.Errorf("notes=%q, want tls-attempt-failed", o.Notes)
	}
	if _, ok := o.Metadata["tls_handshake_alert"]; ok {
		t.Error("a non-TLS reply was recorded as a TLS alert")
	}
}

func TestIdentify_RequiredClientCertificateKeepsWhatTheServerSent(t *testing.T) {
	// TLS 1.2 only: the server rejects our empty certificate INSIDE the
	// handshake, after its hello and chain (under 1.3 our side completes).
	srv := startVersionServer(t, tls.VersionTLS12, tls.VersionTLS12, tls.RequireAnyClientCert)
	const port = 8443
	o, rec := identifyVia(t, port, srv.addr, false, IdentifyOptions{})

	if !o.Identified || o.Protocol != "TLS" || o.Result == nil {
		t.Fatalf("client-cert-required port: identified=%v protocol=%q result=%v", o.Identified, o.Protocol, o.Result)
	}
	res := o.Result
	if len(res.Certificates) != 1 || res.SelectedCipher == "" || len(res.TLSVersions) != 1 || res.TLSVersions[0] != "TLS 1.2" {
		t.Errorf("certificates=%d cipher=%q versions=%v, want the chain, suite and version the server sent",
			len(res.Certificates), res.SelectedCipher, res.TLSVersions)
	}
	if got := res.Metadata["tls_handshake_completed"]; got != false {
		t.Errorf("tls_handshake_completed=%v, want an explicit false", got)
	}
	if got := res.Metadata["server_requests_client_cert"]; got != true {
		t.Errorf("server_requests_client_cert=%v, want true", got)
	}
	if got, _ := res.Metadata["tls_handshake_alert"].(string); got == "" {
		t.Error("the alert that ended the handshake was not recorded")
	}
	// No follow-up handshakes: each would be refused the same way.
	if n, _ := rec.connsWithWrites(port); n != 1 {
		t.Errorf("%d connections with writes, want exactly 1", n)
	}
	if got := srv.handshakes(); len(got) != 0 {
		t.Errorf("server completed handshakes %v; the fixture is not refusing", got)
	}
}
