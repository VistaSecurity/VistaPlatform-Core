package discovery

// A legacy TLS endpoint must be measured, not failed on our side. crypto/tls's
// client defaults would refuse both servers below — a TLS 1.0-only one (client
// floor TLS 1.2) and one offering only RSA key exchange (dropped from the
// client default suites in Go 1.22; an embedded MQTT broker found this way
// offered only RSA-kex and DHE suites, and crypto/tls has no DHE) — leaving a
// port with a live TLS listener as a bare tls-attempt-failed note and the
// device with no crypto on record.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startLegacyServer is a loopback TLS listener accepting only [minV, maxV]
// with only suites, over an RSA certificate (RSA key exchange needs one).
func startLegacyServer(t *testing.T, minV, maxV uint16, suites ...uint16) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "broker.example.test"},
		DNSNames:     []string{"broker.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   minV,
		MaxVersion:   maxV,
		CipherSuites: suites,
	}
	host, port := speakServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tc.Handshake()
	})
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func TestIdentify_TLS10OnlyListenerIsMeasured(t *testing.T) {
	addr := startLegacyServer(t, tls.VersionTLS10, tls.VersionTLS10, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
	o, _ := identifyVia(t, 8883, addr, false, IdentifyOptions{})

	if !o.Identified || o.Result == nil {
		t.Fatalf("TLS 1.0-only listener not measured: identified=%v notes=%q metadata=%v", o.Identified, o.Notes, o.Metadata)
	}
	// The negotiated version is what the weak-protocol rules score.
	if got := negotiatedVersionLabel(o.Result); got != "TLS 1.0" {
		t.Errorf("negotiated %q, want TLS 1.0", got)
	}
	if !slices.Equal(o.Result.TLSVersions, []string{"TLS 1.0"}) {
		t.Errorf("TLSVersions = %v, want only TLS 1.0 (it refuses the rest)", o.Result.TLSVersions)
	}
}

func TestIdentify_RSAKeyExchangeOnlyListenerIsMeasured(t *testing.T) {
	// TLS 1.0–1.2, RSA key exchange only: the broker's shape.
	addr := startLegacyServer(t, tls.VersionTLS10, tls.VersionTLS12,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	o, _ := identifyVia(t, 8883, addr, false, IdentifyOptions{})

	if !o.Identified || o.Result == nil {
		t.Fatalf("RSA-kex-only listener not measured: identified=%v notes=%q metadata=%v", o.Identified, o.Notes, o.Metadata)
	}
	if !strings.HasPrefix(o.Result.SelectedCipher, "TLS_RSA_WITH_") {
		t.Errorf("selected cipher %q, want one of the server's RSA key-exchange suites", o.Result.SelectedCipher)
	}
	if len(o.Result.Certificates) != 1 {
		t.Errorf("%d certificates, want the server's one", len(o.Result.Certificates))
	}
	// Enumeration offers the same suites, so the older versions it accepts
	// with RSA key exchange are found too.
	want := []string{"TLS 1.2", "TLS 1.1", "TLS 1.0"}
	if !slices.Equal(o.Result.TLSVersions, want) {
		t.Errorf("TLSVersions = %v, want %v", o.Result.TLSVersions, want)
	}
}

func TestProbeTLSEndpoint_MeasuresALegacyEndpoint(t *testing.T) {
	// The sensor's TLS enricher and device interrogation take this entry; it
	// shares the identifying handshake.
	addr := startLegacyServer(t, tls.VersionTLS10, tls.VersionTLS11, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	res, err := NewProber(2*time.Second).ProbeTLSEndpoint(context.Background(), host, port, TLSEndpointOptions{EnumerateVersions: true})
	if err != nil {
		t.Fatalf("legacy endpoint not measured: %v", err)
	}
	want := []string{"TLS 1.1", "TLS 1.0"}
	if !slices.Equal(res.TLSVersions, want) {
		t.Errorf("TLSVersions = %v, want %v", res.TLSVersions, want)
	}
}

func TestIdentify_FailedTLSAttemptRecordsTheErrorClass(t *testing.T) {
	// A server that reads the whole ClientHello record and hangs up — what
	// the broker did when it shared no suite with us. (Closing with the hello
	// unread would be a reset instead.)
	host, port := speakServer(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		_, _ = io.ReadFull(c, make([]byte, int(hdr[3])<<8|int(hdr[4])))
	})
	o, _ := identifyVia(t, 8883, net.JoinHostPort(host, strconv.Itoa(port)), false, IdentifyOptions{})

	if o.Notes != "tls-attempt-failed" {
		t.Fatalf("notes=%q, want tls-attempt-failed", o.Notes)
	}
	if got := o.Metadata["tls_handshake_error"]; got != "eof" {
		t.Errorf("tls_handshake_error=%v, want eof", got)
	}
}

func TestTLSHandshakeErrorClass(t *testing.T) {
	remote := func(alert string) error {
		return &net.OpError{Op: "remote error", Err: errors.New("tls: " + alert)}
	}
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{remote("protocol version"), "protocol_version"},
		{remote("handshake failure"), "cipher_suite"},
		{remote("insufficient security"), "cipher_suite"},
		{remote("bad certificate"), "alert"},
		{errors.New("tls: server selected unsupported protocol version 300"), "protocol_version"},
		{errors.New("tls: server chose an unconfigured cipher suite"), "cipher_suite"},
		{errors.New("tls: first record does not look like a TLS handshake"), "not_tls"},
		{&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, "timeout"},
		{context.DeadlineExceeded, "timeout"},
		{&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, "reset"},
		{io.EOF, "eof"},
		{fmt.Errorf("wrapped: %w", io.ErrUnexpectedEOF), "eof"},
		{errors.New("something else"), "other"},
	}
	for _, c := range cases {
		if got := TLSHandshakeErrorClass(c.err); got != c.want {
			t.Errorf("TLSHandshakeErrorClass(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// negotiatedVersionLabel is the negotiated version label, as the finding's
// "version" reads it.
func negotiatedVersionLabel(res *ProbeResult) string {
	if len(res.TLSVersions) == 0 {
		return ""
	}
	return res.TLSVersions[0]
}
