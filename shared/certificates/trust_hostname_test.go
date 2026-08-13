package certificates

// The trust prompt offered the operator a certificate that could never work.
//
// Observed live: the platform's TLS Secret was missing, so its ingress
// controller served its own placeholder (CN=<hash>.traefik.default). The prompt
// dutifully showed that certificate's fingerprint, the operator accepted it, and
// the sensor could not connect — because Go's x509 Verify runs VerifyHostname
// BEFORE it builds a chain, so no pinned anchor can rescue a name mismatch.
//
// An operator has no way to tell a real CA from a placeholder by looking at a
// fingerprint. Refusing before the prompt is the only place that distinction can
// be drawn, so it is pinned here — in both directions, because a check that
// wrongly refuses a correct setup is the same bug pointed the other way.

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// leafForWrongHost mints a leaf valid for someone else entirely — the shape of
// an ingress controller's placeholder certificate.
func leafForWrongHost(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, wrongName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: wrongName},
		DNSNames:     []string{wrongName},
		// Deliberately NO IP SAN: the server is reached at 127.0.0.1, which this
		// certificate says nothing about.
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
}

// startTLSServerWithWrongName serves a chain whose leaf is for another host.
func startTLSServerWithWrongName(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, wrongName string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leafForWrongHost(t, ca, caKey, wrongName)},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchServerTrustAnchor_FlagsCertificateNotValidForHost is the underlying
// observation: the fetch must notice the leaf does not match the host, so
// callers can decide honestly instead of showing a fingerprint.
func TestFetchServerTrustAnchor_FlagsCertificateNotValidForHost(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Placeholder CA")
	srv := startTLSServerWithWrongName(t, ca, caKey, "abc123.traefik.default")

	anchor, err := FetchServerTrustAnchor(srv.URL)
	if err != nil {
		t.Fatalf("FetchServerTrustAnchor: %v", err)
	}
	if anchor.UsableForHost() {
		t.Fatal("anchor reports usable, but its leaf is for abc123.traefik.default")
	}
	if anchor.HostnameErr == nil {
		t.Error("HostnameErr is nil for a certificate issued to another host")
	}
	if anchor.Leaf == nil {
		t.Error("Leaf is nil — the caller cannot explain what the server presented")
	}
}

// TestFetchServerTrustAnchor_ValidHostIsUsable is the opposite polarity: a
// correctly-named (merely untrusted) certificate must NOT be flagged. Getting
// this wrong would block every legitimate private-CA install.
func TestFetchServerTrustAnchor_ValidHostIsUsable(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	anchor, err := FetchServerTrustAnchor(srv.URL)
	if err != nil {
		t.Fatalf("FetchServerTrustAnchor: %v", err)
	}
	if !anchor.UsableForHost() {
		t.Fatalf("a correctly-named private cert was flagged: %v", anchor.HostnameErr)
	}
}

// TestResolveTrustAnchor_RefusesToPromptForWrongHostCert is the defect itself:
// the operator must never be offered a pin that cannot work. The reader is
// deliberately loaded with "y" — if the prompt is reached, the accept path runs
// and the test fails, which is what happened live.
func TestResolveTrustAnchor_RefusesToPromptForWrongHostCert(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Placeholder CA")
	srv := startTLSServerWithWrongName(t, ca, caKey, "abc123.traefik.default")

	var out bytes.Buffer
	in := bufio.NewReader(strings.NewReader("y\n"))

	anchor, err := ResolveTrustAnchor(srv.URL, "", in, &out, true)
	if !errors.Is(err, ErrCertificateNotForHost) {
		t.Fatalf("ResolveTrustAnchor = (%v, %v), want ErrCertificateNotForHost", anchor, err)
	}
	if anchor != nil {
		t.Error("an anchor was returned for a certificate that can never verify")
	}

	msg := out.String()
	if strings.Contains(msg, "Trust this CA for this agent?") {
		t.Error("the operator was still asked to trust a certificate that cannot work")
	}
	// The message has to name what the server is actually serving — a
	// fingerprint alone is what left the operator unable to tell.
	if !strings.Contains(msg, "abc123.traefik.default") {
		t.Errorf("message does not name the certificate's actual identity:\n%s", msg)
	}
	if !strings.Contains(msg, "misconfigured") {
		t.Errorf("message does not say the platform is misconfigured:\n%s", msg)
	}
}

// TestResolveTrustAnchor_RefusesWrongHostCertEvenWithMatchingFingerprint pins
// the unattended path too. A correct --ca-fingerprint proves the operator has
// the right CA; it says nothing about whether the server is serving the right
// certificate. Succeeding here would report a completed security step and then
// fail every connection.
func TestResolveTrustAnchor_RefusesWrongHostCertEvenWithMatchingFingerprint(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Placeholder CA")
	srv := startTLSServerWithWrongName(t, ca, caKey, "abc123.traefik.default")

	fetched, err := FetchServerTrustAnchor(srv.URL)
	if err != nil {
		t.Fatalf("FetchServerTrustAnchor: %v", err)
	}

	var out bytes.Buffer
	anchor, err := ResolveTrustAnchor(srv.URL, fetched.FingerprintSHA256, nil, &out, false)
	if !errors.Is(err, ErrCertificateNotForHost) {
		t.Fatalf("ResolveTrustAnchor = (%v, %v), want ErrCertificateNotForHost", anchor, err)
	}
	if anchor != nil {
		t.Error("an anchor was pinned despite the server's certificate being for another host")
	}
}

// TestResolveTrustAnchor_StillPinsCorrectlyNamedCert is the guard against
// over-refusal: the normal private-CA install must still complete.
func TestResolveTrustAnchor_StillPinsCorrectlyNamedCert(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	var out bytes.Buffer
	in := bufio.NewReader(strings.NewReader("y\n"))

	anchor, err := ResolveTrustAnchor(srv.URL, "", in, &out, true)
	if err != nil {
		t.Fatalf("ResolveTrustAnchor = %v, want nil for a correctly-named private cert", err)
	}
	if anchor == nil || anchor.PEM == "" {
		t.Fatal("no anchor returned for a valid private-CA platform")
	}
	if !strings.Contains(out.String(), "Trust this CA for this agent?") {
		t.Error("the operator was not asked — the prompt is the whole point of this path")
	}
}

// TestDescribeHostnameMismatch_NamesNothingWhenThereIsNothingToSay keeps the
// helper from emitting a scary paragraph for a healthy anchor.
func TestDescribeHostnameMismatch_NamesNothingWhenThereIsNothingToSay(t *testing.T) {
	if got := DescribeHostnameMismatch(nil); got != "" {
		t.Errorf("DescribeHostnameMismatch(nil) = %q, want empty", got)
	}
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)
	anchor, err := FetchServerTrustAnchor(srv.URL)
	if err != nil {
		t.Fatalf("FetchServerTrustAnchor: %v", err)
	}
	if got := DescribeHostnameMismatch(anchor); got != "" {
		t.Errorf("DescribeHostnameMismatch(valid anchor) = %q, want empty", got)
	}
}
