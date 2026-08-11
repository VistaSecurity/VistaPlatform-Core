package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// selfSignedCA mints a self-signed CA and a leaf it signs, mirroring the shape
// a privately-signed platform presents.
func selfSignedCA(t *testing.T, cn string) (caCert *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, key
}

func leafSignedBy(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		// httptest serves on 127.0.0.1, and Go verifies an IP literal against
		// IP SANs only — a DNS SAN of "127.0.0.1" does not satisfy it.
		IPAddresses: []net.IP{net.ParseIP(host)},
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

// startTLSServer serves HTTPS with a privately-signed chain — the situation an
// agent meets against a platform whose edge cert this host does not trust.
func startTLSServer(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leafSignedBy(t, ca, caKey, "127.0.0.1")},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchServerTrustAnchor_ReturnsIssuerMostCert pins that the anchor offered
// for pinning is the CA at the top of the presented chain, not the leaf —
// pinning the leaf would break the moment the platform's cert rotates.
func TestFetchServerTrustAnchor_ReturnsIssuerMostCert(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	anchor, err := FetchServerTrustAnchor(srv.URL)
	if err != nil {
		t.Fatalf("FetchServerTrustAnchor: %v", err)
	}
	if anchor.Certificate.Subject.CommonName != "Test Platform Root CA" {
		t.Fatalf("anchor = %q, want the CA, not the leaf", anchor.Certificate.Subject.CommonName)
	}
	if !anchor.SelfSigned {
		t.Error("self-signed root not detected as self-signed")
	}
	if anchor.FingerprintSHA256 != FingerprintSHA256(ca) {
		t.Error("anchor fingerprint does not match the CA it came from")
	}
	if !strings.Contains(anchor.PEM, "BEGIN CERTIFICATE") {
		t.Errorf("anchor PEM not encoded: %q", anchor.PEM)
	}
}

// TestPinnedAnchorActuallyVerifies is the test that matters: the whole feature
// is worthless if the PEM we hand back does not, in fact, let a verifying
// client connect. Proves the round trip end to end — fetch, pin, verify — with
// InsecureSkipVerify FALSE.
func TestPinnedAnchorActuallyVerifies(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	anchor, err := FetchServerTrustAnchor(srv.URL)
	if err != nil {
		t.Fatalf("FetchServerTrustAnchor: %v", err)
	}

	// Sanity: without the pin the connection must FAIL, or this test proves
	// nothing about the pin.
	bare := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12,
	}}}
	if _, err := bare.Get(srv.URL); err == nil {
		t.Fatal("connection succeeded with an empty trust pool; the test server is not actually privately signed")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(anchor.PEM)) {
		t.Fatal("pinned anchor PEM was not accepted into a cert pool")
	}
	pinned := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, MinVersion: tls.VersionTLS12,
	}}}
	resp, err := pinned.Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned CA did not verify the platform: %v", err)
	}
	_ = resp.Body.Close()
}

// TestResolveTrustAnchor_FingerprintMismatchAborts is the guard that keeps the
// unattended path from being trust-on-first-use. A wrong fingerprint must be
// fatal and unpromptable.
func TestResolveTrustAnchor_FingerprintMismatchAborts(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	var out bytes.Buffer
	wrong := strings.Repeat("ab", 32)
	anchor, err := ResolveTrustAnchor(srv.URL, wrong, nil, &out, false)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("err = %v, want ErrFingerprintMismatch", err)
	}
	if anchor != nil {
		t.Fatal("an anchor was returned despite a fingerprint mismatch")
	}
	if !strings.Contains(out.String(), "mismatch") {
		t.Errorf("operator was not told about the mismatch: %q", out.String())
	}
}

// TestResolveTrustAnchor_FingerprintMatchPins covers the unattended happy path,
// including the formatting tolerance an operator needs when pasting.
func TestResolveTrustAnchor_FingerprintMatchPins(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	for _, form := range []string{
		FingerprintSHA256(ca),
		strings.ToUpper(FingerprintSHA256(ca)),
		FormatFingerprint(FingerprintSHA256(ca)),
		"sha256:" + FingerprintSHA256(ca),
	} {
		var out bytes.Buffer
		anchor, err := ResolveTrustAnchor(srv.URL, form, nil, &out, false)
		if err != nil {
			t.Fatalf("fingerprint form %q rejected: %v", form, err)
		}
		if anchor.FingerprintSHA256 != FingerprintSHA256(ca) {
			t.Errorf("form %q pinned the wrong anchor", form)
		}
	}
}

// TestResolveTrustAnchor_NonInteractiveWithoutFingerprintRefuses pins the rule
// that keeps this from degrading into a silent --insecure: with no human to ask
// and no expected fingerprint, nothing gets pinned.
func TestResolveTrustAnchor_NonInteractiveWithoutFingerprintRefuses(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	var out bytes.Buffer
	anchor, err := ResolveTrustAnchor(srv.URL, "", nil, &out, false)
	if err == nil {
		t.Fatal("silently pinned a CA with no operator approval and no expected fingerprint")
	}
	if anchor != nil {
		t.Fatal("returned an anchor nobody approved")
	}
	if !strings.Contains(err.Error(), "--ca-fingerprint") {
		t.Errorf("error does not tell the operator how to proceed: %v", err)
	}
}

// TestResolveTrustAnchor_InteractiveDecline verifies that declining is a clean
// cancellation and pins nothing.
func TestResolveTrustAnchor_InteractiveDecline(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	for _, answer := range []string{"n\n", "\n", "no\n", "junk\n"} {
		var out bytes.Buffer
		anchor, err := ResolveTrustAnchor(srv.URL, "", &stringLineReader{s: answer}, &out, true)
		if !errors.Is(err, ErrTrustDeclined) {
			t.Fatalf("answer %q: err = %v, want ErrTrustDeclined", answer, err)
		}
		if anchor != nil {
			t.Fatalf("answer %q pinned a CA that was declined", answer)
		}
	}
}

// TestResolveTrustAnchor_InteractiveAcceptShowsFingerprint covers the accept
// path and, critically, that the operator was actually shown the fingerprint
// before being asked — a prompt without one is theater.
func TestResolveTrustAnchor_InteractiveAcceptShowsFingerprint(t *testing.T) {
	ca, caKey := selfSignedCA(t, "Test Platform Root CA")
	srv := startTLSServer(t, ca, caKey)

	var out bytes.Buffer
	anchor, err := ResolveTrustAnchor(srv.URL, "", &stringLineReader{s: "y\n"}, &out, true)
	if err != nil {
		t.Fatalf("accept path failed: %v", err)
	}
	if anchor == nil {
		t.Fatal("accepted but no anchor returned")
	}
	shown := out.String()
	if !strings.Contains(shown, "Test Platform Root CA") {
		t.Error("operator was not shown the CA subject")
	}
	// The fingerprint is displayed colon-grouped; compare on a normalized copy.
	if !strings.Contains(normalizeFingerprint(strings.ReplaceAll(shown, " ", "")), anchor.FingerprintSHA256) {
		t.Errorf("operator was not shown the fingerprint they are being asked to verify:\n%s", shown)
	}
}

// TestFetchServerTrustAnchor_RejectsPlainHTTP guards against "succeeding" on a
// URL that has no certificate at all.
func TestFetchServerTrustAnchor_RejectsPlainHTTP(t *testing.T) {
	if _, err := FetchServerTrustAnchor("http://example.test"); err == nil {
		t.Fatal("plain HTTP accepted; there is no certificate to anchor to")
	}
}

func TestFingerprintsEqual(t *testing.T) {
	base := strings.Repeat("a1", 32)
	cases := []struct {
		a, b string
		want bool
	}{
		{base, base, true},
		{base, strings.ToUpper(base), true},
		{base, FormatFingerprint(base), true},
		{base, "sha256:" + base, true},
		{base, strings.Repeat("b2", 32), false},
		{"", "", false}, // empty must never compare equal
		{base, "", false},
	}
	for _, c := range cases {
		if got := FingerprintsEqual(c.a, c.b); got != c.want {
			t.Errorf("FingerprintsEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestDescribeTrustAnchor_FlagsExpiry(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Expired CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	desc := DescribeTrustAnchor(&TrustAnchor{
		Certificate: cert, FingerprintSHA256: FingerprintSHA256(cert), SelfSigned: true,
	})
	if !strings.Contains(desc, "EXPIRED") {
		t.Errorf("expired CA not flagged to the operator:\n%s", desc)
	}
}

// stringLineReader feeds canned answers to the prompt.
type stringLineReader struct {
	s    string
	done bool
}

func (r *stringLineReader) ReadString(byte) (string, error) {
	if r.done {
		return "", fmt.Errorf("no more input")
	}
	r.done = true
	return r.s, nil
}
