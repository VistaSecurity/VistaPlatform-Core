package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
)

func selfSignedCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Platform Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestServerCAAppliesBeforeClientCertExists is the regression guard for the
// trust-bootstrap fix. The client used to gate its whole TLS transport on
// already holding a client certificate, which made a pinned ServerCACert
// unreachable at the one moment it was needed: registration is itself an HTTPS
// call, and it is what ISSUES the client cert. Against a platform whose edge
// cert is signed by a private CA, that circularity meant an operator could
// supply the correct CA and still never get past x509.
//
// Mutation check: restore the `&& cfg.Security.ClientCert != ""` gate around
// the RootCAs block and this fails.
func TestServerCAAppliesBeforeClientCertExists(t *testing.T) {
	cfg := &config.Config{
		PlatformURL: "https://platform.example.test",
		// Pre-registration state: a CA to trust, and no client identity yet.
		Security: config.SecurityConfig{ServerCACert: selfSignedCAPEM(t)},
	}

	c := NewOutboundClient(cfg)
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatalf("no TLS transport built from a server CA alone; got %T", c.httpClient.Transport)
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("pinned server CA was ignored — registration would fail x509")
	}
	if len(tr.TLSClientConfig.Certificates) != 0 {
		t.Error("presented a client certificate before registration issued one")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("verification disabled; the pin exists precisely so it stays on")
	}
}

// TestNoTrustMaterialLeavesDefaultTransport keeps the fix from over-reaching:
// with neither a CA nor a client cert the agent must fall through to the system
// trust store, which is correct for a platform holding a public certificate.
func TestNoTrustMaterialLeavesDefaultTransport(t *testing.T) {
	cfg := &config.Config{PlatformURL: "https://platform.example.test"}
	if tr := NewOutboundClient(cfg).httpClient.Transport; tr != nil {
		t.Fatalf("custom transport installed with no trust material: %T", tr)
	}
}
