package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// B-12: this peer poll used a bare &http.Client{} against a URL that resolves
// to https://resource-tracker-service:8443 under serviceMtls — a listener that
// is RequireAndVerifyClientCert. Every call failed the handshake, and the
// failure was converted into an inventory-size-derived "API call count" that
// was indistinguishable from a measurement downstream.

// writeTestPKI writes a self-signed CA-ish cert + key usable as both the client
// certificate and the trust anchor, and returns their paths.
func writeTestPKI(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "inventory-service-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func clientCertCount(t *testing.T, c *http.Client) int {
	t.Helper()
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		return 0
	}
	return len(tr.TLSClientConfig.Certificates)
}

func TestNewPeerHTTPClient_PresentsAClientCertificateWhenMTLSIsOn(t *testing.T) {
	certPath, keyPath := writeTestPKI(t)

	c := newPeerHTTPClient(true, certPath, keyPath, certPath)
	if n := clientCertCount(t, c); n != 1 {
		t.Fatalf("mTLS client carries %d client certificates, want 1 — without one the "+
			"handshake against the :8443 peer listener fails on every call", n)
	}
	if c.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", c.Timeout)
	}
}

func TestNewPeerHTTPClient_PlainWhenMTLSIsOff(t *testing.T) {
	certPath, keyPath := writeTestPKI(t)

	c := newPeerHTTPClient(false, certPath, keyPath, certPath)
	if n := clientCertCount(t, c); n != 0 {
		t.Fatalf("plaintext deployment built an mTLS client (%d certs)", n)
	}
}
