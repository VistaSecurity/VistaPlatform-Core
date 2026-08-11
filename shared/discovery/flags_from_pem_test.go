package discovery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeTestCertPEM builds a minimal self-signed RSA cert of the given key size
// and returns its PEM. A small key size (e.g. 1024) drives weak-key detection.
func makeTestCertPEM(t *testing.T, commonName string, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestClassifyCertChainFromPEMs_EmptyAndGarbage(t *testing.T) {
	if v := ClassifyCertChainFromPEMs(nil, false); v != nil {
		t.Errorf("nil input: want nil, got %+v", v)
	}
	if v := ClassifyCertChainFromPEMs([]string{"", "not a pem"}, false); v != nil {
		t.Errorf("garbage input: want nil, got %+v", v)
	}
}

func TestClassifyCertChainFromPEMs_ForwardsQualityFlags(t *testing.T) {
	// Strong key: parses, quality flags present, no weak-key flag.
	strong := makeTestCertPEM(t, "strong.example.com", 2048)
	v := ClassifyCertChainFromPEMs([]string{strong}, false)
	if v == nil {
		t.Fatal("want non-nil validation for a parseable cert")
	}
	// cert_has_sct is always emitted by ClassifyCertificateFlags — its presence
	// proves the adapter parsed the PEM and ran the shared classifier.
	if _, ok := v.QualityFlags["cert_has_sct"].(bool); !ok {
		t.Fatalf("cert_has_sct missing or wrong type: %#v", v.QualityFlags["cert_has_sct"])
	}
	if _, weak := v.QualityFlags["cert_weak_public_key"]; weak {
		t.Errorf("cert_weak_public_key should be absent for RSA-2048, got %v", v.QualityFlags["cert_weak_public_key"])
	}

	// Weak key: the adapter must surface the weak-key flag from the classifier.
	weak := makeTestCertPEM(t, "weak.example.com", 1024)
	vw := ClassifyCertChainFromPEMs([]string{weak}, false)
	if vw == nil {
		t.Fatal("want non-nil validation for weak cert")
	}
	if got, _ := vw.QualityFlags["cert_weak_public_key"].(string); got != "RSA-1024" {
		t.Errorf("cert_weak_public_key: want %q, flags=%#v", "RSA-1024", vw.QualityFlags)
	}
}
