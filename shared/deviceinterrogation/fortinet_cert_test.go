package deviceinterrogation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Pins the map shape processFortinetCertificate produces now that the X.509
// walk goes through shared/certificates: consumers of FortiOS cert
// metadata read these exact keys, so the consolidation must not change them.
func TestProcessFortinetCertificate_MapShape(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "vpn.example.com", Organization: []string{"Example"}},
		DNSNames:     []string{"vpn.example.com", "vpn2.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	got := processFortinetCertificate(map[string]interface{}{"name": "vpn-cert", "cert": pemStr})

	for _, k := range []string{
		"certificate_pem", "fingerprint_sha256", "fingerprint_sha1", "subject_dn",
		"issuer_dn", "subject_alternative_names", "key_usage", "extended_key_usage",
		"public_key_algorithm", "public_key_size", "signature_algorithm",
		"is_ca", "is_self_signed", "serial_number", "not_before", "not_after",
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in processed cert map", k)
		}
	}
	if got["is_self_signed"] != true {
		t.Errorf("is_self_signed = %v, want true", got["is_self_signed"])
	}
	if got["public_key_size"] != 256 {
		t.Errorf("public_key_size = %v, want 256 (P-256)", got["public_key_size"])
	}
	if got["public_key_algorithm"] != "ECDSA" {
		t.Errorf("public_key_algorithm = %v, want ECDSA", got["public_key_algorithm"])
	}
	if got["serial_number"] != "42" {
		t.Errorf("serial_number = %v, want 42", got["serial_number"])
	}
	sans, _ := got["subject_alternative_names"].([]string)
	if len(sans) != 2 {
		t.Errorf("SANs = %v, want both DNS names", sans)
	}
	if got["name"] != "vpn-cert" {
		t.Errorf("original map fields must be preserved, name = %v", got["name"])
	}
}

// Unparseable input must degrade gracefully: the PEM is carried, nothing else
// is fabricated.
func TestProcessFortinetCertificate_UnparseableCarriesPEM(t *testing.T) {
	got := processFortinetCertificate(map[string]interface{}{
		"cert": "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----",
	})
	if _, ok := got["certificate_pem"]; !ok {
		t.Error("PEM body should be preserved on parse failure")
	}
	if _, ok := got["fingerprint_sha256"]; ok {
		t.Error("no fields should be derived from an unparseable certificate")
	}
}
