package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// generateSelfSignedCert creates a self-signed x509 certificate for testing.
func generateSelfSignedCert(t *testing.T, isCA bool, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "test-cert.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test-cert.example.com", "*.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert
}

func generateSelfSignedCertWithRSAKey(t *testing.T, key *rsa.PrivateKey, serial int64, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   "renewed-cert.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"renewed-cert.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert
}

func TestExtractCertificatesFromX509_SelfSigned(t *testing.T) {
	cert := generateSelfSignedCert(t, false,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)

	result := ExtractCertificatesFromX509([]*x509.Certificate{cert})
	if len(result) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(result))
	}

	info := result[0]

	// Serial number
	if info.SerialNumber != cert.SerialNumber.String() {
		t.Errorf("serial number mismatch: got %q, want %q", info.SerialNumber, cert.SerialNumber.String())
	}

	// Subject / Issuer DN
	if info.SubjectDN == "" {
		t.Error("SubjectDN is empty")
	}
	if info.Subject != info.SubjectDN {
		t.Errorf("Subject and SubjectDN should match: %q != %q", info.Subject, info.SubjectDN)
	}
	if info.IssuerDN == "" {
		t.Error("IssuerDN is empty")
	}

	// Timestamps
	if info.NotBefore.IsZero() || info.NotAfter.IsZero() {
		t.Error("NotBefore or NotAfter is zero")
	}

	// Key algorithm
	if info.KeyAlgorithm != "RSA" {
		t.Errorf("expected key algorithm RSA, got %q", info.KeyAlgorithm)
	}

	// Key size
	if info.KeySize != 2048 {
		t.Errorf("expected key size 2048, got %d", info.KeySize)
	}

	// IsCA
	if info.IsCA {
		t.Error("expected IsCA false")
	}

	// PEM
	if info.CertificatePEM == "" {
		t.Error("CertificatePEM is empty")
	}

	// Fingerprints
	if info.FingerprintSHA256 == "" {
		t.Error("FingerprintSHA256 is empty")
	}
	if info.FingerprintSHA1 == "" {
		t.Error("FingerprintSHA1 is empty")
	}
	if len(info.FingerprintSHA256) != 64 {
		t.Errorf("SHA256 fingerprint wrong length: %d", len(info.FingerprintSHA256))
	}
	if len(info.FingerprintSHA1) != 40 {
		t.Errorf("SHA1 fingerprint wrong length: %d", len(info.FingerprintSHA1))
	}

	// SANs
	if len(info.SubjectAlternativeNames) != 2 {
		t.Errorf("expected 2 SANs, got %d: %v", len(info.SubjectAlternativeNames), info.SubjectAlternativeNames)
	}

	// Key usage
	if len(info.KeyUsage) != 2 {
		t.Errorf("expected 2 key usages, got %d: %v", len(info.KeyUsage), info.KeyUsage)
	}

	// Extended key usage
	if len(info.ExtendedKeyUsage) != 1 || info.ExtendedKeyUsage[0] != "ServerAuth" {
		t.Errorf("expected [ServerAuth], got %v", info.ExtendedKeyUsage)
	}

	// Chain order
	if info.ChainOrder != 0 {
		t.Errorf("expected chain order 0, got %d", info.ChainOrder)
	}
}

func TestExtractCertificatesFromX509_EmptySlice(t *testing.T) {
	result := ExtractCertificatesFromX509(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %d", len(result))
	}

	result = ExtractCertificatesFromX509([]*x509.Certificate{})
	if len(result) != 0 {
		t.Errorf("expected empty result for empty input, got %d", len(result))
	}
}

func TestExtractCertificatesFromX509_ChainOrder(t *testing.T) {
	leaf := generateSelfSignedCert(t, false, x509.KeyUsageDigitalSignature, nil)
	intermediate := generateSelfSignedCert(t, true, x509.KeyUsageCertSign, nil)

	result := ExtractCertificatesFromX509([]*x509.Certificate{leaf, intermediate})
	if len(result) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(result))
	}
	if result[0].ChainOrder != 0 {
		t.Errorf("leaf chain order: expected 0, got %d", result[0].ChainOrder)
	}
	if result[1].ChainOrder != 1 {
		t.Errorf("intermediate chain order: expected 1, got %d", result[1].ChainOrder)
	}
}

func TestExtractKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		input    x509.KeyUsage
		expected []string
	}{
		{"none", 0, nil},
		{"digital signature", x509.KeyUsageDigitalSignature, []string{"DigitalSignature"}},
		{"multiple", x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, []string{"KeyEncipherment", "CertSign"}},
		{"all", x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
			x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly |
			x509.KeyUsageDecipherOnly,
			[]string{
				"DigitalSignature", "ContentCommitment", "KeyEncipherment",
				"DataEncipherment", "KeyAgreement", "CertSign",
				"CRLSign", "EncipherOnly", "DecipherOnly",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractKeyUsage(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("length mismatch: got %v, want %v", got, tt.expected)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestPublicKeyFingerprintSHA256_DeduplicatesRenewedCertificates(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	first := generateSelfSignedCertWithRSAKey(t, key, 1, now.Add(-time.Hour), now.Add(24*time.Hour))
	renewed := generateSelfSignedCertWithRSAKey(t, key, 2, now, now.Add(48*time.Hour))

	if string(first.Raw) == string(renewed.Raw) {
		t.Fatal("test setup produced identical certificates; renewal should change certificate bytes")
	}

	firstFP := PublicKeyFingerprintSHA256(first)
	renewedFP := PublicKeyFingerprintSHA256(renewed)
	if firstFP == "" {
		t.Fatal("expected non-empty SPKI fingerprint")
	}
	if firstFP != renewedFP {
		t.Fatalf("same public key produced different SPKI fingerprints: %q != %q", firstFP, renewedFP)
	}
}

func TestPublicKeyFingerprintSHA256_EmptyWhenNoCertificateOrSPKI(t *testing.T) {
	if got := PublicKeyFingerprintSHA256(nil); got != "" {
		t.Errorf("nil certificate fingerprint = %q, want empty", got)
	}
	if got := PublicKeyFingerprintSHA256(&x509.Certificate{}); got != "" {
		t.Errorf("certificate without SPKI fingerprint = %q, want empty", got)
	}
}

func TestPublicKeyCurve(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	tests := []struct {
		name string
		key  interface{}
		want string
	}{
		{"ecdsa P-256", &ecKey.PublicKey, "P-256"},
		{"rsa has no curve", &rsaKey.PublicKey, ""},
		{"nil", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PublicKeyCurve(tt.key); got != tt.want {
				t.Errorf("PublicKeyCurve() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseCertificatePEM(t *testing.T) {
	cert := generateSelfSignedCert(t, false, x509.KeyUsageDigitalSignature, nil)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	got, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM() unexpected error: %v", err)
	}
	if got.SerialNumber.String() != cert.SerialNumber.String() {
		t.Errorf("serial number = %q, want %q", got.SerialNumber.String(), cert.SerialNumber.String())
	}

	if _, err := ParseCertificatePEM("not a certificate"); err == nil {
		t.Fatal("ParseCertificatePEM() with invalid input succeeded, want error")
	}
}

func TestCalculateKeySize_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	size := CalculateKeySize(&key.PublicKey)
	if size != 2048 {
		t.Errorf("expected 2048, got %d", size)
	}
}

func TestCalculateKeySize_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	size := CalculateKeySize(&key.PublicKey)
	if size != 256 {
		t.Errorf("expected 256, got %d", size)
	}
}

func TestCalculateKeySize_Unknown(t *testing.T) {
	size := CalculateKeySize("not a key")
	if size != 0 {
		t.Errorf("expected 0, got %d", size)
	}
}
