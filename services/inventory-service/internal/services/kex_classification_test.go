package services

// Guards for two defects that made modern and post-quantum deployments look
// worse than legacy ones.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

var (
	tenantZero = uuid.New()
	assetZero  = uuid.New()
)

// keyExchangeFamily decides which bit-length floor applies. It replaced
// `strings.Contains(kex, "EC")`, which matched neither X25519 nor ML-KEM, so
// their legitimate 256-bit keys were measured against the RSA floor and
// reported as CRITICAL.
func TestKeyExchangeFamily_ClassifiesModernAndPQCCorrectly(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, tc := range []struct {
		kex  string
		want kexFamily
	}{
		{"RSA-2048", kexFamilyFiniteField},
		{"STATIC-RSA", kexFamilyFiniteField},
		{"DH-1024", kexFamilyFiniteField},
		{"DHE", kexFamilyFiniteField},
		{"ECDHE", kexFamilyEllipticCurve},
		{"X25519", kexFamilyEllipticCurve}, // has no "EC" substring
		{"X448", kexFamilyEllipticCurve},   // ditto
		{"CURVE25519", kexFamilyEllipticCurve},
		{"ML-KEM-768", kexFamilyPostQuantum},
		{"HQC-128", kexFamilyPostQuantum},
		// Contains "EC" (SECP) *and* MLKEM — post-quantum must win.
		{"SecP256r1MLKEM768", kexFamilyPostQuantum},
		{"X25519MLKEM768", kexFamilyPostQuantum},
	} {
		if got := keyExchangeFamily(str(tc.kex)); got != tc.want {
			t.Errorf("keyExchangeFamily(%q) = %v, want %v", tc.kex, got, tc.want)
		}
	}
	if got := keyExchangeFamily(nil); got != kexFamilyUnknown {
		t.Errorf("keyExchangeFamily(nil) = %v, want unknown", got)
	}
}

// A 256-bit X25519 or ML-KEM key must not be reported as a critically weak RSA
// modulus.
func TestWeakCryptoDetector_ModernKeySizesAreNotCritical(t *testing.T) {
	d := NewWeakCryptoDetector(nil)
	str := func(s string) *string { return &s }
	num := func(n int) *int { return &n }

	for _, kex := range []string{"X25519", "ECDHE", "ML-KEM-768", "X25519MLKEM768", "HQC-128"} {
		impl := &models.CryptoImplementation{
			Protocol:             "TLS",
			ProtocolVersion:      str("TLS1.3"),
			KeyExchangeAlgorithm: str(kex),
			KeySize:              num(256),
		}
		issues := d.AnalyzeCryptoImplementation(tenantZero, assetZero, impl)
		for _, is := range issues {
			if is.Category == CategoryKeySize {
				t.Errorf("%s with a 256-bit key produced a key-size finding (%s, %s)",
					kex, is.Severity, is.IssueType)
			}
		}
	}

	// The floor must still bite where it is meaningful.
	weak := &models.CryptoImplementation{
		Protocol:             "TLS",
		ProtocolVersion:      str("TLS1.2"),
		KeyExchangeAlgorithm: str("RSA-1024"),
		KeySize:              num(512),
	}
	found := false
	for _, is := range d.AnalyzeCryptoImplementation(tenantZero, assetZero, weak) {
		if is.Category == CategoryKeySize && is.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("a 512-bit RSA key must still be reported as critically weak")
	}
}
