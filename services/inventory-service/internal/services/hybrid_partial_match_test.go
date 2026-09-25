package services

import (
	"testing"

	"github.com/google/uuid"
)

// A partial name that states only one half of a hybrid key exchange must never
// resolve to the hybrid row. The substring fallback accepts a single match, so
// once SecP384r1MLKEM1024 was the only key-exchange code containing
// "secp384r1", a purely classical P-384 exchange resolved to a post-quantum
// row and read as quantum-ready.
func TestClassifyAlgorithm_PartialNameNeverLandsOnAHybrid(t *testing.T) {
	kex := func(code string, pqc bool, meta map[string]interface{}) Algorithm {
		return Algorithm{ID: uuid.New(), Code: code, Category: "key_exchange", RiskScore: scorePtr(15), IsPQC: pqc, Metadata: meta}
	}
	hybrid := map[string]interface{}{"hybrid": true}
	s := &AlgorithmService{}
	s.setCatalogueForTest([]Algorithm{
		kex("DH-ECP-384", false, nil),
		kex("ML-KEM-1024", true, nil),
		kex("SecP384r1MLKEM1024", true, hybrid),
		// No metadata marker: recognised by its code naming both halves.
		kex("SecP256r1MLKEM768", true, nil),
		kex("mlkem768x25519-sha256", true, hybrid),
	})

	for _, in := range []string{"secp384r1", "SECP384R1", "MLKEM1024", "mlkem1024", "secp256r1", "P256", "x25519-sha256"} {
		alg, err := s.ClassifyAlgorithm(in, "key_exchange")
		if err != nil {
			t.Fatalf("ClassifyAlgorithm(%q): %v", in, err)
		}
		if alg != nil && isHybridKeyExchangeRow(alg) {
			t.Errorf("ClassifyAlgorithm(%q) = %s — a one-half name resolved to a HYBRID row (false PQC-ready)", in, alg.Code)
		}
	}

	// Naming both halves still resolves, exactly or partially.
	for in, want := range map[string]string{
		"SecP384r1MLKEM1024": "SecP384r1MLKEM1024",
		"secp256r1mlkem768":  "SecP256r1MLKEM768",
		"mlkem768x25519":     "mlkem768x25519-sha256",
	} {
		alg, err := s.ClassifyAlgorithm(in, "key_exchange")
		if err != nil || alg == nil || alg.Code != want {
			t.Errorf("ClassifyAlgorithm(%q) = %v (err %v), want %s", in, alg, err, want)
		}
	}
}
