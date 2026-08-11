package services

import "testing"

// classifyPQCAlgorithm is the pure classifier behind the cert_pqc_status measurement:
// only the NIST PQC families are quantum_safe; classical algorithms and anything
// unrecognized are quantum_vulnerable (assume-at-risk). No database.
func TestClassifyPQCAlgorithm(t *testing.T) {
	vulnerable := []string{"RSA", "rsa", "ECDSA", "EC", "EdDSA", "Ed25519", "DSA", "DH", "RSASSA-PSS", "", "totally-unknown"}
	safe := []string{"ML-KEM", "ML-KEM-768", "MLKEM768", "Kyber512", "ML-DSA", "Dilithium3", "SLH-DSA", "SPHINCS+", "Falcon-512", "FN-DSA"}

	for _, a := range vulnerable {
		if got := classifyPQCAlgorithm(a); got != "quantum_vulnerable" {
			t.Errorf("classifyPQCAlgorithm(%q) = %q, want quantum_vulnerable", a, got)
		}
	}
	for _, a := range safe {
		if got := classifyPQCAlgorithm(a); got != "quantum_safe" {
			t.Errorf("classifyPQCAlgorithm(%q) = %q, want quantum_safe", a, got)
		}
	}
}

// Hybrid key exchange (classical + PQC) is the NIST/IETF migration path and must count as
// quantum_safe — the substring match makes that work for free, so config_kex_pqc_status
// ( PQC-003) classifies hybrids correctly. Pure classical hybrids stay vulnerable.
func TestClassifyPQCAlgorithm_Hybrid(t *testing.T) {
	safe := []string{"X25519MLKEM768", "x25519mlkem768", "SecP256r1MLKEM768", "X25519Kyber768Draft00"}
	for _, a := range safe {
		if got := classifyPQCAlgorithm(a); got != "quantum_safe" {
			t.Errorf("classifyPQCAlgorithm(%q) = %q, want quantum_safe (hybrid)", a, got)
		}
	}
	if got := classifyPQCAlgorithm("X25519"); got != "quantum_vulnerable" {
		t.Errorf("classifyPQCAlgorithm(%q) = %q, want quantum_vulnerable", "X25519", got)
	}
}

// classifySymmetricQuantumMargin backs config_sym_strength ( PQC-005, advisory):
// AES-192/256 and ChaCha20 keep a >=128-bit margin under Grover (quantum_safe); AES-128
// and weaker are quantum_marginal; unknown/empty is assume-at-risk (marginal).
func TestClassifySymmetricQuantumMargin(t *testing.T) {
	safe := []string{"AES-256-GCM", "aes256", "AES_256", "AES-192-GCM", "ChaCha20-Poly1305", "CHACHA20"}
	marginal := []string{"AES-128-GCM", "AES128", "AES-128-CBC", "3DES", "DES", "RC4", "", "unknown"}

	for _, a := range safe {
		if got := classifySymmetricQuantumMargin(a); got != "quantum_safe" {
			t.Errorf("classifySymmetricQuantumMargin(%q) = %q, want quantum_safe", a, got)
		}
	}
	for _, a := range marginal {
		if got := classifySymmetricQuantumMargin(a); got != "quantum_marginal" {
			t.Errorf("classifySymmetricQuantumMargin(%q) = %q, want quantum_marginal", a, got)
		}
	}
}
