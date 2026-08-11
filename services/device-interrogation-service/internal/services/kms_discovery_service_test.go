package services

import (
	"testing"
)

func TestMapKeySpecToAlgorithm(t *testing.T) {
	tests := []struct {
		keySpec  string
		expected string
	}{
		{"SYMMETRIC_DEFAULT", "AES-256"},
		{"RSA_2048", "RSA-2048"},
		{"RSA_3072", "RSA-3072"},
		{"RSA_4096", "RSA-4096"},
		{"ECC_NIST_P256", "ECC-P256"},
		{"ECC_NIST_P384", "ECC-P384"},
		{"ECC_NIST_P521", "ECC-P521"},
		{"ECC_SECG_P256K1", "ECC-SECP256K1"},
		{"HMAC_256", "HMAC-SHA256"},
		{"UNKNOWN_SPEC", "UNKNOWN_SPEC"},
	}

	for _, tt := range tests {
		result := MapKeySpecToAlgorithm(tt.keySpec)
		if result != tt.expected {
			t.Errorf("MapKeySpecToAlgorithm(%q) = %q, want %q", tt.keySpec, result, tt.expected)
		}
	}
}

func TestKeySpecToSize(t *testing.T) {
	tests := []struct {
		spec     string
		expected int
	}{
		{"SYMMETRIC_DEFAULT", 256},
		{"RSA_2048", 2048},
		{"RSA_3072", 3072},
		{"RSA_4096", 4096},
		{"ECC_NIST_P256", 256},
		{"ECC_NIST_P384", 384},
		{"ECC_NIST_P521", 521},
		{"HMAC_256", 256},
		{"HMAC_384", 384},
		{"HMAC_512", 512},
		{"UNKNOWN", 0},
	}

	for _, tt := range tests {
		result := keySpecToSize(tt.spec)
		if result != tt.expected {
			t.Errorf("keySpecToSize(%q) = %d, want %d", tt.spec, result, tt.expected)
		}
	}
}
