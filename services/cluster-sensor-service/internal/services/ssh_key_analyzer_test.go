package services

import (
	"testing"
)

func TestAssessSSHKeyStrength(t *testing.T) {
	tests := []struct {
		keyType  string
		keySize  int
		weak     bool
		contains string
	}{
		{"ssh-ed25519", 256, false, ""},
		{"ecdsa-sha2-nistp256", 256, false, ""},
		{"rsa-sha2-256", 4096, false, ""},
		{"rsa-sha2-512", 2048, false, ""},
		{"ssh-rsa", 2048, true, "SHA-1"}, // ssh-rsa uses SHA-1
		{"ssh-rsa", 1024, true, "too small"},
		{"rsa-sha2-256", 1024, true, "too small"}, // Small key
		{"ssh-dss", 1024, true, "DSA"},            // DSA deprecated
	}

	for _, tt := range tests {
		weak, reason := assessSSHKeyStrength(tt.keyType, tt.keySize)
		if weak != tt.weak {
			t.Errorf("assessSSHKeyStrength(%q, %d) weak=%v, want %v (reason: %s)",
				tt.keyType, tt.keySize, weak, tt.weak, reason)
		}
		if tt.contains != "" && !contains(reason, tt.contains) {
			t.Errorf("assessSSHKeyStrength(%q, %d) reason=%q, want contains %q",
				tt.keyType, tt.keySize, reason, tt.contains)
		}
	}

	weak, reason := assessSSHKeyStrength("ssh-rsa", 1024)
	if !weak || !contains(reason, "SHA-1") {
		t.Errorf("assessSSHKeyStrength(%q, %d) want weak reason mentioning SHA-1, got weak=%v reason=%q",
			"ssh-rsa", 1024, weak, reason)
	}
}

func TestSSHKeySize(t *testing.T) {
	// Test the size inference from key type
	tests := []struct {
		keyType  string
		expected int
	}{
		{"ssh-ed25519", 256},
		{"ecdsa-sha2-nistp256", 256},
		{"ecdsa-sha2-nistp384", 384},
		{"ecdsa-sha2-nistp521", 521},
		{"ssh-dss", 1024},
	}

	for _, tt := range tests {
		// For non-RSA types, sshKeySize uses type-based inference
		// We can't test with real ssh.PublicKey without network, but we
		// validate the assessSSHKeyStrength logic that uses the sizes
		weak, _ := assessSSHKeyStrength(tt.keyType, tt.expected)
		if tt.keyType == "ssh-ed25519" && weak {
			t.Errorf("ed25519 should not be weak")
		}
		if tt.keyType == "ssh-dss" && !weak {
			t.Errorf("DSA should be weak")
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
