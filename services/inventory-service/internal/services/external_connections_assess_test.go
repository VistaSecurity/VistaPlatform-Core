package services

import "testing"

func TestNormalizeCipherComponent(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		// Mode suffix stripped, then hyphen removed
		{"AES-256-GCM", "AES256"},
		{"AES-128-GCM", "AES128"},
		{"AES-256-CBC", "AES256"},
		{"AES-128-CBC", "AES128"},
		{"CHACHA20-POLY1305", "CHACHA20"},
		{"RC4-128", "RC4"},
		{"3DES-EDE-CBC", "3DES"},
		// Already a clean code — no-op
		{"ECDHE", "ECDHE"},
		{"SHA384", "SHA384"},
		{"SHA256", "SHA256"},
		{"SHA1", "SHA1"},
		{"MD5", "MD5"},
		{"RSA", "RSA"},
		{"ECDSA", "ECDSA"},
		{"DHE", "DHE"},
	}
	for _, tt := range tests {
		got := normalizeCipherComponent(tt.in)
		if got != tt.want {
			t.Errorf("normalizeCipherComponent(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
