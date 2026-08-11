package cryptoparse_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

func TestNormalizeComponentCode(t *testing.T) {
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
		// W2-16: spaced protocol versions. The sensor's TLS enricher and the F5
		// interrogator emit the human-readable spelling; the catalogue codes it
		// without the space.
		{"TLS 1.0", "TLS1.0"},
		{"TLS 1.1", "TLS1.1"},
		{"TLS 1.2", "TLS1.2"},
		{"TLS 1.3", "TLS1.3"},
	}
	for _, tt := range tests {
		if got := cryptoparse.NormalizeComponentCode(tt.in); got != tt.want {
			t.Errorf("NormalizeComponentCode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestNormalizeProtocolVersion covers the protocols where separator removal is
// not enough — pcap-processor renders SSLv3 as "SSL 3.0", which normalizes to
// "SSL3.0" and still does not equal the catalogue's "SSLv3".
func TestNormalizeProtocolVersion(t *testing.T) {
	aliased := map[string]string{
		"SSL 3.0": "SSLv3",
		"SSL3.0":  "SSLv3",
		"ssl 3.0": "SSLv3",
		"SSLv3":   "SSLv3",
		"SSL 2.0": "SSLv2",
		"SSLv2":   "SSLv2",
	}
	for in, want := range aliased {
		if got := cryptoparse.NormalizeProtocolVersion(in); got != want {
			t.Errorf("NormalizeProtocolVersion(%q) = %q, want %q", in, got, want)
		}
	}

	// No alias needed (or none known): the caller falls through to its other
	// resolution steps rather than being handed a guess.
	for _, in := range []string{"TLS 1.2", "TLS1.3", "DTLS 1.2", ""} {
		if got := cryptoparse.NormalizeProtocolVersion(in); got != "" {
			t.Errorf("NormalizeProtocolVersion(%q) = %q, want \"\"", in, got)
		}
	}
}
