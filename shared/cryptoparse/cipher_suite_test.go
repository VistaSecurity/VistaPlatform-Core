package cryptoparse_test

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse/cryptoparsetest"
)

// TestParseCipherSuite_Golden is the definition of the vocabulary contract: the
// shared parser is what the golden table describes. Both consumers then have
// their own test proving their surface agrees with this same table.
func TestParseCipherSuite_Golden(t *testing.T) {
	for _, tc := range cryptoparsetest.GoldenSuites {
		t.Run(tc.Suite, func(t *testing.T) {
			got, err := cryptoparse.ParseCipherSuite(tc.Suite)
			if err != nil || got == nil {
				t.Fatalf("ParseCipherSuite(%q) failed: %v", tc.Suite, err)
			}
			if got.KeyExchange != tc.KeyExchange {
				t.Errorf("key exchange = %q, want %q", got.KeyExchange, tc.KeyExchange)
			}
			if got.Signature != tc.Signature {
				t.Errorf("signature = %q, want %q", got.Signature, tc.Signature)
			}
			if got.Symmetric != tc.Symmetric {
				t.Errorf("symmetric = %q, want %q", got.Symmetric, tc.Symmetric)
			}
			if got.Hash != tc.Hash {
				t.Errorf("hash = %q, want %q", got.Hash, tc.Hash)
			}
			if bits := cryptoparse.SymmetricKeyBits(got.Symmetric); bits != tc.SymmetricKeyBits {
				t.Errorf("symmetric key bits = %d, want %d", bits, tc.SymmetricKeyBits)
			}
		})
	}
}

// TestParseCipherSuite_NeverEmitsModeDecoratedNames is the mutation guard for
// the regression the consolidation closes: a code containing a mode suffix is
// not a catalogue code and will resolve by accident or not at all. This is the
// exact assertion cbom-service's copy would have failed.
func TestParseCipherSuite_NeverEmitsModeDecoratedNames(t *testing.T) {
	suites := []string{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_CHACHA20_POLY1305_SHA256",
		"ECDHE-RSA-CHACHA20-POLY1305",
		"AES256-GCM-SHA384",
	}
	allowed := map[string]bool{
		"AES128": true, "AES256": true, "CHACHA20": true,
		"3DES": true, "DES": true, "RC4": true, "NULL": true, "": true,
	}
	for _, suite := range suites {
		got, err := cryptoparse.ParseCipherSuite(suite)
		if err != nil || got == nil {
			t.Fatalf("ParseCipherSuite(%q) failed: %v", suite, err)
		}
		if !allowed[got.Symmetric] {
			t.Errorf("%s: symmetric %q is outside the agreed vocabulary", suite, got.Symmetric)
		}
	}
}

func TestParseCipherSuite_Empty(t *testing.T) {
	if _, err := cryptoparse.ParseCipherSuite(""); err == nil {
		t.Error(`ParseCipherSuite("") should error`)
	}
	// Whitespace is not an error, but it must not invent components.
	got, err := cryptoparse.ParseCipherSuite("   ")
	if err != nil || got == nil {
		t.Fatalf(`ParseCipherSuite("   ") failed: %v`, err)
	}
	if got.KeyExchange != "" || got.Signature != "" || got.Symmetric != "" || got.Hash != "" {
		t.Errorf("whitespace produced components: %+v", got)
	}
}

func TestSymmetricKeyBits(t *testing.T) {
	cases := map[string]int{
		"AES128": 128, "AES256": 256, "CHACHA20": 256,
		// Deliberately unpinned: the name does not fix the length, and a wrong
		// number in a CBOM is worse than an absent one.
		"RC4": 0, "NULL": 0, "3DES": 0, "DES": 0, "": 0,
	}
	for code, want := range cases {
		if got := cryptoparse.SymmetricKeyBits(code); got != want {
			t.Errorf("SymmetricKeyBits(%q) = %d, want %d", code, got, want)
		}
	}
}
