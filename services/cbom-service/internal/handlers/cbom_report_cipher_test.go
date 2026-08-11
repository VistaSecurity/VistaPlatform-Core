package handlers

// Cipher-suite parsing in the CBOM handler.
//
// This file used to pin the OUTPUT OF A DRIFTED COPY. cbom-service carried a
// hand-transcribed "mirror" of inventory-service's parser, and by the time it
// was found it still emitted the mode-decorated names — "AES-256-GCM",
// "CHACHA20-POLY1305", "AES-128-CBC", bare "SHA" — that inventory's parser had
// been specifically fixed to stop emitting, plus a different key-exchange
// table. Its tests were green the whole time, because they asserted the drift.
//
// A CBOM artifact is audit-grade evidence. Naming a component differently from
// the inventory it was generated from, for the same observed suite, is the
// worst place in the product for a fork. Both consumers now call
// shared/cryptoparse, and the golden table in cryptoparsetest is the single
// fixture both are held to.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse/cryptoparsetest"
)

// findSource returns the first cbomAlgorithmSource with the given role, or nil.
func findSource(sources []cbomAlgorithmSource, role string) *cbomAlgorithmSource {
	for i := range sources {
		if sources[i].Role == role {
			return &sources[i]
		}
	}
	return nil
}

// codeFor returns the code emitted for a role, or "" when the role is absent.
func codeFor(sources []cbomAlgorithmSource, role string) string {
	if s := findSource(sources, role); s != nil {
		return s.Code
	}
	return ""
}

// TestParseCipherSuiteAlgorithms_MatchesSharedGolden is the cross-consumer
// guard. inventory-service has the matching test over the same table; while
// both are green the two services cannot disagree about a suite.
func TestParseCipherSuiteAlgorithms_MatchesSharedGolden(t *testing.T) {
	for _, tc := range cryptoparsetest.GoldenSuites {
		t.Run(tc.Suite, func(t *testing.T) {
			sources := parseCipherSuiteAlgorithms(tc.Suite, 0)

			if got := codeFor(sources, "key_exchange"); got != tc.KeyExchange {
				t.Errorf("key_exchange = %q, want %q", got, tc.KeyExchange)
			}
			if got := codeFor(sources, "signature"); got != tc.Signature {
				t.Errorf("signature = %q, want %q", got, tc.Signature)
			}
			if got := codeFor(sources, "symmetric"); got != tc.Symmetric {
				t.Errorf("symmetric = %q, want %q", got, tc.Symmetric)
			}
			if got := codeFor(sources, "hash"); got != tc.Hash {
				t.Errorf("hash = %q, want %q", got, tc.Hash)
			}

			if sym := findSource(sources, "symmetric"); sym != nil {
				if sym.KeySize != tc.SymmetricKeyBits {
					t.Errorf("symmetric key size = %d, want %d", sym.KeySize, tc.SymmetricKeyBits)
				}
			}
		})
	}
}

// TestParseCipherSuiteAlgorithms_EmitsCatalogueCodes is the mutation guard for
// the specific drift: every code a CBOM component is named after must be a
// catalogue code, never a mode-decorated description. This assertion is what
// the old copy failed.
func TestParseCipherSuiteAlgorithms_EmitsCatalogueCodes(t *testing.T) {
	allowedSymmetric := map[string]bool{
		"AES128": true, "AES256": true, "CHACHA20": true,
		"3DES": true, "DES": true, "RC4": true, "NULL": true,
	}
	allowedHash := map[string]bool{
		"SHA1": true, "SHA224": true, "SHA256": true, "SHA384": true,
		"SHA512": true, "MD5": true, "NULL": true,
	}

	suites := []string{
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_RC4_128_SHA",
		"ECDHE-RSA-AES256-GCM-SHA384",
		"AES128-SHA",
	}
	for _, suite := range suites {
		sources := parseCipherSuiteAlgorithms(suite, 0)
		if sym := codeFor(sources, "symmetric"); sym != "" && !allowedSymmetric[sym] {
			t.Errorf("%s: symmetric %q is not a catalogue code", suite, sym)
		}
		if h := codeFor(sources, "hash"); h != "" && !allowedHash[h] {
			t.Errorf("%s: hash %q is not a catalogue code", suite, h)
		}
	}
}

// TestParseCipherSuiteAlgorithms_StaticKeyExchangeIsNotRSA pins the
// forward-secrecy distinction the old copy erased: its key-exchange table had
// no ECDH/DH entries, so a static-ECDH suite — which offers no forward secrecy,
// exactly what the no-PFS controls hunt for — was labelled plain RSA.
func TestParseCipherSuiteAlgorithms_StaticKeyExchangeIsNotRSA(t *testing.T) {
	cases := map[string]string{
		"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256":  "ECDH",
		"TLS_DH_RSA_WITH_AES_256_CBC_SHA256":    "DH",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE",
	}
	for suite, want := range cases {
		if got := codeFor(parseCipherSuiteAlgorithms(suite, 0), "key_exchange"); got != want {
			t.Errorf("%s: key_exchange = %q, want %q", suite, got, want)
		}
	}
}

func TestParseCipherSuiteAlgorithms_EdgeCases(t *testing.T) {
	if result := parseCipherSuiteAlgorithms("", 0); result != nil {
		t.Errorf("empty string: expected nil, got %+v", result)
	}
	if result := parseCipherSuiteAlgorithms("   ", 0); result != nil {
		t.Errorf("whitespace: expected nil, got %+v", result)
	}
}

// TestParseCipherSuiteAlgorithms_KeySizePassthrough: the asset's key size
// describes the KEY EXCHANGE key and is carried onto that component only. The
// symmetric component takes its length from the suite name instead, so a
// 2048-bit RSA key exchange never mislabels an AES-128 cipher as 2048-bit.
func TestParseCipherSuiteAlgorithms_KeySizePassthrough(t *testing.T) {
	sources := parseCipherSuiteAlgorithms("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 2048)

	kx := findSource(sources, "key_exchange")
	if kx == nil {
		t.Fatal("missing key_exchange")
	}
	if kx.KeySize != 2048 {
		t.Errorf("key_exchange key size: got %d, want 2048", kx.KeySize)
	}

	sym := findSource(sources, "symmetric")
	if sym == nil {
		t.Fatal("missing symmetric")
	}
	if sym.KeySize != 128 {
		t.Errorf("symmetric key size: got %d, want 128 (from the suite name, not the asset key)", sym.KeySize)
	}
}
