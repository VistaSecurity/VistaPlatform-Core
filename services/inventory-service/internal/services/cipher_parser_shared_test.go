package services

// Cross-consumer conformance and protocol-version resolution.
//
// The cipher-suite parser now lives in shared/cryptoparse and is consumed by
// both this service and cbom-service. cbom-service used to carry a
// hand-transcribed copy that drifted, so a CBOM artifact — audit-grade evidence
// — could name a component differently from the inventory it was generated
// from, for the same observed suite. The golden table in cryptoparsetest is the
// single fixture both consumers are held to; cbom-service has the matching test.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse/cryptoparsetest"
)

// TestParseCipherSuite_MatchesSharedGolden holds inventory-service's parser
// surface to the shared fixture. If this and cbom-service's counterpart are
// both green, the two services cannot disagree about a suite.
func TestParseCipherSuite_MatchesSharedGolden(t *testing.T) {
	s := &AlgorithmService{}
	for _, tc := range cryptoparsetest.GoldenSuites {
		t.Run(tc.Suite, func(t *testing.T) {
			got, err := s.ParseCipherSuite(tc.Suite)
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
		})
	}
}

// protocolCatalogue mirrors the seeded protocol_version rows, risk scores
// included, so the assertions below can be about the RFC 8996 ladder rather
// than merely about string equality.
func protocolCatalogue() []Algorithm {
	mk := func(code string, risk int, strength, deprecation string) Algorithm {
		return Algorithm{
			ID: uuid.New(), Code: code, Category: "protocol_version",
			RiskScore: risk, Strength: strength, DeprecationStatus: deprecation,
		}
	}
	return []Algorithm{
		mk("SSLv2", 95, "weak", "obsolete"),
		mk("SSLv3", 90, "weak", "obsolete"),
		mk("TLS1.0", 75, "weak", "deprecated"),
		mk("TLS1.1", 70, "weak", "deprecated"),
		mk("TLS1.2", 25, "strong", "current"),
		mk("TLS1.3", 10, "recommended", "current"),
	}
}

// TestClassifyAlgorithm_ResolvesSpacedProtocolVersions is W2-16.
//
// The sensor's TLS enricher (getTLSVersionName) and the F5 interrogator emit
// the human-readable spelling "TLS 1.0" / "TLS 1.2"; pcap-processor emits
// "SSL 3.0". The catalogue codes them "TLS1.0" / "TLS1.2" / "SSLv3".
//
// Before the fix none of those resolved: the exact lookup missed, the
// mode-suffix normalizer was a no-op on them (it only removed hyphens), and the
// substring fallback found nothing because no CODE contains "tls 1.2". The
// protocol_version component was therefore left unlinked for every
// sensor-discovered implementation — and since catalogueRiskRoles counts
// protocol_version, the RFC 8996 deprecation ladder (TLS 1.0 = 75, TLS 1.1 =
// 70) never contributed to any risk score in production data.
func TestClassifyAlgorithm_ResolvesSpacedProtocolVersions(t *testing.T) {
	s := &AlgorithmService{}
	s.setCatalogueForTest(protocolCatalogue())

	cases := []struct {
		observed string
		wantCode string
		wantRisk int
	}{
		// Spaced TLS — what the sensor actually emits.
		{"TLS 1.0", "TLS1.0", 75},
		{"TLS 1.1", "TLS1.1", 70},
		{"TLS 1.2", "TLS1.2", 25},
		{"TLS 1.3", "TLS1.3", 10},
		// The unspaced catalogue spelling must keep working.
		{"TLS1.0", "TLS1.0", 75},
		{"TLS1.2", "TLS1.2", 25},
		// SSL needs an alias, not just separator removal: "SSL 3.0" normalizes
		// to "SSL3.0", which is still not "SSLv3".
		{"SSL 3.0", "SSLv3", 90},
		{"SSL 2.0", "SSLv2", 95},
		{"SSLv3", "SSLv3", 90},
	}

	for _, tc := range cases {
		t.Run(tc.observed, func(t *testing.T) {
			alg, err := s.ClassifyAlgorithm(tc.observed, "protocol_version")
			if err != nil {
				t.Fatalf("ClassifyAlgorithm(%q) errored: %v", tc.observed, err)
			}
			if alg == nil {
				t.Fatalf("ClassifyAlgorithm(%q) resolved to nothing — the protocol-version "+
					"risk signal would never fire for this producer", tc.observed)
			}
			if alg.Code != tc.wantCode {
				t.Fatalf("ClassifyAlgorithm(%q) = %q, want %q", tc.observed, alg.Code, tc.wantCode)
			}
			if alg.RiskScore != tc.wantRisk {
				t.Errorf("%q resolved to catalogue risk %d, want %d", tc.observed, alg.RiskScore, tc.wantRisk)
			}
		})
	}
}

// TestClassifyAlgorithm_ProtocolAliasDoesNotFabricate is the other polarity:
// normalization must not turn an unknown protocol string into a confident
// resolution. Unassessed stays unassessed.
func TestClassifyAlgorithm_ProtocolAliasDoesNotFabricate(t *testing.T) {
	s := &AlgorithmService{}
	s.setCatalogueForTest(protocolCatalogue())

	for _, unknown := range []string{"TLS 1.4", "QUIC v1", "Unknown-0x7F1D", "SSL 1.0"} {
		alg, err := s.ClassifyAlgorithm(unknown, "protocol_version")
		if err != nil {
			t.Fatalf("ClassifyAlgorithm(%q) errored: %v", unknown, err)
		}
		if alg != nil {
			t.Errorf("%q resolved to %q (risk %d) — unknown protocols must stay unassessed",
				unknown, alg.Code, alg.RiskScore)
		}
	}
}
