package services

// Unit guards for B-17(a) and B-17(c): the Go half of the legacy-protocol
// predicate, and the managed-asset path's consumption of the enumerated
// accepted-version list.
//
// These run without a database. The SQL twin is pinned against
// isLegacyProtocolVersion by TestIntegration_LegacyProtocolVersionSQL_MatchesGo.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func TestIsLegacyProtocolVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		want    bool
	}{
		// The spelling every producer in this tree actually writes. The old
		// comparisons looked for a bare "1.0", so these all read as clean.
		{"TLS 1.0", true},
		{"TLS 1.1", true},
		{"TLS 1.2", false},
		{"TLS 1.3", false},
		// Cloud SSL-policy and interrogator spellings.
		{"TLSv1.0", true},
		{"TLSv1.1", true},
		{"TLSv1", true}, // AWS renders TLS 1.0 this way
		{"TLSv1.2", false},
		{"TLS1.0", true},
		{"TLS1.2", false},
		// Version-only forms from the passive path.
		{"1.0", true},
		{"1.1", true},
		{"1", true},
		{"1.2", false},
		{"1.3", false},
		// SSL is weak at every version and in every spelling.
		{"SSLv2", true},
		{"SSLv3", true},
		{"SSL 3.0", true},
		{"ssl3", true},
		// Case and separator folding.
		{"tls 1.0", true},
		{"tls-1.1", true},
		{" TLS 1.0 ", true},
		// Not a protocol version we judge.
		{"", false},
		{"unknown", false},
		{"SSH-2.0", false},
		{"DTLS 1.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			t.Parallel()
			if got := isLegacyProtocolVersion(tt.version); got != tt.want {
				t.Fatalf("isLegacyProtocolVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// TestIsWeakProtocol_SpacedVersion is the specific regression: a TLS connection
// whose stored protocol_version is the spaced "TLS 1.0" must produce the weak
// reason. It never did.
func TestIsWeakProtocol_SpacedVersion(t *testing.T) {
	t.Parallel()

	spaced := "TLS 1.0"
	if !isWeakProtocol("TLS", &spaced) {
		t.Error(`isWeakProtocol("TLS", "TLS 1.0") = false — the spelling every producer writes must be recognised`)
	}
	modern := "TLS 1.3"
	if isWeakProtocol("TLS", &modern) {
		t.Error(`isWeakProtocol("TLS", "TLS 1.3") = true`)
	}
}

func TestHasWeakTLSVersion_NonSpacedSpellings(t *testing.T) {
	t.Parallel()

	if !hasWeakTLSVersion([]string{"TLSv1.1", "TLS 1.2"}) {
		t.Error("enumerated TLSv1.1 must count as legacy")
	}
	if !hasWeakTLSVersion([]string{"SSLv3", "TLS 1.2"}) {
		t.Error("enumerated SSLv3 must count as legacy")
	}
	if hasWeakTLSVersion([]string{"TLS 1.2", "TLS 1.3"}) {
		t.Error("a modern-only enumeration must not count as legacy")
	}
}

// TestLegacyTLSVersionsFromRawData covers B-17(c): the accepted-version set is
// written into raw_data by both probing runtimes and was read nowhere on the
// managed-asset path.
func TestLegacyTLSVersionsFromRawData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  models.JSONB
		want int
	}{
		{"nil raw_data", nil, 0},
		{"key absent", models.JSONB{"source": "sensor_discovery"}, 0},
		// Post-JSONB-scan shape.
		{"json array with legacy", models.JSONB{"tls_versions": []interface{}{"TLS 1.0", "TLS 1.2"}}, 1},
		{"json array clean", models.JSONB{"tls_versions": []interface{}{"TLS 1.2", "TLS 1.3"}}, 0},
		{"json array two legacy", models.JSONB{"tls_versions": []interface{}{"SSLv3", "TLS 1.1", "TLS 1.2"}}, 2},
		// Go-built shape.
		{"go slice", models.JSONB{"tls_versions": []string{"TLSv1.1", "TLS 1.2"}}, 1},
		// Malformed means "not measured", never "clean" — but it must not panic.
		{"wrong type", models.JSONB{"tls_versions": "TLS 1.0"}, 0},
		{"mixed junk", models.JSONB{"tls_versions": []interface{}{42, "TLS 1.0"}}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := legacyTLSVersionsFromRawData(tt.raw); len(got) != tt.want {
				t.Fatalf("legacyTLSVersionsFromRawData(%v) = %v, want %d entries", tt.raw, got, tt.want)
			}
		})
	}
}

// TestAnalyzeCryptoRisk_ReportsAcceptedLegacyVersions proves the risk factor a
// user actually sees: a server that NEGOTIATES TLS 1.3 but still ACCEPTS TLS
// 1.0 must be flagged. Before the fix the managed-asset path had no signal at
// all for this, while the byte-identical external observation was flagged.
func TestAnalyzeCryptoRisk_ReportsAcceptedLegacyVersions(t *testing.T) {
	t.Parallel()

	version := "TLS 1.3"
	impl := &models.CryptoImplementation{
		Protocol:        "TLS",
		ProtocolVersion: &version,
		RawData:         models.JSONB{"tls_versions": []interface{}{"TLS 1.0", "TLS 1.2", "TLS 1.3"}},
	}
	factors := (&AssetService{}).AnalyzeCryptoRisk(impl)

	var found bool
	for _, f := range factors {
		if f == "Server accepts legacy TLS: TLS 1.0" {
			found = true
		}
		if f == "Outdated TLS version" {
			t.Errorf("negotiated TLS 1.3 must not be reported as outdated; factors = %v", factors)
		}
	}
	if !found {
		t.Fatalf("no legacy-TLS risk factor; factors = %v", factors)
	}

	// And the negotiated-version check still fires on its own, for the spaced
	// spelling that the previous `version < "1.2"` string comparison missed.
	legacy := "TLS 1.0"
	factors = (&AssetService{}).AnalyzeCryptoRisk(&models.CryptoImplementation{
		Protocol:        "TLS",
		ProtocolVersion: &legacy,
	})
	found = false
	for _, f := range factors {
		if f == "Outdated TLS version" {
			found = true
		}
	}
	if !found {
		t.Fatalf(`negotiated "TLS 1.0" was not reported outdated; factors = %v`, factors)
	}
}

// TestFindingDiscoveryMethod covers B-45's mapping: every value it can return
// must be a member of the discovery_method ENUM, or the INSERT aborts.
func TestFindingDiscoveryMethod(t *testing.T) {
	t.Parallel()

	// Mirrors the ENUM in scripts/database/schema.sql.
	enum := map[string]bool{
		"passive": true, "active": true, "manual": true, "integration": true,
		"device_interrogation": true, "cloud_api": true,
		"source_code_scan": true, "host_scan": true,
	}
	for producer, mapped := range discoveryMethodByProducerString {
		if !enum[mapped] {
			t.Errorf("producer %q maps to %q, which is not a discovery_method enum member", producer, mapped)
		}
	}
	for source, mapped := range discoveryMethodBySourceString {
		if !enum[mapped] {
			t.Errorf("source %q maps to %q, which is not a discovery_method enum member", source, mapped)
		}
	}
	if !enum[defaultDiscoveryMethod] {
		t.Errorf("defaultDiscoveryMethod %q is not a discovery_method enum member", defaultDiscoveryMethod)
	}

	tests := []struct {
		name string
		raw  map[string]interface{}
		want string
	}{
		{"nil", nil, "integration"},
		{"explicit passive", map[string]interface{}{"discovery_method": "passive"}, "passive"},
		{"case and space tolerant", map[string]interface{}{"discovery_method": " Active_Enrichment "}, "active"},
		{"source second chance", map[string]interface{}{"source": "cloud_discovery"}, "cloud_api"},
		{"discovery_method wins over source", map[string]interface{}{"discovery_method": "passive", "source": "cloud_discovery"}, "passive"},
		{"ambiguous source is not guessed", map[string]interface{}{"source": "connection_elevation"}, "integration"},
		{"non-string value", map[string]interface{}{"discovery_method": 7}, "integration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := findingDiscoveryMethod(IngestFinding{RawData: tt.raw}); got != tt.want {
				t.Fatalf("findingDiscoveryMethod(%v) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
