package services

import (
	"testing"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// The device-interrogation management probe (the shared TLSProber) measures
// the TLS key exchange like every other handshake site. Its result reaches
// inventory through buildSensorDiscoveryMetadata, which is an ALLOWLIST — a key
// it does not name is dropped before discovery-processor ever sees it. The
// hybrid-support flags are what the "supports hybrid, negotiated classical"
// remediation hint reads ( W1.9), so they must survive it, and an
// unanswered question must stay absent rather than become false.
func TestManagementProbe_HybridSupportReachesDiscoveryRow(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			ca, err := (&di.TLSProber{InsecureSkipVerify: true}).ProbeTLS(srv.Host, srv.Port)
			if err != nil {
				t.Fatalf("ProbeTLS: %v", err)
			}
			row := roundTripJSON(t, buildSensorDiscoveryMetadata(nil, nil, toDiscoveredAsset(ca, nil)))
			if row["key_exchange_algorithm"] != c.WantGroup {
				t.Errorf("key_exchange_algorithm = %v, want %q", row["key_exchange_algorithm"], c.WantGroup)
			}
			if row["tls_supports_classical_kex"] != c.WantSupportsClassical || row["tls_supports_pqc_hybrid_kex"] != c.WantSupportsPQCHybrid {
				t.Errorf("support flags = %v / %v, want %v / %v",
					row["tls_supports_classical_kex"], row["tls_supports_pqc_hybrid_kex"], c.WantSupportsClassical, c.WantSupportsPQCHybrid)
			}
			checkHybridGroup(t, "discovery row", c, row)
		})
	}
}

// A flag the probe never answered stays absent all the way through: absent is
// "unknown", and writing false for it would claim the server refused a hybrid
// offer nobody made.
func TestBuildSensorDiscoveryMetadata_UnansweredHybridSupportStaysAbsent(t *testing.T) {
	asset := toDiscoveredAsset(&di.CryptoAsset{
		Hostname: "fw.example.com", Port: 443, Protocol: "TLS",
		Metadata: map[string]interface{}{"key_exchange_algorithm": "X25519", "tls_supports_classical_kex": true},
	}, nil)
	row := buildSensorDiscoveryMetadata(nil, nil, asset)
	for _, key := range []string{"tls_supports_pqc_hybrid_kex", "tls_pqc_hybrid_kex_group"} {
		if v, present := row[key]; present {
			t.Errorf("%s = %v, want absent — the probe never answered it", key, v)
		}
	}
	if row["tls_supports_classical_kex"] != true {
		t.Errorf("tls_supports_classical_kex = %v, want true", row["tls_supports_classical_kex"])
	}
}

// Only a bool is a support answer and only a hybrid group name is a hybrid
// group. A collector's metadata map is not trusted to hold either.
func TestBuildSensorDiscoveryMetadata_HybridSupportTypesAreChecked(t *testing.T) {
	asset := toDiscoveredAsset(&di.CryptoAsset{
		Hostname: "fw.example.com", Port: 443, Protocol: "TLS",
		Metadata: map[string]interface{}{
			"tls_supports_pqc_hybrid_kex": "true",
			"tls_supports_classical_kex":  1,
			"tls_pqc_hybrid_kex_group":    "X25519",
		},
	}, nil)
	row := buildSensorDiscoveryMetadata(nil, nil, asset)
	for _, key := range []string{"tls_supports_pqc_hybrid_kex", "tls_supports_classical_kex", "tls_pqc_hybrid_kex_group"} {
		if v, present := row[key]; present {
			t.Errorf("%s = %v (%T), want absent", key, v, v)
		}
	}
}
