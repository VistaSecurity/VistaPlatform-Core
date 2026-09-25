package converter

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// A TLS discovery's negotiated key-exchange group reaches the finding's key
// exchange — which is what inventory links as the configuration's key_exchange
// component and the PQC classifier reads. For a TLS 1.3 endpoint it is the only
// key exchange there is: TLS_AES_128_GCM_SHA256 names none, so without it
// ingest assumes classical ECDHE and reports a hybrid endpoint as needing
// migration.
func TestToIngestFinding_TLSKeyExchangeGroupReachesKeyExchange(t *testing.T) {
	tests := []struct {
		name    string
		meta    map[string]interface{}
		want    string
		wantPQC bool
	}{
		{
			// The standalone sensor's shape: sensor-manager nests the
			// sensor's RawMetadata under raw_metadata.
			name: "sensor envelope, hybrid",
			meta: tlsKexEnvelope(map[string]interface{}{
				"key_exchange_algorithm": "X25519MLKEM768", "key_exchange_group_raw": 4588,
				"tls_supports_classical_kex": false, "tls_supports_pqc_hybrid_kex": true,
			}),
			want: "X25519MLKEM768", wantPQC: true,
		},
		{
			name: "sensor envelope, classical",
			meta: tlsKexEnvelope(map[string]interface{}{
				"key_exchange_algorithm": "X25519", "key_exchange_group_raw": 29,
				"tls_supports_classical_kex": true, "tls_supports_pqc_hybrid_kex": false,
			}),
			want: "X25519", wantPQC: false,
		},
		{
			// The cloud collectors' shape: crypto fields at the top level.
			name: "cloud row, hybrid",
			meta: map[string]interface{}{
				"version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "discovery_method": "cloud_api",
				"key_exchange_algorithm": "SecP256r1MLKEM768", "key_exchange_group_raw": 4587,
			},
			want: "SecP256r1MLKEM768", wantPQC: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := convertTLSKex(t, tt.meta)
			if f.KeyExchangeAlgorithm == nil || *f.KeyExchangeAlgorithm != tt.want {
				t.Fatalf("KeyExchangeAlgorithm = %v, want %q", f.KeyExchangeAlgorithm, tt.want)
			}
			if f.RawData["pqc_kex_detected"] != tt.wantPQC {
				t.Errorf("pqc_kex_detected = %v, want %v", f.RawData["pqc_kex_detected"], tt.wantPQC)
			}
		})
	}
}

// Passive capture writes a cipher-suite LABEL ("ECDHE_RSA") under the same
// key, with no measured group beside it. This read promotes only a measured
// group; a label is left to the ingest's cipher-suite parse as before, because
// promoting it would suppress that parse while resolving to no catalogue row.
func TestToIngestFinding_SuiteLabelWithoutMeasuredGroupIsNotPromoted(t *testing.T) {
	f := convertTLSKex(t, tlsKexEnvelope(map[string]interface{}{"key_exchange_algorithm": "ECDHE_RSA"}))
	if f.KeyExchangeAlgorithm != nil {
		t.Errorf("KeyExchangeAlgorithm = %q, want nil — a suite label is not a measured group", *f.KeyExchangeAlgorithm)
	}
}

func tlsKexEnvelope(raw map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "key_size": 0,
		"discovery_method": "active_enrichment", "raw_metadata": raw,
	}
}

func convertTLSKex(t *testing.T, meta map[string]interface{}) *IngestFinding {
	t.Helper()
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f, err := NewSensorDiscoveryConverter().ToIngestFinding(&models.SensorDiscovery{
		ID: uuid.New(), SensorID: uuid.New(), Protocol: "TLS", DestIP: "192.0.2.10", Port: 443, Metadata: b,
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	return f
}
