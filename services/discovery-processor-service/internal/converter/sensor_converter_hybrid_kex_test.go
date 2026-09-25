package converter

import "testing"

// The TLS key-exchange SUPPORT answers — does the server accept a hybrid
// post-quantum offer, and which hybrid group did it pick — reach the finding's
// raw_data, which inventory stores on the crypto configuration. They are what
// the "supports hybrid, negotiated classical" remediation hint reads (
// W1.9). The standalone sensor nests them inside the raw_metadata envelope;
// cloud and interrogation rows carry them at the top level. A false must stay
// false and an absent answer must stay absent.
func TestToIngestFinding_HybridKexSupportReachesRawData(t *testing.T) {
	tests := []struct {
		name      string
		meta      map[string]interface{}
		wantKex   string
		wantFlag  interface{} // nil = absent
		wantGroup interface{} // nil = absent
	}{
		{
			name: "sensor envelope, supports hybrid, negotiated classical",
			meta: tlsKexEnvelope(map[string]interface{}{
				"key_exchange_algorithm": "X25519", "key_exchange_group_raw": 29,
				"tls_supports_classical_kex": true, "tls_supports_pqc_hybrid_kex": true,
				"tls_pqc_hybrid_kex_group": "X25519MLKEM768",
			}),
			wantKex: "X25519", wantFlag: true, wantGroup: "X25519MLKEM768",
		},
		{
			name: "interrogation row at the top level",
			meta: map[string]interface{}{
				"version": "TLS 1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "discovery_method": "device_interrogation",
				"device_id": "4f7c2d1e-0000-4000-8000-000000000001", "key_exchange_algorithm": "DH-ECP-256",
				"tls_supports_classical_kex": true, "tls_supports_pqc_hybrid_kex": true,
				"tls_pqc_hybrid_kex_group": "SecP256r1MLKEM768",
			},
			wantKex: "DH-ECP-256", wantFlag: true, wantGroup: "SecP256r1MLKEM768",
		},
		{
			name: "server refused the hybrid offer",
			meta: tlsKexEnvelope(map[string]interface{}{
				"key_exchange_algorithm": "X25519", "key_exchange_group_raw": 29,
				"tls_supports_classical_kex": true, "tls_supports_pqc_hybrid_kex": false,
			}),
			wantKex: "X25519", wantFlag: false,
		},
		{
			name: "hybrid support never asked",
			meta: tlsKexEnvelope(map[string]interface{}{
				"key_exchange_algorithm": "X25519", "key_exchange_group_raw": 29,
				"tls_supports_classical_kex": true,
			}),
			wantKex: "X25519",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := convertTLSKex(t, tt.meta)
			if f.KeyExchangeAlgorithm == nil || *f.KeyExchangeAlgorithm != tt.wantKex {
				t.Errorf("KeyExchangeAlgorithm = %v, want %q", f.KeyExchangeAlgorithm, tt.wantKex)
			}
			for key, want := range map[string]interface{}{
				"tls_supports_pqc_hybrid_kex": tt.wantFlag,
				"tls_pqc_hybrid_kex_group":    tt.wantGroup,
			} {
				got, present := f.RawData[key]
				switch {
				case want == nil && present:
					t.Errorf("raw_data[%s] = %v, want absent", key, got)
				case want != nil && got != want:
					t.Errorf("raw_data[%s] = %v (present=%v), want %v", key, got, present, want)
				}
			}
		})
	}
}
