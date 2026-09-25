package processor

import (
	"encoding/json"
	"testing"
)

// The external-connection path reads the same key the TLS probes write. A
// sensor row carries it nested in the raw_metadata envelope; flattening must
// deliver the negotiated group as the connection's key exchange.
func TestExtractCryptoDetails_TLSKeyExchangeGroup(t *testing.T) {
	meta, err := json.Marshal(map[string]interface{}{
		"version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "key_size": 0,
		"raw_metadata": map[string]interface{}{
			"key_exchange_algorithm": "X25519MLKEM768", "key_exchange_group_raw": 4588,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	d := extractCryptoDetails(meta)
	if d == nil || d.KeyExchangeAlgorithm == nil || *d.KeyExchangeAlgorithm != "X25519MLKEM768" {
		t.Fatalf("KeyExchangeAlgorithm = %+v, want X25519MLKEM768", d)
	}
}
