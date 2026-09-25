package converter

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse/cryptoparsetest"
)

func convertMetadata(t *testing.T, metadata map[string]interface{}) *IngestFinding {
	t.Helper()
	blob, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewSensorDiscoveryConverter().ToIngestFinding(&models.SensorDiscovery{
		ID: uuid.New(), SensorID: uuid.New(), Protocol: "IPSec", DestIP: "192.0.2.10", Port: 500,
		Metadata: blob,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func kexOf(f *IngestFinding) string {
	if f.KeyExchangeAlgorithm == nil {
		return "<nil>"
	}
	return *f.KeyExchangeAlgorithm
}

// device-interrogation-service writes an interrogated asset's key exchange as
// `key_exchange_algorithm`. This converter used to read only negotiated_kex,
// kex_algorithms and key_exchange, so for every interrogation finding the key
// exchange was dropped here — a VPN arrived in inventory linking AES and SHA-2
// only, and was classified as quantum-safe.
//
// The metadata below is what the writer produces for each contract case
// (result_processor_kex_test.go pins that half).
func TestToIngestFinding_VPNKeyExchangeContract(t *testing.T) {
	for _, c := range cryptoparsetest.VPNKeyExchangeCases {
		t.Run(c.Name, func(t *testing.T) {
			metadata := map[string]interface{}{
				"discovery_method": "device_interrogation",
				"version":          "",
				"cipher_suite":     c.CipherSuite,
				"hash_algorithm":   c.Hash,
			}
			// The writer omits what it does not know (omitempty).
			if c.WantKex != "" {
				metadata["key_exchange_algorithm"] = c.WantKex
			}
			if c.WantKeySize != 0 {
				metadata["key_size"] = c.WantKeySize
			}
			if c.WantOffered != nil {
				metadata["kex_algorithms"] = c.WantOffered
			}
			f := convertMetadata(t, metadata)

			wantKex := c.WantKex
			if wantKex == "" {
				wantKex = "<nil>" // unknown: the offer list's head must not stand in
			}
			if got := kexOf(f); got != wantKex {
				t.Errorf("KeyExchangeAlgorithm = %s, want %s", got, wantKex)
			}
			switch {
			case c.WantKeySize == 0 && f.KeySize != nil:
				t.Errorf("KeySize = %d, want nil", *f.KeySize)
			case c.WantKeySize != 0 && (f.KeySize == nil || *f.KeySize != c.WantKeySize):
				t.Errorf("KeySize = %v, want %d", f.KeySize, c.WantKeySize)
			}
			// The offered list rides through to inventory in raw_data, which
			// links every entry.
			if c.WantOffered != nil {
				var got []string
				for _, v := range f.RawData["kex_algorithms"].([]interface{}) {
					got = append(got, v.(string))
				}
				if !reflect.DeepEqual(got, c.WantOffered) {
					t.Errorf("raw_data kex_algorithms = %v, want %v", got, c.WantOffered)
				}
			}
		})
	}
}

// The interrogated scalar is read only from rows the interrogation writer
// produced, and for those rows it is the ONLY source: their kex_algorithms is
// an offer list. Every other producer keeps its existing precedence.
func TestToIngestFinding_InterrogatedKeyExchange(t *testing.T) {
	interrogated := func(kv ...interface{}) map[string]interface{} {
		m := map[string]interface{}{"discovery_method": "device_interrogation"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	cases := []struct {
		name string
		meta map[string]interface{}
		want string
	}{
		{"interrogated scalar", interrogated("key_exchange_algorithm", "Curve25519"), "Curve25519"},
		// For an interrogation row only the stated scalar counts: the offer
		// list's head is not the exchange in use.
		{"scalar, not the offer head", interrogated("kex_algorithms", []string{"DH-ECP-256", "DH-MODP-2048"}, "key_exchange_algorithm", "DH-MODP-2048"), "DH-MODP-2048"},
		{"offer list alone is not a key exchange", interrogated("kex_algorithms", []string{"DH-MODP-2048"}), "<nil>"},
		// Other producers keep their precedence.
		{"ssh negotiated", map[string]interface{}{"negotiated_kex": "curve25519-sha256", "kex_algorithms": []string{"sntrup761x25519-sha512"}}, "curve25519-sha256"},
		{"ssh offered head", map[string]interface{}{"kex_algorithms": []string{"curve25519-sha256"}}, "curve25519-sha256"},
		{"blank scalar is nothing", interrogated("key_exchange_algorithm", "  "), "<nil>"},

		// Not an interrogation row: passive capture writes a cipher-suite LABEL
		// under the same key. Promoting it would suppress the ingest's own
		// suite parse and link nothing — whether it sits at the top level or
		// inside sensor-manager's raw_metadata envelope.
		{"passive label, top level", map[string]interface{}{"key_exchange_algorithm": "ECDHE_RSA"}, "<nil>"},
		{"passive label, envelope", map[string]interface{}{
			"discovery_method": "passive", "raw_metadata": map[string]interface{}{"key_exchange_algorithm": "ECDHE_RSA"},
		}, "<nil>"},
		{"interrogation marker only in the envelope", map[string]interface{}{
			"raw_metadata": map[string]interface{}{"discovery_method": "device_interrogation", "key_exchange_algorithm": "ECDHE_RSA"},
		}, "<nil>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kexOf(convertMetadata(t, tc.meta)); got != tc.want {
				t.Errorf("KeyExchangeAlgorithm = %s, want %s", got, tc.want)
			}
		})
	}
}

// ML-KEM named in the offered list or as the scalar is the PQC signal the
// raw_data flag exists for.
func TestToIngestFinding_IKEMLKEMSetsPQCFlag(t *testing.T) {
	f := convertMetadata(t, map[string]interface{}{"discovery_method": "device_interrogation", "key_exchange_algorithm": "ML-KEM-768"})
	if f.RawData["pqc_kex_detected"] != true {
		t.Errorf("pqc_kex_detected = %v, want true for an ML-KEM key exchange", f.RawData["pqc_kex_detected"])
	}
}
