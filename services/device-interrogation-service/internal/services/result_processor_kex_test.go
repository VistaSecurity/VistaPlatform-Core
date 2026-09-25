package services

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse/cryptoparsetest"
)

// The metadata this writer produces is the only thing discovery-processor sees
// of an interrogated tunnel. It must name the key exchange under the key the
// converter reads, carry the whole offered-group list, and put the key
// exchange's key size — not the cipher's — in key_size.
//
// Each case runs twice: once as an agent built BEFORE this contract reports it
// (the group only in metadata, the AES length in key_size), and once as a
// current collector reports it. Agents in the field update later than the
// platform does, and both must land identically.
func TestBuildSensorDiscoveryMetadata_VPNKeyExchangeContract(t *testing.T) {
	deviceID := uuid.New()
	for _, c := range cryptoparsetest.VPNKeyExchangeCases {
		legacy := models.DiscoveredAsset{
			Protocol:             c.Protocol,
			CipherSuite:          c.CipherSuite,
			HashAlgorithm:        c.Hash,
			KeySize:              c.CipherKeyBits,
			KeyExchangeAlgorithm: c.CollectorKex,
			Metadata:             map[string]interface{}{},
		}
		if c.DHGroup != "" {
			legacy.Metadata["dh_group"] = c.DHGroup
		}
		if c.PFSGroup != "" {
			legacy.Metadata["pfs_dh_group"] = c.PFSGroup
		}
		current := legacy
		current.KeyExchangeAlgorithm = c.WantKex
		current.KeySize = c.WantKeySize

		for label, asset := range map[string]models.DiscoveredAsset{"legacy-agent": legacy, "current": current} {
			t.Run(c.Name+"/"+label, func(t *testing.T) {
				// Round-trip through JSON: this is what the row stores and what
				// the converter decodes.
				blob, err := json.Marshal(buildSensorDiscoveryMetadata(&deviceID, nil, asset))
				if err != nil {
					t.Fatal(err)
				}
				var meta map[string]interface{}
				if err := json.Unmarshal(blob, &meta); err != nil {
					t.Fatal(err)
				}

				if got, present := meta["key_exchange_algorithm"]; c.WantKex == "" {
					if present {
						t.Errorf("key_exchange_algorithm = %v, want absent — the key exchange is unknown", got)
					}
				} else if got != c.WantKex {
					t.Errorf("key_exchange_algorithm = %v, want %s", got, c.WantKex)
				}
				offered, present := meta["kex_algorithms"]
				if c.WantOffered == nil {
					if present {
						t.Errorf("kex_algorithms = %v, want absent", offered)
					}
				} else {
					var got []string
					if list, ok := offered.([]interface{}); ok {
						for _, v := range list {
							s, _ := v.(string)
							got = append(got, s)
						}
					}
					if !reflect.DeepEqual(got, c.WantOffered) {
						t.Errorf("kex_algorithms = %v, want %v", offered, c.WantOffered)
					}
				}
				if got, present := meta["key_size"]; c.WantKeySize == 0 {
					if present {
						t.Errorf("key_size = %v, want absent — never the cipher's length beside a DH exchange", got)
					}
				} else if f, _ := got.(float64); int(f) != c.WantKeySize {
					t.Errorf("key_size = %v, want %d", got, c.WantKeySize)
				}
			})
		}
	}
}

// An agent built before the UniFi fix reports the IKE VERSION as the key
// exchange. It must not reach the converter as one: the version goes where
// versions go, and the group (when present) is the key exchange.
func TestBuildSensorDiscoveryMetadata_LegacyIKEVersionIsNotAKeyExchange(t *testing.T) {
	deviceID := uuid.New()

	withGroup := buildSensorDiscoveryMetadata(&deviceID, nil, models.DiscoveredAsset{
		Protocol:             "IPSec",
		KeyExchangeAlgorithm: "IKEV2",
		KeySize:              256,
		Metadata:             map[string]interface{}{"dh_group": "14"},
	})
	if got := withGroup["key_exchange_algorithm"]; got != "DH-MODP-2048" {
		t.Errorf("key_exchange_algorithm = %v, want DH-MODP-2048", got)
	}
	if got := withGroup["version"]; got != "IKEv2" {
		t.Errorf("version = %v, want IKEv2 carried over from the misplaced scalar", got)
	}

	noGroup := buildSensorDiscoveryMetadata(&deviceID, nil, models.DiscoveredAsset{
		Protocol:             "IPSec",
		ProtocolVersion:      "IKEv1",
		KeyExchangeAlgorithm: "IKEV2",
		KeySize:              256,
	})
	if got, present := noGroup["key_exchange_algorithm"]; present {
		t.Errorf("key_exchange_algorithm = %v, want absent — an IKE version is not a key exchange", got)
	}
	if got := noGroup["version"]; got != "IKEv1" {
		t.Errorf("version = %v, want the reported IKEv1 kept, not overwritten", got)
	}
	if got := noGroup["key_size"]; got != 256 {
		t.Errorf("key_size = %v, want 256 untouched when no group resolves", got)
	}
}

// dh_group "33 14": the preferred group (GOST) has no catalogue row. The
// review found the writer emitting kex_algorithms ["DH-MODP-2048"] with no
// scalar and the AES length still in key_size — and the converter then took
// the offer list's head as the key exchange at 256 bits, which scores
// Critical. The key exchange is unknown, and key_size must not survive.
func TestBuildSensorDiscoveryMetadata_UnassessableFirstGroupDropsKeySize(t *testing.T) {
	deviceID := uuid.New()
	meta := buildSensorDiscoveryMetadata(&deviceID, nil, models.DiscoveredAsset{
		Protocol:    "IPSec",
		CipherSuite: "aes256-sha256",
		KeySize:     256,
		Metadata:    map[string]interface{}{"dh_group": "33 14"},
	})
	if got, present := meta["key_size"]; present {
		t.Errorf("key_size = %v, want absent — the AES length beside a DH offer reads as a 256-bit finite-field key", got)
	}
	if got, present := meta["key_exchange_algorithm"]; present {
		t.Errorf("key_exchange_algorithm = %v, want absent — group 14 is the second choice, not the one in use", got)
	}
	if got := meta["kex_algorithms"]; !reflect.DeepEqual(got, []string{"DH-MODP-2048"}) {
		t.Errorf("kex_algorithms = %v, want [DH-MODP-2048]", got)
	}

	// GOST alone: nothing to offer, and still no AES length.
	gostOnly := buildSensorDiscoveryMetadata(&deviceID, nil, models.DiscoveredAsset{
		Protocol: "IPSec", KeySize: 256, Metadata: map[string]interface{}{"dh_group": "33"},
	})
	for _, k := range []string{"key_size", "key_exchange_algorithm", "kex_algorithms"} {
		if v, present := gostOnly[k]; present {
			t.Errorf("GOST-only: %s = %v, want absent", k, v)
		}
	}
}

// Non-VPN assets are untouched: no dh_group, no rewrite.
func TestBuildSensorDiscoveryMetadata_TLSKeyExchangeUntouched(t *testing.T) {
	deviceID := uuid.New()
	meta := buildSensorDiscoveryMetadata(&deviceID, nil, models.DiscoveredAsset{
		Protocol:             "TLS",
		KeyExchangeAlgorithm: "ECDHE",
		KeySize:              2048,
	})
	if meta["key_exchange_algorithm"] != "ECDHE" || meta["key_size"] != 2048 {
		t.Errorf("TLS kex/key_size rewritten: %v / %v", meta["key_exchange_algorithm"], meta["key_size"])
	}
	if _, present := meta["kex_algorithms"]; present {
		t.Errorf("kex_algorithms invented for a TLS asset: %v", meta["kex_algorithms"])
	}
}
