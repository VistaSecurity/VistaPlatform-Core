package processor

// The envelope sensor-manager writes around a sensor discovery
// (StoreDiscoveries) sets version / cipher_suite / key_size unconditionally,
// whether or not the sensor populated the corresponding struct field. An
// unconditional outer-wins merge therefore let `"version": ""` erase a
// populated raw_metadata["version"].
//
// That is not hypothetical. Observed live in external_connections after a real
// sensor ran for hours:
//
//	protocol_version | cipher_suite           | count | with_cert
//	QUIC v1          | (null)                 |    18 |         0
//	(null)           | TLS_AES_128_GCM_SHA256 |     8 |         8
//	(null)           | TLS_AES_256_GCM_SHA384 |     1 |         1
//
// Full certificate chain and cipher suite extracted, protocol version gone —
// because the active TLS enricher writes the version it measured into
// raw_metadata while the discovery's own top-level Version carries the (empty)
// version of the passive observation that triggered the probe.
//
// The consequence is not cosmetic: protocol_version is what isWeakProtocol
// reads in inventory-service's assessCrypto, so a NULL version means a TLS 1.0
// or 1.1 connection cannot be detected or scored at all.

import (
	"encoding/json"
	"testing"
)

// TestExtractCryptoDetails_EmptyEnvelopeVersionDoesNotEraseEnrichedVersion is
// the direct regression, shaped exactly like the live data: envelope version
// empty, enriched version present, certificate present.
func TestExtractCryptoDetails_EmptyEnvelopeVersionDoesNotEraseEnrichedVersion(t *testing.T) {
	raw := map[string]interface{}{
		// The sensor-manager envelope, verbatim: the top-level fields of the
		// discovery struct, with the sensor's own map nested under raw_metadata.
		"version":          "", // discovery.Version was unset
		"cipher_suite":     "TLS_AES_128_GCM_SHA256",
		"key_size":         0,
		"discovery_method": "active_enrichment",
		"raw_metadata": map[string]interface{}{
			"version":           "TLS 1.3",
			"enrichment_method": "active_probe_after_passive",
			"certificates": []interface{}{
				map[string]interface{}{
					"chain_order":        0.0,
					"subject_dn":         "CN=example.com",
					"fingerprint_sha256": "deadbeef",
				},
			},
		},
	}
	metadata, _ := json.Marshal(raw)

	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}
	if d.ProtocolVersion == nil {
		t.Fatal("protocol version is nil — the empty envelope value erased the enriched one")
	}
	assertStrPtr(t, "protocol version", d.ProtocolVersion, "TLS 1.3")

	// And the rest of the row is unchanged: this is not a case of the nested map
	// taking over generally.
	assertStrPtr(t, "cipher suite", d.CipherSuite, "TLS_AES_128_GCM_SHA256")
	assertStrPtr(t, "cert fingerprint", d.CertFingerprintSHA256, "deadbeef")
}

// TestExtractCryptoDetails_PopulatedEnvelopeStillWins pins the other polarity.
// The envelope is the promoted, authoritative copy whenever it actually holds a
// value — a nested-wins merge would be the same bug pointed the other way, with
// a stale raw_metadata value overriding what the control plane normalised.
func TestExtractCryptoDetails_PopulatedEnvelopeStillWins(t *testing.T) {
	raw := map[string]interface{}{
		"version":      "TLS 1.2",
		"cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"raw_metadata": map[string]interface{}{
			"version":      "TLS 1.0",
			"cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		},
	}
	metadata, _ := json.Marshal(raw)

	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}
	assertStrPtr(t, "protocol version", d.ProtocolVersion, "TLS 1.2")
	assertStrPtr(t, "cipher suite", d.CipherSuite, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
}

// TestExtractCryptoDetails_EmptyEnvelopeCipherAndKeySize covers the same
// shadowing for the other two unconditionally-written envelope keys. key_size is
// numeric, so its empty form is 0 rather than "" — the shadowing is identical.
func TestExtractCryptoDetails_EmptyEnvelopeCipherAndKeySize(t *testing.T) {
	raw := map[string]interface{}{
		"version":      "TLS 1.2",
		"cipher_suite": "",
		"key_size":     0,
		"raw_metadata": map[string]interface{}{
			"cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"key_size":     256,
		},
	}
	metadata, _ := json.Marshal(raw)

	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}
	assertStrPtr(t, "cipher suite", d.CipherSuite, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	assertIntPtr(t, "key size", d.KeySize, 256)
}

// TestExtractCryptoDetails_WeakTLSVersionSurvivesTheEnvelope is the reason this
// matters. A TLS 1.0 connection is exactly what the product exists to find, and
// it is only findable if the version reaches the row: isWeakProtocol in
// inventory-service reads protocol_version and nothing else.
func TestExtractCryptoDetails_WeakTLSVersionSurvivesTheEnvelope(t *testing.T) {
	raw := map[string]interface{}{
		"version":      "",
		"cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"raw_metadata": map[string]interface{}{
			"version": "TLS 1.0",
		},
	}
	metadata, _ := json.Marshal(raw)

	d := extractCryptoDetails(metadata)
	if d == nil || d.ProtocolVersion == nil {
		t.Fatal("TLS 1.0 was dropped — it cannot be scored as a weak protocol")
	}
	assertStrPtr(t, "protocol version", d.ProtocolVersion, "TLS 1.0")
}

// TestFlattenSensorDiscoveryMetadata_EmptyBothSidesKeepsTheKey guards against
// the skip-empty rule dropping a key entirely: an envelope key that is empty on
// both sides must still be present (as empty), not vanish.
func TestFlattenSensorDiscoveryMetadata_EmptyBothSidesKeepsTheKey(t *testing.T) {
	out := flattenSensorDiscoveryMetadata(map[string]interface{}{
		"version":      "",
		"raw_metadata": map[string]interface{}{"version": "", "other": "x"},
	})
	v, present := out["version"]
	if !present {
		t.Fatal("version key disappeared from the flattened map")
	}
	if v != "" {
		t.Errorf("version = %v, want empty string", v)
	}
	if out["other"] != "x" {
		t.Errorf("nested key lost: other = %v", out["other"])
	}
}

// TestIsEmptyMetadataValue pins the emptiness rule itself, including the
// false-y-but-meaningful cases that must NOT be treated as empty — a bool false
// is a real answer (cert_has_sct, mtls_detected) and must keep winning.
func TestIsEmptyMetadataValue(t *testing.T) {
	empty := []interface{}{nil, "", "   ", 0.0, 0, []interface{}{}, map[string]interface{}{}}
	for _, v := range empty {
		if !isEmptyMetadataValue(v) {
			t.Errorf("isEmptyMetadataValue(%#v) = false, want true", v)
		}
	}

	notEmpty := []interface{}{"TLS 1.3", 1.0, 256, false, true, []interface{}{"a"}, map[string]interface{}{"a": 1}}
	for _, v := range notEmpty {
		if isEmptyMetadataValue(v) {
			t.Errorf("isEmptyMetadataValue(%#v) = true, want false", v)
		}
	}
}

// TestFlattenSensorDiscoveryMetadata_FalseEnvelopeValueStillWins is the
// consequence of the bool rule above, through the merge: an explicit false in
// the envelope must override a stale true underneath. Treating false as "empty"
// is the classic jq `//` mistake and would silently invert a security flag.
func TestFlattenSensorDiscoveryMetadata_FalseEnvelopeValueStillWins(t *testing.T) {
	out := flattenSensorDiscoveryMetadata(map[string]interface{}{
		"mtls_detected": false,
		"raw_metadata":  map[string]interface{}{"mtls_detected": true},
	})
	if out["mtls_detected"] != false {
		t.Errorf("mtls_detected = %v, want false (an explicit false is an answer, not an absence)", out["mtls_detected"])
	}
}
