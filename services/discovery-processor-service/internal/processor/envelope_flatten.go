package processor

import (
	"encoding/json"
	"strings"
)

// flattenSensorDiscoveryMetadata merges the envelope written by sensor-manager
// (version, cipher_suite, discovery_method, …) with the nested "raw_metadata"
// object that holds passive TLS / active-enrichment payloads (certificates array,
// handshake_types, supported_ciphers, …). Outer keys win on conflict so the
// control-plane normalisation layer does not hide TLS enrichment from
// inventory-service's certificate and quality-flag readers.
//
// EXCEPT when the outer value is empty. sensor-manager's StoreDiscoveries writes
// all five envelope keys unconditionally, whether or not the sensor populated
// the corresponding struct field, so `"version": ""` is written for every
// discovery whose top-level Version is unset. An unconditional outer-wins merge
// let that empty string erase a populated raw_metadata["version"] — which is why
// TLS-over-TCP rows reached external_connections with a cipher suite and a full
// certificate chain but protocol_version NULL. The active TLS enricher sets
// metadata["version"] from the ServerHello it just parsed, while the discovery's
// own Version field carries the (often empty) version of the passive observation
// that triggered enrichment.
//
// An empty value carries no information, so it must not win over one that does.
// This applies to every envelope key, not just version: cipher_suite and
// key_size are shadowed by "" and 0 the same way.
//
// Flattening is also where the legacy flat certificate shape is folded back
// into the canonical "certificates" array — the one seam every imported
// finding passes through, third-party ones included since WP3, so an
// un-upgraded sensor is handled identically whichever table its finding
// lands in.
func flattenSensorDiscoveryMetadata(raw map[string]interface{}) map[string]interface{} {
	return upgradeLegacyFlatCertificate(flattenSensorDiscoveryEnvelope(raw))
}

// flattenSensorDiscoveryEnvelope performs the envelope merge described above.
func flattenSensorDiscoveryEnvelope(raw map[string]interface{}) map[string]interface{} {
	nested, ok := raw["raw_metadata"].(map[string]interface{})
	if !ok || len(nested) == 0 {
		return raw
	}
	out := make(map[string]interface{}, len(nested)+len(raw))
	for k, v := range nested {
		out[k] = v
	}
	for k, v := range raw {
		if k == "raw_metadata" {
			continue
		}
		if isEmptyMetadataValue(v) {
			if existing, present := out[k]; present && !isEmptyMetadataValue(existing) {
				continue
			}
		}
		out[k] = v
	}
	return out
}

// isEmptyMetadataValue reports whether a decoded JSON value carries no
// information — nil, the empty string, numeric zero, or an empty array/object.
// JSON numbers decode as float64 through encoding/json; json.Number is accepted
// too in case a decoder is configured with UseNumber.
func isEmptyMetadataValue(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case float64:
		return t == 0
	case int:
		return t == 0
	case json.Number:
		return t.String() == "" || t.String() == "0"
	case []interface{}:
		return len(t) == 0
	case map[string]interface{}:
		return len(t) == 0
	default:
		return false
	}
}
