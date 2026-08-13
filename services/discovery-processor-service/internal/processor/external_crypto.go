package processor

import (
	"encoding/json"
	"strings"
	"time"
)

// ExternalCryptoDetails holds the normalised crypto and certificate fields
// extracted from a sensor discovery's metadata JSONB blob.
// Handles:
//   - Passive capture + Active probe / TLS enricher: structured "certificates" array with a CertificateInfo per cert
//   - Envelope shape: sensor-manager wraps sensor fields with top-level version/cipher_suite
//     and nests the rest in "raw_metadata" — see flattenSensorDiscoveryMetadata.
type ExternalCryptoDetails struct {
	ProtocolVersion      *string
	CipherSuite          *string
	KeyExchangeAlgorithm *string
	KeySize              *int
	SupportedTLSVersions []string

	CertSubject            *string
	CertIssuer             *string
	CertSAN                []string
	CertNotBefore          *time.Time
	CertNotAfter           *time.Time
	CertFingerprintSHA256  *string
	CertPublicKeyAlgorithm *string
	CertPublicKeySize      *int
	CertSignatureAlgorithm *string
	CertValidationStatus   *string
	CertPEM                *string

	// Sensor-level certificate quality flags (from classifyCertificateFlags)
	CertHasSCT        *bool   // Certificate Transparency: embedded SCTs present
	CertKnownBadCA    *string // Known-bad CA name (Superfish, eDellRoot, etc.)
	CertNoSubject     bool    // Certificate has no subject DN
	CertNoCommonName  bool    // Certificate has no Common Name
	CertIsEV          bool    // Extended Validation certificate
	CertLargeSANCount *int    // SAN count if > 100
	OCSPStatus        *string // OCSP revocation status (good/revoked/unknown)
}

// flattenSensorDiscoveryMetadata merges the envelope written by sensor-manager
// (version, cipher_suite, discovery_method, …) with the nested "raw_metadata"
// object that holds passive TLS / active-enrichment payloads (certificates array,
// handshake_types, supported_ciphers, …). Outer keys win on conflict so the
// control-plane normalisation layer does not hide TLS enrichment from
// extractCryptoDetails.
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
func flattenSensorDiscoveryMetadata(raw map[string]interface{}) map[string]interface{} {
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

// extractCryptoDetails parses sensor discovery metadata and returns normalised
// crypto and certificate information. Returns nil if metadata is empty.
func extractCryptoDetails(metadata []byte) *ExternalCryptoDetails {
	if len(metadata) == 0 {
		return nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(metadata, &raw); err != nil {
		return nil
	}

	raw = flattenSensorDiscoveryMetadata(raw)

	d := &ExternalCryptoDetails{}

	// Protocol version
	if v := stringField(raw, "version"); v != "" {
		d.ProtocolVersion = &v
	}

	// Cipher suite (passive: "cipher_suite"; active probe: "selected_cipher")
	if v := stringField(raw, "cipher_suite"); v != "" {
		d.CipherSuite = &v
	} else if v := stringField(raw, "selected_cipher"); v != "" {
		d.CipherSuite = &v
	}

	// Key exchange algorithm — present in both passive and active paths:
	//   passive:      emitted by sensor as "key_exchange_algorithm" (parsed from cipher suite)
	//   active probe: set from DiscoveryFinding.KeyExchangeAlgorithm
	if v := stringField(raw, "key_exchange_algorithm"); v != "" {
		d.KeyExchangeAlgorithm = &v
	}

	// Supported TLS versions from active enumeration probe
	if versions := stringSliceField(raw, "tls_versions"); len(versions) > 0 {
		d.SupportedTLSVersions = versions
	}

	// Explicit key_size from metadata (active probe may set this directly)
	if n := intField(raw, "key_size"); n > 0 {
		d.KeySize = &n
	}
	// Derive cipher symmetric key size from suite name when not explicitly provided
	if d.KeySize == nil && d.CipherSuite != nil {
		if ks := keySizeFromCipherSuite(*d.CipherSuite); ks > 0 {
			d.KeySize = &ks
		}
	}

	// Both passive capture and active probe now emit a "certificates" array
	if certs, ok := raw["certificates"].([]interface{}); ok && len(certs) > 0 {
		// Find the leaf cert: lowest chain_order or index 0
		leaf := leafCert(certs)
		if leaf != nil {
			d.CertSubject = strPtr(stringField(leaf, "subject_dn"))
			d.CertIssuer = strPtr(stringField(leaf, "issuer_dn"))
			if sa := stringSliceField(leaf, "subject_alternative_names"); len(sa) > 0 {
				d.CertSAN = sa
			}
			d.CertNotBefore = timeField(leaf, "not_before")
			d.CertNotAfter = timeField(leaf, "not_after")
			d.CertFingerprintSHA256 = strPtr(stringField(leaf, "fingerprint_sha256"))
			d.CertPublicKeyAlgorithm = strPtr(stringField(leaf, "key_algorithm"))
			if n := intField(leaf, "key_size"); n > 0 {
				d.CertPublicKeySize = &n
			}
			d.CertSignatureAlgorithm = strPtr(stringField(leaf, "signature_alg"))
			// Leaf entries usually omit cert_validation_status; the sensor
			// places it on the metadata envelope alongside "certificates".
			if vs := stringField(leaf, "cert_validation_status"); vs != "" {
				d.CertValidationStatus = strPtr(vs)
			} else if vs := stringField(raw, "cert_validation_status"); vs != "" {
				d.CertValidationStatus = strPtr(vs)
			}
			d.CertPEM = strPtr(stringField(leaf, "certificate_pem"))
		}
	}

	// --- Sensor-level certificate quality flags ---
	// These are set by classifyCertificateFlags() in the sensor's active prober
	// and enricher, stored in RawMetadata alongside the cert fields.
	if v, ok := raw["cert_has_sct"]; ok {
		if b, ok := v.(bool); ok {
			d.CertHasSCT = &b
		}
	}
	if v := stringField(raw, "cert_known_bad_ca"); v != "" {
		d.CertKnownBadCA = &v
	}
	if v, ok := raw["cert_no_subject"]; ok {
		if b, ok := v.(bool); ok {
			d.CertNoSubject = b
		}
	}
	if v, ok := raw["cert_no_common_name"]; ok {
		if b, ok := v.(bool); ok {
			d.CertNoCommonName = b
		}
	}
	if v, ok := raw["cert_is_ev"]; ok {
		if b, ok := v.(bool); ok {
			d.CertIsEV = b
		}
	}
	if n := intField(raw, "cert_large_san_count"); n > 0 {
		d.CertLargeSANCount = &n
	}
	if v := stringField(raw, "ocsp_status"); v != "" {
		d.OCSPStatus = &v
	}

	return d
}

// keySizeFromCipherSuite extracts the symmetric cipher key size (in bits) from a
// TLS cipher suite name. Returns 0 if the suite name doesn't contain a recognisable
// key-size marker.
func keySizeFromCipherSuite(suite string) int {
	switch {
	case strings.Contains(suite, "_AES_256_"):
		return 256
	case strings.Contains(suite, "_AES_128_"):
		return 128
	case strings.Contains(suite, "_CHACHA20_"):
		return 256
	case strings.Contains(suite, "_3DES_"):
		return 168
	case strings.Contains(suite, "_RC4_128_"):
		return 128
	case strings.Contains(suite, "_RC4_40_"):
		return 40
	case strings.Contains(suite, "_DES40_"):
		return 40
	case strings.Contains(suite, "_DES_"):
		return 56
	}
	return 0
}

// leafCert picks the leaf certificate from the certificates array.
// Prefers the entry with the lowest chain_order value; only considers certs
// that have chain_order set. Falls back to index 0 when none have chain_order.
func leafCert(certs []interface{}) map[string]interface{} {
	var best map[string]interface{}
	bestOrder := int(^uint(0) >> 1) // max int

	for _, c := range certs {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		order, hasOrder := intFieldOptional(m, "chain_order")
		if !hasOrder {
			continue // skip certs without chain_order to avoid treating missing as 0
		}
		if order < bestOrder {
			bestOrder = order
			best = m
		}
	}

	if best == nil && len(certs) > 0 {
		best, _ = certs[0].(map[string]interface{})
	}
	return best
}

// --- helpers ---

func stringField(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func intField(m map[string]interface{}, key string) int {
	n, _ := intFieldOptional(m, key)
	return n
}

func intFieldOptional(m map[string]interface{}, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

func stringSliceField(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// timeFieldLayouts lists formats accepted when parsing time strings from sensor
// metadata. Active probes emit RFC3339; the passive tls_assembler previously
// emitted Go's time.Time.String() format. We accept both for robustness.
var timeFieldLayouts = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05 -0700 MST",
}

func timeField(m map[string]interface{}, key string) *time.Time {
	s := stringField(m, key)
	if s == "" {
		return nil
	}
	for _, layout := range timeFieldLayouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return &t
		}
	}
	return nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
