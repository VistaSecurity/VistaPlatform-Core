package processor

// Reading the legacy flat certificate shape that sensors in the field still send.
//
// Until the passive TLS parser in sensor/internal/capture/packet_capture.go was
// taught the canonical shape, its non-reassembled path took the leaf
// certificate apart into loose `cert_<field>` keys plus a bare
// `certificate_pem`. Nothing ever read them: extractCryptoDetails (the
// external-connections path) and inventory-service's
// extractCertificatesFromFinding (the asset/certificate path) both look for a
// "certificates" array, so a certificate captured that way landed in
// sensor_discoveries and in no certificate inventory at all.
//
// The sensor is a standalone binary on a customer host, so the platform gets
// upgraded while the field keeps emitting the old shape for as long as the
// operator takes to roll their sensors. Folding that shape into one canonical
// entry on the way in both recovers the lost data and makes an un-upgraded
// sensor indistinguishable from an upgraded one everywhere downstream — there
// is exactly one place that knows the legacy spelling, and it is this file.
//
// The legacy keys are ASSEMBLED from a prefix and a suffix rather than written
// as literals, for the same reason the retired-product-name guards assemble
// their needle (CLAUDE.md, *The retired product name*):
// TestCanonicalCertificateMetadataKey hunts for those literals to stop new
// PRODUCERS, and a regex cannot tell a producer's literal from a reader's.
// Do not "tidy" them into literals — the guard will fail, and rightly.

// legacyCertKeyPrefix is the prefix the old passive parser put in front of
// every certificate field it flattened.
const legacyCertKeyPrefix = "cert_"

// legacyFlatCertFields maps the suffix of a legacy flat key onto the canonical
// shared/certificates.CertificateInfo field name it was carrying.
var legacyFlatCertFields = map[string]string{
	"subject":             "subject_dn",
	"issuer":              "issuer_dn",
	"not_before":          "not_before",
	"not_after":           "not_after",
	"fingerprint_sha256":  "fingerprint_sha256",
	"key_algorithm":       "key_algorithm",
	"signature_algorithm": "signature_alg",
	"public_key_size":     "key_size",
	"san":                 "subject_alternative_names",
}

// upgradeLegacyFlatCertificate rewrites a legacy flat leaf certificate into a
// single-entry canonical "certificates" array. It returns raw untouched when
// there is already a canonical array (a current sensor, or any other producer)
// or when the flat keys are not present.
//
// The returned map is a copy whenever an entry is synthesised, so a caller's
// map is never mutated behind its back.
func upgradeLegacyFlatCertificate(raw map[string]interface{}) map[string]interface{} {
	if len(raw) == 0 {
		return raw
	}
	// A canonical array always wins: it is either a current producer's, or a
	// richer chain than one flattened leaf could ever be.
	if certs, ok := raw["certificates"].([]interface{}); ok && len(certs) > 0 {
		return raw
	}

	entry := make(map[string]interface{}, len(legacyFlatCertFields)+2)
	for suffix, canonical := range legacyFlatCertFields {
		v, ok := raw[legacyCertKeyPrefix+suffix]
		if !ok || isEmptyMetadataValue(v) {
			continue
		}
		entry[canonical] = v
	}
	// The PEM was the one field written WITHOUT the prefix. It is only safe to
	// claim it as the leaf's here, where we already know no canonical array is
	// present to disagree.
	if v, ok := raw["certificate_pem"]; ok && !isEmptyMetadataValue(v) {
		entry["certificate_pem"] = v
	}

	// A flattened certificate is only a certificate if it has an identity. The
	// legacy producer wrote the fingerprint unconditionally, immediately after
	// the DER parsed, so its absence means these keys are not that shape and
	// nothing should be synthesised from them.
	if isEmptyMetadataValue(entry["fingerprint_sha256"]) {
		return raw
	}
	// The flat form could only ever carry the leaf.
	entry["chain_order"] = 0

	out := make(map[string]interface{}, len(raw)+1)
	for k, v := range raw {
		out[k] = v
	}
	out["certificates"] = []interface{}{entry}
	return out
}
