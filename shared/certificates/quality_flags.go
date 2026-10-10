package certificates

import "time"

// The certificate-quality assessment a probe stamps beside the "certificates"
// array of a discovery's metadata, read in ONE place.
//
// Active TLS probing (shared/discovery's ClassifyCertificateFlags and the OCSP
// check) and the sensor's enricher write these keys at the top level of the
// discovery metadata. CLAUDE.md requires them persisted for internal assets
// (the certificates table) AND for external connections. They used to be read
// by two hand-written extractors that disagreed: discovery-processor's
// external-connections writer read all of them, and inventory-service's ingest
// path read four for certificates and none for the external connections it
// wrote itself ( F16). Both paths now read through this function, so a
// flag added here reaches both tables or neither.

// CertificateQuality is the quality assessment carried by a discovery's
// metadata.
//
// Pointer fields are ABSENT when nil. An explicit false is an answer
// (`cert_has_sct: false` says the certificate carries no SCT) and must never be
// collapsed into "not measured" — that is the jq `//` mistake CLAUDE.md warns
// about, and it inverts a security flag.
type CertificateQuality struct {
	// ValidationStatus is the leaf's chain validation verdict (valid, expired,
	// self_signed, ...): the leaf certificate's own cert_validation_status when
	// it carries one, else the envelope's, which is where the TLS enricher puts
	// it.
	ValidationStatus *string
	HasSCT           *bool
	// SCTSource is absent (not "") when the producer could not observe the
	// TLS-extension and OCSP routes — see shared/discovery.RefineSCTFlags.
	SCTSource     *string
	KnownBadCA    *string
	NoSubject     bool
	NoCommonName  bool
	IsEV          bool
	LargeSANCount *int
	OCSPStatus    *string
	OCSPDetail    *string
}

// CertificateQualityFromMetadata reads the quality flags from a discovery's
// metadata. raw must already be flattened (the sensor-manager envelope merged
// with its nested raw_metadata), which is the shape every ingest path hands
// inventory-service. A nil map yields the zero value.
func CertificateQualityFromMetadata(raw map[string]interface{}) CertificateQuality {
	var q CertificateQuality
	if raw == nil {
		return q
	}
	if leaf := LeafCertificateEntry(raw); leaf != nil {
		q.ValidationStatus = nonEmptyString(leaf, "cert_validation_status")
	}
	if q.ValidationStatus == nil {
		q.ValidationStatus = nonEmptyString(raw, "cert_validation_status")
	}
	if v, ok := raw["cert_has_sct"].(bool); ok {
		q.HasSCT = &v
	}
	q.SCTSource = nonEmptyString(raw, "cert_sct_source")
	q.KnownBadCA = nonEmptyString(raw, "cert_known_bad_ca")
	if v, ok := raw["cert_no_subject"].(bool); ok {
		q.NoSubject = v
	}
	if v, ok := raw["cert_no_common_name"].(bool); ok {
		q.NoCommonName = v
	}
	if v, ok := raw["cert_is_ev"].(bool); ok {
		q.IsEV = v
	}
	if n, ok := metadataInt(raw["cert_large_san_count"]); ok && n > 0 {
		q.LargeSANCount = &n
	}
	q.OCSPStatus = nonEmptyString(raw, "ocsp_status")
	q.OCSPDetail = nonEmptyString(raw, "ocsp_detail")
	return q
}

// LeafCertificateEntry picks the leaf from the metadata's "certificates" array:
// the entry with the lowest chain_order, considering only entries that HAVE a
// chain_order (a missing one is not 0); the first entry when none has one. Nil
// when there is no array.
func LeafCertificateEntry(raw map[string]interface{}) map[string]interface{} {
	certs, ok := raw["certificates"].([]interface{})
	if !ok || len(certs) == 0 {
		return nil
	}
	var best map[string]interface{}
	bestOrder := int(^uint(0) >> 1)
	for _, c := range certs {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		order, has := metadataInt(m["chain_order"])
		if !has {
			continue
		}
		if order < bestOrder {
			bestOrder = order
			best = m
		}
	}
	if best == nil {
		best, _ = certs[0].(map[string]interface{})
	}
	return best
}

func nonEmptyString(m map[string]interface{}, key string) *string {
	s, ok := m[key].(string)
	if !ok || s == "" {
		return nil
	}
	return &s
}

// metadataInt reads a JSON number (float64 after encoding/json) or a Go int.
func metadataInt(v interface{}) (int, bool) {
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

// metadataTimeLayouts are the formats a certificate validity time arrives in
// inside discovery metadata. Active probes emit RFC 3339; the passive TLS
// assembler of older sensors emitted Go's time.Time.String() format, and those
// sensors are still in the field.
var metadataTimeLayouts = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05 -0700 MST",
}

// ParseMetadataTime parses a certificate validity time from discovery
// metadata in any layout a producer has written. Moved here from
// discovery-processor's external-connections extractor ( WP3) so the one
// reader in inventory-service accepts what that extractor accepted.
func ParseMetadataTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range metadataTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
