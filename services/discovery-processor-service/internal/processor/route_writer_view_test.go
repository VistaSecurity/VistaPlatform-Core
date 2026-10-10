package processor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
)

// routeWriterView is what inventory-service's one external-connections writer
// (routeToExternalConnection) reads off a finding this service imported.
//
// discovery-processor wrote external_connections itself until WP3, from
// its own extractor (extractCryptoDetails), and the tests in
// external_crypto*_test.go pinned what that extractor saw in every metadata
// shape a producer writes. The extractor is gone; every row is imported, and
// what reaches the writer is now the finding importFinding builds. These
// tests keep their assertions and read them from that finding instead:
//
//   - protocol version, cipher suite, key exchange: the finding's own fields
//     (an empty string is no measurement, as the writer's nonEmptyPtr reads it),
//     the exchange falling back to raw_data's key_exchange_algorithm label as
//     the writer's does;
//   - supported versions and the measured exchange-key size: the raw_data keys
//     the writer reads (externalDiscoveryEvidence);
//   - the certificate: the leaf the shared reader picks from raw_data's
//     "certificates" array, and its validation verdict through the shared
//     quality reader — both the writer's own code.
type routeWriterView struct {
	ProtocolVersion, CipherSuite, KeyExchangeAlgorithm *string
	KeySize                                            *int
	SupportedTLSVersions                               []string

	CertSubject, CertIssuer, CertFingerprintSHA256, CertPublicKeyAlgorithm *string
	CertSignatureAlgorithm, CertValidationStatus, CertPEM                  *string
	CertPublicKeySize                                                      *int
	CertSAN                                                                []string
	CertNotBefore, CertNotAfter                                            *time.Time
}

func routeWriterViewOf(t *testing.T, metadata []byte) *routeWriterView {
	t.Helper()
	f, err := (&BatchProcessor{}).importFinding(&models.SensorDiscovery{
		ID: uuid.New(), SensorID: uuid.New(), DestIP: "203.0.113.9", Port: 443, Protocol: "TLS", Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("importFinding: %v", err)
	}
	// What crosses the wire, not the in-memory map.
	b, err := json.Marshal(f.RawData)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	v := &routeWriterView{
		ProtocolVersion:      routeNonEmpty(f.ProtocolVersion),
		CipherSuite:          routeNonEmpty(f.CipherSuite),
		KeyExchangeAlgorithm: routeWriterKEX(f.KeyExchangeAlgorithm, raw),
		SupportedTLSVersions: routeStrings(raw["tls_versions"]),
		CertValidationStatus: sharedcerts.CertificateQualityFromMetadata(raw).ValidationStatus,
	}
	if n, ok := raw["key_exchange_key_size"].(float64); ok && n > 0 {
		size := int(n)
		v.KeySize = &size
	}
	if leaf := sharedcerts.LeafCertificateEntry(raw); leaf != nil {
		str := func(k string) *string { s, _ := leaf[k].(string); return routeNonEmpty(&s) }
		v.CertSubject, v.CertIssuer = str("subject_dn"), str("issuer_dn")
		v.CertFingerprintSHA256, v.CertPublicKeyAlgorithm = str("fingerprint_sha256"), str("key_algorithm")
		v.CertSignatureAlgorithm, v.CertPEM = str("signature_alg"), str("certificate_pem")
		if n, ok := leaf["key_size"].(float64); ok && n > 0 {
			size := int(n)
			v.CertPublicKeySize = &size
		}
		v.CertSAN = routeStrings(leaf["subject_alternative_names"])
		for key, dst := range map[string]**time.Time{"not_before": &v.CertNotBefore, "not_after": &v.CertNotAfter} {
			if s, _ := leaf[key].(string); s != "" {
				if ts, ok := sharedcerts.ParseMetadataTime(s); ok {
					*dst = &ts
				}
			}
		}
	}
	return v
}

// routeWriterKEX is the writer's key exchange: the finding's, else the
// raw_data label.
func routeWriterKEX(finding *string, raw map[string]interface{}) *string {
	if v := routeNonEmpty(finding); v != nil {
		return v
	}
	label, _ := raw["key_exchange_algorithm"].(string)
	return routeNonEmpty(&label)
}

func routeNonEmpty(p *string) *string {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	return p
}

func routeStrings(v interface{}) []string {
	list, _ := v.([]interface{})
	var out []string
	for _, item := range list {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
