package services

import (
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	cryptostrength "github.com/vistasecurity/vistaplatform/shared/strength"
)

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func nullableStrength(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func observationValue[T any](incoming, prior *T) *T {
	if incoming == nil {
		return prior
	}
	return incoming
}
func observationString(incoming, prior *string) *string {
	if incoming == nil || strings.TrimSpace(*incoming) == "" {
		return prior
	}
	return incoming
}

// Merge actual facts before assessment. Missing/empty fields are an incomplete
// observation, never affirmative evidence that a previous weakness disappeared.
func mergeExternalObservation(in, prior models.ExternalConnectionUpsert) models.ExternalConnectionUpsert {
	in.ProtocolVersion = observationString(in.ProtocolVersion, prior.ProtocolVersion)
	in.CipherSuite = observationString(in.CipherSuite, prior.CipherSuite)
	if prior.KeyExchangeAlgorithm != nil && in.KeyExchangeAlgorithm != nil && !strings.EqualFold(*in.KeyExchangeAlgorithm, *prior.KeyExchangeAlgorithm) && (in.KeySize == nil || *in.KeySize <= 0) {
		in.KeyExchangeAlgorithm = prior.KeyExchangeAlgorithm
	}
	in.KeyExchangeAlgorithm = observationString(in.KeyExchangeAlgorithm, prior.KeyExchangeAlgorithm)
	if in.KeySize == nil || *in.KeySize <= 0 {
		in.KeySize = prior.KeySize
	}
	if len(in.SupportedTLSVersions) == 0 {
		in.SupportedTLSVersions = prior.SupportedTLSVersions
	}
	if prior.CertPublicKeyAlgorithm != nil && in.CertPublicKeyAlgorithm != nil && !strings.EqualFold(*in.CertPublicKeyAlgorithm, *prior.CertPublicKeyAlgorithm) && (in.CertPublicKeySize == nil || *in.CertPublicKeySize <= 0) {
		in.CertPublicKeyAlgorithm = prior.CertPublicKeyAlgorithm
	}
	in.CertPublicKeyAlgorithm = observationString(in.CertPublicKeyAlgorithm, prior.CertPublicKeyAlgorithm)
	if in.CertPublicKeySize == nil || *in.CertPublicKeySize <= 0 {
		in.CertPublicKeySize = prior.CertPublicKeySize
	}
	in.CertSignatureAlgorithm = observationString(in.CertSignatureAlgorithm, prior.CertSignatureAlgorithm)
	in.CertNotBefore = observationValue(in.CertNotBefore, prior.CertNotBefore)
	in.CertNotAfter = observationValue(in.CertNotAfter, prior.CertNotAfter)
	in.CertValidationStatus = observationString(in.CertValidationStatus, prior.CertValidationStatus)
	in.CertFingerprintSHA256 = observationString(in.CertFingerprintSHA256, prior.CertFingerprintSHA256)
	in.CertSubject = observationString(in.CertSubject, prior.CertSubject)
	in.CertIssuer = observationString(in.CertIssuer, prior.CertIssuer)
	in.CertPEM = observationString(in.CertPEM, prior.CertPEM)
	in.CertSCTSource = observationString(in.CertSCTSource, prior.CertSCTSource)
	if len(in.CertSAN) == 0 {
		in.CertSAN = prior.CertSAN
	}
	return in
}

func externalProtocolCode(protocol, version string) string {
	if code := cryptoparse.NormalizeProtocolVersion(version); code != "" {
		return code
	}
	v := strings.TrimSpace(version)
	if len(v) > 0 && v[0] >= '0' && v[0] <= '9' {
		v = protocol + v
	}
	return cryptoparse.NormalizeComponentCode(v)
}

// Resolving an opaque historical weakness requires a fresh observation of every
// crypto dimension: negotiated/offered protocols, suite, exchange key and leaf
// public key/signature. Merged old facts do not satisfy this predicate.
func completeExternalObservation(in models.ExternalConnectionUpsert) bool {
	for _, v := range []*string{in.ProtocolVersion, in.CipherSuite, in.KeyExchangeAlgorithm, in.CertPublicKeyAlgorithm, in.CertSignatureAlgorithm} {
		if v == nil || strings.TrimSpace(*v) == "" {
			return false
		}
	}
	for _, version := range in.SupportedTLSVersions {
		if strings.TrimSpace(version) == "" {
			return false
		}
	}
	return in.KeySize != nil && *in.KeySize > 0 && in.CertPublicKeySize != nil && *in.CertPublicKeySize > 0 && len(in.SupportedTLSVersions) > 0
}

// Strength sorting uses the same ordering as assessment; null stays separate.
func externalStrengthSortSQL() string {
	var parts []string
	for _, d := range cryptostrength.Definitions() {
		parts = append(parts, fmt.Sprintf("WHEN '%s' THEN %d", d.Value, d.Rank))
	}
	return "CASE crypto_strength " + strings.Join(parts, " ") + " ELSE NULL END"
}

const externalReassessmentReason = "Previous weak assessment requires fresh cryptographic evidence"

// A reconstructed weak fact cannot prove that every historical reason was
// reconstructed. Keep that evidence gap even alongside a known weak judgment.
func preserveExternalAssessment(rating string, reasons []string, priorStrength *string, priorReasons []string, freshComplete bool) (string, []string) {
	gap := priorStrength == nil && len(priorReasons) > 0
	for _, reason := range priorReasons {
		gap = gap || reason == externalReassessmentReason || reason == externalKeySizeRoleReason
	}
	if gap && !freshComplete {
		reasons = appendUnique(reasons, priorReasons...)
		if !containsExternalReason(priorReasons, externalKeySizeRoleReason) {
			reasons = appendUnique(reasons, externalReassessmentReason)
		}
		if rating != "weak" {
			rating = ""
		}
	} else if rating == "" && stringValue(priorStrength) == "weak" {
		rating = "weak"
		reasons = appendUnique(reasons, priorReasons...)
	}
	return rating, reasons
}

const externalKeySizeRoleReason = "Historical key_size may be cipher bits; exchange-size verification required"

func containsExternalReason(reasons []string, value string) bool {
	for _, reason := range reasons {
		if reason == value {
			return true
		}
	}
	return false
}

// The former sensor adapter copied cipher bits into key_size. The migration
// marks only old values matching that fallback. A changed suite cannot resolve
// the older size role; a fresh exchange measurement can.
// Retain the original stored number, but do not judge it as an exchange size.
func prepareExternalAssessment(in models.ExternalConnectionUpsert, priorReasons []string, verified bool) (models.ExternalConnectionUpsert, []string) {
	if !containsExternalReason(priorReasons, externalKeySizeRoleReason) {
		return in, priorReasons
	}
	if !verified {
		in.KeySize = nil
		return in, priorReasons
	}
	var reasons []string
	for _, reason := range priorReasons {
		if reason != externalKeySizeRoleReason {
			reasons = append(reasons, reason)
		}
	}
	return in, reasons
}

// Discovery metadata's generic key_size is deliberately excluded: passive and
// active producers use it for several roles. The external write DTO key_size
// means measured exchange bits only.
func externalDiscoveryEvidence(raw map[string]interface{}) (*int, []string) {
	var size *int
	var versions []string
	nested, _ := raw["raw_metadata"].(map[string]interface{})
	for _, facts := range []map[string]interface{}{raw, nested} {
		if size == nil {
			n := 0
			switch value := facts["key_exchange_key_size"].(type) {
			case int:
				n = value
			case float64:
				if value == float64(int(value)) {
					n = int(value)
				}
			}
			if n > 0 {
				size = &n
			}
		}
		if len(versions) == 0 {
			switch values := facts["tls_versions"].(type) {
			case []string:
				for _, v := range values {
					if strings.TrimSpace(v) != "" {
						versions = append(versions, v)
					}
				}
			case []interface{}:
				for _, v := range values {
					if text, ok := v.(string); ok && strings.TrimSpace(text) != "" {
						versions = append(versions, text)
					}
				}
			}
		}
	}
	return size, versions
}

// appendUnique appends each item not already present in slice, preserving
// order.
func appendUnique(slice []string, items ...string) []string {
	seen := make(map[string]bool)
	for _, item := range slice {
		seen[item] = true
	}
	for _, item := range items {
		if !seen[item] {
			slice = append(slice, item)
			seen[item] = true
		}
	}
	return slice
}
