package services

import (
	"strconv"
	"strings"
)

// Provider-API certificate records, projected onto the canonical certificate
// shape.
//
// CLAUDE.md, *Single certificate format*: every discovery path — passive
// capture, active probing, TLS enrichment, and a provider's own API — emits
// certificates as a `"certificates"` JSON array whose entries use the canonical
// field names of shared/certificates.CertificateInfo (`subject_dn`,
// `issuer_dn`, `fingerprint_sha256`, `not_before`, `not_after`,
// `key_algorithm`, `signature_alg`, `certificate_pem`, `chain_order`, …).
// Alternative naming conventions must not be introduced.
//
// They were, here. The ACM record for a CloudFront distribution's viewer
// certificate was written to the discovery row under `acm_certificates`, a key
// no materializer reads, so a real certificate with a real expiry sat in
// `assets.metadata` and two `sensor_discoveries` rows and reached neither
// `certificates` nor anything that scores or warns on it.
//
// What a provider API can and cannot say
//
// ACM's DescribeCertificate returns METADATA ABOUT a certificate, not the
// certificate. There is no PEM, so there is no `fingerprint_sha256` and no
// `is_ca`, and those fields are left ABSENT rather than filled with a
// plausible-looking value: a fabricated fingerprint would be compared, and
// would silently match or fail to match a wire-observed certificate that is
// genuinely the same one. Identity for a PEM-less record therefore falls to
// serial + issuer, which is the composite key the certificate service already
// supports for partial-data certificates.
//
// Nothing here retrieves or stores key material (CLAUDE.md, *Collect posture,
// never key material*): the input is already an allowlist projection of the ACM
// response, and this narrows it further.

// acmKeyAlgorithm splits ACM's KeyAlgorithm enum into the canonical
// family / size / curve triple.
//
// ACM spells the algorithm and its security parameter as one token
// ("RSA_2048", "EC_prime256v1"); the canonical shape keeps them apart, because
// `key_algorithm` is the family x509.PublicKeyAlgorithm.String() produces and
// `key_size` is the bit length. Keeping them apart is also what lets the
// downstream catalogue lookup resolve to the SIZED row: the `algorithms` row
// whose code is a bare `RSA` is "RSA key transport (static)", a TLS
// key-exchange assessment scored 70/weak, while `RSA-2048` is the 40/acceptable
// assessment of an actual 2048-bit key. algorithmCodeForKey in
// inventory-service builds "RSA-<bits>" from exactly this pair and resolves to
// nothing at all when the size is unknown.
//
// Returns zero values for an unrecognised spec — an unknown token is not
// evidence of anything, and guessing a family from a prefix we have never seen
// is how a wrong answer that looks right gets stored.
func acmKeyAlgorithm(spec string) (family string, bits int, curve string) {
	s := strings.ToUpper(strings.TrimSpace(spec))
	switch {
	case s == "":
		return "", 0, ""
	case strings.HasPrefix(s, "RSA_"):
		n, err := strconv.Atoi(strings.TrimPrefix(s, "RSA_"))
		if err != nil || n <= 0 {
			return "RSA", 0, ""
		}
		return "RSA", n, ""
	case strings.HasPrefix(s, "EC_"):
		// ACM names the curve in OpenSSL's vocabulary; the canonical `curve`
		// field and shared/certificates.PublicKeyCurve use the NIST names, and
		// the bit length is the curve's field size.
		switch s {
		case "EC_PRIME256V1":
			return "ECDSA", 256, "P-256"
		case "EC_SECP384R1":
			return "ECDSA", 384, "P-384"
		case "EC_SECP521R1":
			return "ECDSA", 521, "P-521"
		}
		return "ECDSA", 0, ""
	}
	return "", 0, ""
}

// canonicalACMCertificate projects one entry of a crypto config's
// provider-certificate array — the `{"arn": …, "details": {…}}` shape
// getCertificateDetails produces — onto a canonical `certificates` array entry.
//
// Returns nil when the record could not become a certificate row: the
// materializer requires BOTH a subject and an issuer
// (extractCertificateData returns nil without them), so a record missing either
// would be silently dropped one layer further down, and dropping it here is the
// same outcome said out loud.
func canonicalACMCertificate(entry map[string]interface{}) map[string]interface{} {
	if entry == nil {
		return nil
	}
	details, _ := entry["details"].(map[string]interface{})
	if details == nil {
		// An ARN with no DescribeCertificate response behind it. The ARN alone
		// names a certificate but states nothing about it — no subject, no
		// issuer, no dates — so there is nothing to inventory.
		return nil
	}

	str := func(k string) string {
		v, _ := details[k].(string)
		return strings.TrimSpace(v)
	}

	domain := str("domain_name")
	subjectDN := str("subject")
	if subjectDN == "" && domain != "" {
		// ACM's Subject is normally present and already a DN. When it is not,
		// the domain name IS the certificate's common name (ACM issues with
		// CN=DomainName), so rendering it as a one-RDN DN restates a fact
		// rather than inventing one.
		subjectDN = "CN=" + domain
	}
	issuerDN := str("issuer")
	if subjectDN == "" || issuerDN == "" {
		return nil
	}

	cert := map[string]interface{}{
		"subject_dn": subjectDN,
		"issuer_dn":  issuerDN,
		// Provenance. The Certificates lens badges a cloud-managed certificate
		// differently from one observed on the wire because their renewal
		// stories differ: this one is rotated by the provider and the tenant
		// never holds its key.
		"data_source": certDataSourceCloudAPI,
	}
	if domain != "" {
		cert["common_name"] = domain
	}
	if v := str("serial"); v != "" {
		cert["serial_number"] = v
	}
	if v := str("not_before"); v != "" {
		cert["not_before"] = v
	}
	if v := str("not_after"); v != "" {
		cert["not_after"] = v
	}
	if family, bits, curve := acmKeyAlgorithm(str("key_algorithm")); family != "" {
		cert["key_algorithm"] = family
		if bits > 0 {
			cert["key_size"] = bits
		}
		if curve != "" {
			cert["curve"] = curve
		}
	}
	if v := str("signature_algorithm"); v != "" {
		cert["signature_alg"] = v
	}
	if sans := stringSliceFromAny(details["subject_alternative_names"]); len(sans) > 0 {
		cert["subject_alternative_names"] = sans
	}

	// ACM-specific facts that are not certificate fields travel in the same
	// `acm_metadata` sub-map EnrichCertificatesWithACM stamps on a
	// wire-observed certificate, so both paths hand the materializer one shape.
	acm := map[string]interface{}{}
	if arn, _ := entry["arn"].(string); arn != "" {
		acm["arn"] = arn
	} else if arn := str("arn"); arn != "" {
		acm["arn"] = arn
	}
	for _, k := range []string{"status", "type", "renewal_eligibility"} {
		if v := str(k); v != "" {
			acm[k] = v
		}
	}
	if v, ok := details["in_use_by"]; ok && v != nil {
		acm["in_use_by"] = v
	}
	if v, ok := details["domain_validation_options"]; ok && v != nil {
		acm["domain_validation_options"] = v
	}
	if len(acm) > 0 {
		cert["acm_metadata"] = acm
	}
	return cert
}

// certDataSource* are the per-certificate provenance values the ingest path
// stores in `certificates.data_source`. They are per-ENTRY rather than
// per-finding because a single cloud discovery carries both kinds: the ACM
// record states what is configured, and a handshake against the same endpoint
// states what is served.
const (
	certDataSourceCloudAPI = "cloud_api"
	certDataSourceObserved = "discovery"
)

// mergeProviderCertificates folds a crypto config's provider-API certificate
// records into the SAME canonical `certificates` array as the chain observed in
// a handshake, and labels every entry with where it came from.
//
// Deduped by ARN: EnrichCertificatesWithACM has already attached `acm_metadata`
// to any observed certificate it could match to an ACM record by domain, and
// re-appending that record would put the same certificate in the array twice.
//
// Returns nil when there is nothing to record, so the caller can leave the key
// off the metadata entirely rather than writing an empty array.
func mergeProviderCertificates(observed interface{}, providerCerts interface{}) []interface{} {
	merged := make([]interface{}, 0, 4)
	seenARNs := map[string]bool{}

	for _, c := range anySlice(observed) {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		// An observed certificate is bytes off the wire. Say so explicitly:
		// without a per-entry label every certificate in a cloud discovery
		// inherits the finding-level "cloud_api", which would badge the
		// distribution's default *.cloudfront.net certificate — captured in a
		// handshake — as cloud-managed.
		if s, _ := m["data_source"].(string); s == "" {
			m["data_source"] = certDataSourceObserved
		}
		if acm, ok := m["acm_metadata"].(map[string]interface{}); ok {
			if arn, _ := acm["arn"].(string); arn != "" {
				seenARNs[arn] = true
			}
		}
		merged = append(merged, m)
	}

	for _, c := range anySlice(providerCerts) {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		arn, _ := m["arn"].(string)
		if arn != "" && seenARNs[arn] {
			continue
		}
		canonical := canonicalACMCertificate(m)
		if canonical == nil {
			continue
		}
		if arn != "" {
			seenARNs[arn] = true
		}
		merged = append(merged, canonical)
	}

	if len(merged) == 0 {
		return nil
	}
	// chain_order is the entry's position in this array, which is what every
	// reader (canonicalCertPEMs, the materializer's leaf-is-index-0 rule)
	// already assumes.
	for i, c := range merged {
		if m, ok := c.(map[string]interface{}); ok {
			m["chain_order"] = i
		}
	}
	return merged
}

// anySlice normalises the two slice shapes a crypto config's certificate array
// can arrive in: []interface{} after the JSON round-trip extractCryptoConfigs
// performs, or []map[string]interface{} when a caller built it in memory.
func anySlice(v interface{}) []interface{} {
	switch s := v.(type) {
	case nil:
		return nil
	case []interface{}:
		return s
	case []map[string]interface{}:
		out := make([]interface{}, 0, len(s))
		for _, m := range s {
			out = append(out, m)
		}
		return out
	}
	return nil
}

// stringSliceFromAny reads a JSON-ish list of strings.
func stringSliceFromAny(v interface{}) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok && str != "" {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}
