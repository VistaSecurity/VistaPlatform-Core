package discovery

import "crypto/x509"

// CertChainValidation holds the results of validating a TLS certificate chain.
type CertChainValidation struct {
	ValidationStatus string                 // valid, expired, self_signed, hostname_mismatch, untrusted_ca, revoked, incomplete_chain
	ValidationError  string                 // raw error message for operator visibility
	QualityFlags     map[string]interface{} // SCT, known-bad CA, weak sig, EV, etc.
	OCSPStatus       string                 // good, revoked, unknown
	OCSPDetail       string                 // OCSP response detail
}

// ValidateAndClassifyCertChainPassive performs local chain validation and
// quality classification only (no OCSP HTTP). Use on passive-capture hot paths
// where outbound network I/O must not block the pipeline.
func ValidateAndClassifyCertChainPassive(peerCerts []*x509.Certificate, hostname string) *CertChainValidation {
	return validateAndClassifyCertChain(peerCerts, hostname, nil, true)
}

// ValidateAndClassifyCertChain performs full certificate chain validation:
// verifies against the system trust store, classifies the result, computes
// quality flags, and checks OCSP revocation (staple first, then direct query).
// Pass an empty hostname to skip hostname verification; ocspStaple may be nil.
func ValidateAndClassifyCertChain(peerCerts []*x509.Certificate, hostname string, ocspStaple []byte) *CertChainValidation {
	return validateAndClassifyCertChain(peerCerts, hostname, ocspStaple, false)
}

func validateAndClassifyCertChain(peerCerts []*x509.Certificate, hostname string, ocspStaple []byte, skipOCSPQueries bool) *CertChainValidation {
	if len(peerCerts) == 0 {
		return &CertChainValidation{
			ValidationStatus: "unknown",
			ValidationError:  "no certificates presented",
			QualityFlags:     map[string]interface{}{},
		}
	}

	leaf := peerCerts[0]

	opts := x509.VerifyOptions{}
	if hostname != "" {
		opts.DNSName = hostname
	}
	if len(peerCerts) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, ic := range peerCerts[1:] {
			opts.Intermediates.AddCert(ic)
		}
	}

	_, validationErr := leaf.Verify(opts)
	result := &CertChainValidation{}
	result.ValidationStatus, result.ValidationError = ClassifyValidationError(validationErr)
	result.QualityFlags = ClassifyCertificateFlags(leaf, peerCerts)

	// OCSP revocation check: staple first, then direct query (active paths only).
	if !skipOCSPQueries && len(peerCerts) > 1 {
		issuer := peerCerts[1]
		result.OCSPStatus, result.OCSPDetail = CheckOCSPStaple(ocspStaple, leaf, issuer)
		if result.OCSPStatus == "" {
			result.OCSPStatus, result.OCSPDetail = CheckOCSPRevocation(leaf, issuer)
		}
		if result.OCSPStatus == "revoked" {
			result.ValidationStatus = "revoked"
			result.ValidationError = "certificate has been revoked (OCSP)"
		}
	}

	return result
}
