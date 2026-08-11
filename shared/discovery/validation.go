package discovery

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"
)

// ClassifyValidationError maps an x509 verification error to a short status
// label, returning the raw error string for operator visibility. A nil error
// classifies as ("valid", "").
func ClassifyValidationError(err error) (status, detail string) {
	if err == nil {
		return "valid", ""
	}

	msg := err.Error()

	// Self-signed certs are commonly surfaced as UnknownAuthorityError
	// ("certificate signed by unknown authority"). Detect this before the
	// generic unknown-authority classification.
	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) && IsSelfSigned(unknownAuthorityErr.Cert) {
		return "self_signed", msg
	}

	switch {
	case strings.Contains(msg, "certificate has expired") || strings.Contains(msg, "certificate is not yet valid"):
		return "expired", msg
	case strings.Contains(msg, "certificate is valid for") || strings.Contains(msg, "doesn't contain any IP SANs"):
		return "hostname_mismatch", msg
	case strings.Contains(msg, "self-signed"):
		return "self_signed", msg
	case strings.Contains(msg, "certificate chain is incomplete"):
		// Incomplete chain: server didn't send required intermediates.
		return "incomplete_chain", msg
	case strings.Contains(msg, "certificate signed by unknown authority") || strings.Contains(msg, "unknown authority"):
		return "untrusted_ca", msg
	default:
		return "untrusted_ca", msg
	}
}

// IsSelfSigned reports whether a certificate is self-signed (subject == issuer
// and it verifies its own signature).
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}
