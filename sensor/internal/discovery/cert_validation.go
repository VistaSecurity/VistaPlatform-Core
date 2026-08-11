// Package discovery: certificate chain validation.
//
// Chain-pool construction, classification, and OCSP checking all live in
// shared/discovery so the sensor and the in-cluster Platform Sensor validate
// identically. This file is a thin type alias + delegation shim kept so
// existing sensor-internal call sites (discovery.ValidateAndClassifyChain*,
// discovery.CertChainValidation) don't need to change.
package discovery

import (
	"crypto/x509"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// CertChainValidation holds the results of validating a TLS certificate chain.
type CertChainValidation = shareddisc.CertChainValidation

// ValidateAndClassifyCertChainPassive performs local chain validation and quality
// classification only (no OCSP HTTP). Use this on passive capture hot paths where
// outbound network I/O must not block the packet pipeline.
func ValidateAndClassifyCertChainPassive(peerCerts []*x509.Certificate, hostname string) *CertChainValidation {
	return shareddisc.ValidateAndClassifyCertChainPassive(peerCerts, hostname)
}

// ValidateAndClassifyCertChain performs full certificate chain validation:
//   - Verifies the chain against the system trust store
//   - Classifies the validation result (valid, expired, self_signed, etc.)
//   - Computes certificate quality flags (SCT, known-bad CA, EV, etc.)
//   - Checks OCSP revocation status (staple first, then direct query)
//
// hostname is used for SNI/DNS identity checks. Pass empty string to skip
// hostname verification (validates chain trust and expiry only).
// ocspStaple is the raw OCSP staple response from the TLS handshake (may be nil).
func ValidateAndClassifyCertChain(peerCerts []*x509.Certificate, hostname string, ocspStaple []byte) *CertChainValidation {
	return shareddisc.ValidateAndClassifyCertChain(peerCerts, hostname, ocspStaple)
}
