package discovery

import (
	"crypto/x509"
	"encoding/pem"
)

// ClassifyCertChainFromPEMs parses an ordered (leaf-first) set of PEM-encoded
// certificates and returns the same chain-validation result the active TLS
// prober produces: validation status, quality flags (SCT, EV, known-bad CA,
// weak signature/key, incomplete chain, large SAN count) and — when withOCSP is
// set and an issuer is present — OCSP revocation status.
//
// The interrogation paths (cloud-API discovery and device interrogation) already
// hold certificates as PEM rather than live *x509.Certificate objects, but must
// emit byte-for-byte identical quality flags to the passive/active sensor — see
// ClassifyCertificateFlags. This adapter is the single point that keeps the
// interrogation producers in sync with the sensor, so the flags do not have to
// be recomputed (or forgotten) at each call site.
//
// Pass certs leaf-first (chain_order ascending). PEM blocks that are not
// certificates, or that fail to parse, are skipped. Returns nil when no
// certificate parses, so callers can simply skip merging on a nil result.
func ClassifyCertChainFromPEMs(pems []string, withOCSP bool) *CertChainValidation {
	var certs []*x509.Certificate
	for _, p := range pems {
		rest := []byte(p)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		return nil
	}

	// Empty hostname skips hostname verification — interrogation does not always
	// carry a reliable SNI hostname, and a spurious hostname_mismatch would be
	// worse than no opinion. OCSP is gated by the caller because some paths run
	// inside a synchronous request and cannot afford the responder round-trip.
	if withOCSP {
		return ValidateAndClassifyCertChain(certs, "", nil)
	}
	return ValidateAndClassifyCertChainPassive(certs, "")
}
