package discovery

import (
	"crypto/x509"
	"net"
	"strings"
)

// VerifyDNSName returns a host string suitable for x509.VerifyOptions.DNSName
// when the dial target is host (which is frequently a raw IP: sweep targets,
// scan job targets, and passive flows all identify endpoints by address).
//
// Passing a raw IP straight through as DNSName is wrong: Go treats an
// IP-shaped DNSName as an IP-SAN check, so every endpoint whose certificate
// carries only DNS SANs — i.e. almost every valid one — classifies as
// hostname_mismatch. Empty return means the caller should omit DNSName
// entirely and verify only chain/trust/expiry.
func VerifyDNSName(leaf *x509.Certificate, host string) string {
	if leaf == nil {
		return ""
	}
	if peerIP := net.ParseIP(host); peerIP != nil {
		for _, ip := range leaf.IPAddresses {
			if ip.Equal(peerIP) {
				return host
			}
		}
	}
	// Prefer a concrete SAN; wildcard-only certs cannot be matched to an IP
	// without a reverse lookup we deliberately do not perform.
	for _, name := range leaf.DNSNames {
		if name != "" && !strings.HasPrefix(name, "*.") {
			return name
		}
	}
	for _, name := range leaf.DNSNames {
		if name != "" {
			return name
		}
	}
	if cn := leaf.Subject.CommonName; cn != "" && strings.Contains(cn, ".") {
		return cn
	}
	return ""
}

// ResolveVerifyHost picks the hostname to verify a chain against. A real
// hostname is used as-is (so the identity check is genuine); an empty or
// IP-literal identity falls back to VerifyDNSName against the leaf.
func ResolveVerifyHost(identity string, peerCerts []*x509.Certificate) string {
	identity = strings.TrimSpace(identity)
	if identity != "" && net.ParseIP(identity) == nil {
		return identity
	}
	if len(peerCerts) == 0 {
		return ""
	}
	return VerifyDNSName(peerCerts[0], identity)
}
