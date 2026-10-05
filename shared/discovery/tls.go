// Package discovery holds the pure-Go, CGO-free primitives shared by both
// network-discovery runtimes: the standalone Sensor binary (deployed to
// customer networks) and the in-cluster Platform Sensor
// (cluster-sensor-service). These were previously copy-pasted in both places
// and drifted; they now live here as the single source of truth.
//
// Everything in this package must stay CGO-free (the sensor cross-compiles to
// several OSes, some with CGO disabled) and free of platform-runtime coupling
// (no DB, NATS, or multi-tenant context). libpcap/passive-capture code stays in
// the sensor's own capture/ package and never moves here.
//
// The known-bad-CA fingerprint list in quality.go (surfaced as the
// cert_known_bad_ca quality flag) is a tripwire for a small set of specific,
// individually-verified incidents — not a comprehensive CA distrust database.
// See the doc comment on knownBadCAFingerprints before treating its absence as
// "this CA is fine."
//
// The connect-scan engine (Scanner, in scan.go and its scan_*.go siblings) is
// the shared TCP port-discovery pass: liveness by TCP connect (accepted or
// refused both mean up; silence is "no answer", never "down"), a
// high-concurrency connect scan bounded by a pace profile and a process-wide
// file-descriptor budget, a tarpit guard, and OT-safe handling of industrial
// ports (serialized, connect-only, or skipped). It contacts only the
// netip.Addr values it is given — no name resolution, no derived addresses —
// so callers must pass addresses already cleared by
// shared/identity/dispatchguard. It writes no payload; identification and UDP
// are separate passes. See the comment at the top of scan.go.
package discovery

import (
	"crypto/tls"
	"fmt"
)

// TLSVersionName maps a crypto/tls version constant to a human-readable label.
func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

// CipherSuiteName maps a TLS cipher-suite id to its IANA name. A suite outside
// the table below takes crypto/tls's own name for it when the standard library
// knows one (the ECDHE-ECDSA CBC suites a default Go client still offers, for
// instance); anything else is rendered as "Unknown-0x%04X" so the raw id is
// preserved.
func CipherSuiteName(suite uint16) string {
	if name := cipherSuiteTableName(suite); name != "" {
		return name
	}
	for _, cs := range tls.CipherSuites() {
		if cs.ID == suite {
			return cs.Name
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == suite {
			return cs.Name
		}
	}
	return fmt.Sprintf("Unknown-0x%04X", suite)
}

// cipherSuiteTableName is the explicit table, "" for a suite it does not list.
func cipherSuiteTableName(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case 0x003D: // TLS_RSA_WITH_AES_256_CBC_SHA256
		return "TLS_RSA_WITH_AES_256_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return ""
	}
}
