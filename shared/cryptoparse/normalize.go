package cryptoparse

import "strings"

// cipherModeSuffixes are operating mode tokens that may be appended to cipher
// algorithm names by upstream producers (e.g. "AES-256-GCM"). The algorithms
// table stores the base cipher without mode (e.g. "AES256"), so these are
// stripped before a catalogue lookup. This is purely syntactic/structural
// knowledge — no strength values are encoded here.
var cipherModeSuffixes = []string{
	"-EDE-CBC",  // 3DES-EDE-CBC → 3DES
	"-POLY1305", // CHACHA20-POLY1305 → CHACHA20 → ChaCha20
	"-GCM",      // AES-256-GCM → AES-256
	"-CBC",      // AES-256-CBC → AES-256
	"-CTR",      // AES-256-CTR → AES-256
	"-128",      // RC4-128 → RC4
}

// NormalizeComponentCode strips operating-mode suffixes from a cipher component
// name, then removes formatting hyphens and spaces so the result matches the
// `algorithms.code` format (e.g. "AES-256-GCM" → "AES256",
// "CHACHA20-POLY1305" → "CHACHA20", "TLS 1.2" → "TLS1.2"). For values that are
// already clean codes (key exchange, hash) this is a no-op.
//
// Space removal is what makes SPACED PROTOCOL VERSIONS resolve. The sensor's
// TLS enricher and the F5 interrogator both emit "TLS 1.2" / "TLS 1.0" (a
// human-readable spelling), while the catalogue codes them "TLS1.2" / "TLS1.0".
// Without this the exact lookup missed, the substring fallback found nothing
// (no code CONTAINS "tls 1.2"), and the protocol-version component was left
// unlinked — so the RFC 8996 deprecation ladder (TLS1.0 risk 75, TLS1.1 risk
// 70) never fired for any sensor-discovered implementation.
func NormalizeComponentCode(parsed string) string {
	upper := strings.ToUpper(parsed)
	for _, suffix := range cipherModeSuffixes {
		if strings.HasSuffix(upper, suffix) {
			parsed = parsed[:len(parsed)-len(suffix)]
			break
		}
	}
	parsed = strings.ReplaceAll(parsed, "-", "")
	return strings.ReplaceAll(parsed, " ", "")
}

// protocolVersionAliases maps spellings producers actually emit to the
// catalogue code for the same protocol, where removing separators is not
// enough to bridge the two.
//
// The SSL entries are the ones that need it: pcap-processor renders SSLv3 as
// "SSL 3.0", which NormalizeComponentCode reduces to "SSL3.0" — still not the
// catalogue's "SSLv3". Keys are compared after upper-casing and separator
// removal, so one entry covers "SSL 3.0", "SSL-3.0" and "ssl3.0".
var protocolVersionAliases = map[string]string{
	"SSL2.0": "SSLv2",
	"SSL2":   "SSLv2",
	"SSLV2":  "SSLv2",
	"SSL3.0": "SSLv3",
	"SSL3":   "SSLv3",
	"SSLV3":  "SSLv3",
}

// NormalizeProtocolVersion maps an observed protocol-version string onto the
// catalogue code for that protocol, or returns "" when it has no alias. It is a
// second chance after NormalizeComponentCode, not a replacement for it.
func NormalizeProtocolVersion(observed string) string {
	key := strings.ToUpper(NormalizeComponentCode(strings.TrimSpace(observed)))
	return protocolVersionAliases[key]
}

// X509SignatureCatalogueCode maps the name Go's crypto/x509 gives a certificate
// signature algorithm onto the catalogue's spelling of the same algorithm, or
// returns the input unchanged when the two already agree or it is not one of
// those names.
//
// Every certificate producer records x509.SignatureAlgorithm.String(), which
// puts the hash FIRST for RSA ("SHA256-RSA", "SHA256-RSAPSS") while the
// catalogue codes the same algorithms "RSA-SHA256" and "RSA-PSS". The ECDSA
// and EdDSA names already match. Without this the lookup missed for every
// RSA-signed certificate and the signature was reported as unassessed.
//
// It is a spelling bridge only: whether the algorithm is weak is still the
// catalogue row's answer (RSA-SHA1 and RSA-MD5 are rows too).
func X509SignatureCatalogueCode(name string) string {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if hash, ok := strings.CutSuffix(upper, "-RSAPSS"); ok && hash != "" {
		return "RSA-PSS"
	}
	if hash, ok := strings.CutSuffix(upper, "-RSA"); ok && hash != "" && !strings.Contains(hash, "-") {
		return "RSA-" + hash
	}
	return name
}
