package crypto

import "strings"

// ParseKeyExchangeAlgorithm extracts the key exchange algorithm from a TLS cipher suite name.
// For example "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" returns "ECDHE_RSA".
// Returns "" for TLS 1.3 suites (they use separate key share negotiation).
func ParseKeyExchangeAlgorithm(cipherSuite string) string {
	// TLS 1.3 suites (TLS_AES_* / TLS_CHACHA20_*) — no key exchange in name
	if strings.HasPrefix(cipherSuite, "TLS_AES_") || strings.HasPrefix(cipherSuite, "TLS_CHACHA20_") {
		return ""
	}
	// Standard pattern: TLS_<KEX>_WITH_... or TLS_<KEX>_<AUTH>_WITH_...
	parts := strings.SplitN(cipherSuite, "_WITH_", 2)
	if len(parts) != 2 {
		return ""
	}
	prefix := parts[0] // e.g. "TLS_ECDHE_RSA" or "TLS_RSA"
	// Remove "TLS_" prefix
	prefix = strings.TrimPrefix(prefix, "TLS_")
	// Known key exchange prefixes
	kexMap := map[string]string{
		"ECDHE_RSA":   "ECDHE_RSA",
		"ECDHE_ECDSA": "ECDHE_ECDSA",
		"DHE_RSA":     "DHE_RSA",
		"DHE_DSS":     "DHE_DSS",
		"RSA":         "RSA",
		"DH_RSA":      "DH_RSA",
		"DH_DSS":      "DH_DSS",
		"ECDH_RSA":    "ECDH_RSA",
		"ECDH_ECDSA":  "ECDH_ECDSA",
	}
	if kex, ok := kexMap[prefix]; ok {
		return kex
	}
	// Return the prefix as-is if not in the map
	return prefix
}
