package converter

import "strings"

// isInterrogationRow reports whether a sensor_discoveries row was written by
// device-interrogation-service (buildSensorDiscoveryMetadata), whose marker is
// discovery_method "device_interrogation" at the top level.
func isInterrogationRow(metadata map[string]interface{}) bool {
	method, _ := metadata["discovery_method"].(string)
	return method == "device_interrogation"
}

// interrogatedKeyExchange returns the key exchange device-interrogation-service
// stated for an interrogated asset, or nil.
//
// buildSensorDiscoveryMetadata writes it as `key_exchange_algorithm` for every
// interrogated asset — WireGuard's Curve25519, an IPsec tunnel's IKE group as a
// catalogue code, an F5 profile's key exchange. This converter never read that
// key, so every interrogation finding reached inventory with no key exchange,
// and a VPN linking only AES and SHA-2 was classified as quantum-safe.
//
// Only this scalar counts for an interrogation row. The row's kex_algorithms
// is an OFFER list (every DH group the tunnel can be steered onto, PFS groups
// included), and when the scalar is absent the key exchange is unknown — the
// preferred IKE group has no catalogue row, or only a PFS group is known. The
// offer list's head must not stand in for it: that promoted a second-choice
// group to "the key exchange", and read beside a stale key_size it scored
// Critical. Inventory links the offers itself, as offers.
//
// Call it ONLY for a row isInterrogationRow accepts; the converter's one gate
// is at the call site (a second, redundant check here could not be shown to
// matter). The gate is what keeps this from being a blanket read of the key:
// passive capture writes a cipher-suite LABEL under the same name
// ("ECDHE_RSA", parsed from the suite), which resolves to no catalogue row.
// Promoting it would suppress the ingest's own cipher-suite parse
// (crypto_queries.go links the suite's key exchange only when the finding names
// none), and a TLS configuration that had a key exchange would lose it. A TLS
// handshake's measured group is read separately, where its wire id marks it as
// a measurement.
//
// Top level only: that is where the interrogation writer puts it.
func interrogatedKeyExchange(metadata map[string]interface{}) *string {
	kex, ok := metadata["key_exchange_algorithm"].(string)
	if !ok || strings.TrimSpace(kex) == "" {
		return nil
	}
	return &kex
}
