package converter

// measuredTLSGroup returns the key-exchange group a live TLS handshake
// negotiated, or nil.
//
// Every TLS handshake site (shared/discovery.TLSKeyExchange.ApplyTo) writes the
// group's catalogue code under key_exchange_algorithm with its wire id beside
// it under key_exchange_group_raw. The standalone sensor's rows carry both
// inside the raw_metadata envelope sensor-manager builds; the cloud
// collectors' rows carry them at the top level. Both are read.
//
// The wire id is what makes the value a measurement. Passive capture writes a
// cipher-suite LABEL under the same key ("ECDHE_RSA", parsed from the suite
// name) with no id beside it, and promoting that label here would suppress the
// ingest's own cipher-suite parse (crypto_queries.go links the suite's key
// exchange only when the finding names none) while resolving to no catalogue
// row — a configuration that had a key exchange would lose it.
func measuredTLSGroup(metadata map[string]interface{}) *string {
	for _, m := range []map[string]interface{}{metadata, nestedRawMetadata(metadata)} {
		if m == nil {
			continue
		}
		if _, measured := m["key_exchange_group_raw"]; !measured {
			continue
		}
		if g, ok := m["key_exchange_algorithm"].(string); ok && g != "" {
			return &g
		}
	}
	return nil
}

func nestedRawMetadata(metadata map[string]interface{}) map[string]interface{} {
	nested, _ := metadata["raw_metadata"].(map[string]interface{})
	return nested
}
