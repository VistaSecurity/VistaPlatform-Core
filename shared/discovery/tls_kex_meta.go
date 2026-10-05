package discovery

import "crypto/tls"

// TLSKeyExchangeFromMetadata is the inverse of TLSKeyExchange.ApplyTo: it
// reads the measurement back out of a TLS ProbeResult's metadata, for a caller
// whose own result type carries the struct (device-interrogation-service's
// cloud handshake). A key ApplyTo did not write comes back as the zero value —
// exactly what ApplyTo omitted it for — so ApplyTo(FromMetadata(m)) writes the
// same keys and values m held.
func TLSKeyExchangeFromMetadata(meta map[string]interface{}) TLSKeyExchange {
	var k TLSKeyExchange
	if raw, ok := meta[MetaKeyExchangeGroupRaw].(uint16); ok {
		k.GroupID = tls.CurveID(raw)
	}
	k.Group, _ = meta[MetaKeyExchangeAlgorithm].(string)
	if b, ok := meta[MetaTLSSupportsClassicalKex].(bool); ok {
		k.SupportsClassical = boolPtr(b)
	}
	if b, ok := meta[MetaTLSSupportsPQCHybridKex].(bool); ok {
		k.SupportsPQCHybrid = boolPtr(b)
	}
	k.PQCHybridGroup, _ = meta[MetaTLSPQCHybridKexGroup].(string)
	// ApplyTo derives the exchange size from a known group, and writes KeyBits
	// only for an exchange with no group id (a custom finite-field prime), so
	// only that case reads it back.
	if bits, ok := meta[MetaKeyExchangeKeySize].(int); ok && k.GroupID == 0 {
		k.KeyBits = bits
	}
	return k
}
