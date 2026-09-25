package services

import "github.com/vistasecurity/vistaplatform/shared/discovery"

// copyTLSKeyExchangeSupport copies a TLS handshake's key-exchange SUPPORT
// answers from src to dst: whether the server accepts a classical-only and a
// hybrid-post-quantum-only offer, and which hybrid group it accepted.
//
// Every handshake site writes these through discovery.TLSKeyExchange.ApplyTo.
// The paths that carry an interrogated or scheduled-cloud asset to a
// sensor_discoveries row copy fields by NAME, so a key they do not name is
// dropped — which is how these reached the cloud-interactive path's row but
// not the management probe's or the scheduled cloud path's, and the
// "supports hybrid, negotiated classical" remediation hint ( W1.9) could
// never fire for either.
//
// Only a bool is an answer and only a hybrid group name is a hybrid group:
// anything else is dropped rather than coerced. An absent key stays absent —
// absent means the question was not answered, and writing false for it would
// claim a refusal nobody observed.
func copyTLSKeyExchangeSupport(dst, src map[string]interface{}) {
	if dst == nil || src == nil {
		return
	}
	for _, key := range []string{discovery.MetaTLSSupportsClassicalKex, discovery.MetaTLSSupportsPQCHybridKex} {
		if v, ok := src[key].(bool); ok {
			dst[key] = v
		}
	}
	if hybrid, _ := src[discovery.MetaTLSSupportsPQCHybridKex].(bool); hybrid {
		if g, ok := src[discovery.MetaTLSPQCHybridKexGroup].(string); ok && discovery.IsPQCHybridTLSGroupName(g) {
			dst[discovery.MetaTLSPQCHybridKexGroup] = g
		}
	}
}
