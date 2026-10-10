package processor

import (
	"encoding/json"
	"testing"
)

// A passively captured TLS connection, once the sensor joins the
// server -> client half to the client -> server half, carries its negotiated
// version and suite in the sensor's TOP-LEVEL Version / CipherSuite — which
// sensor-manager's StoreDiscoveries promotes onto the envelope — and its
// certificate chain inside raw_metadata. These pin that shape end to end
// through the import (routeWriterViewOf), and that a ClientHello-only discovery (the
// only shape a sensor that never saw the ServerHello produces) yields no
// version or suite rather than an empty one.

func passiveEnvelope(version, cipher string, raw map[string]interface{}) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"source_ip":        "192.0.2.173",
		"version":          version,
		"cipher_suite":     cipher,
		"key_size":         0,
		"discovery_method": "passive",
		"raw_metadata":     raw,
		"service_hints":    nil,
	})
	return b
}

func TestExtractCryptoDetails_PassiveServerHelloEnvelope(t *testing.T) {
	d := routeWriterViewOf(t, passiveEnvelope("TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", map[string]interface{}{
		"session_id":             "s1",
		"reassembled":            true,
		"handshake_types":        []interface{}{"ClientHello", "ServerHello", "Certificate"},
		"sni":                    "example.com",
		"key_exchange_algorithm": "ECDHE",
		"cert_validation_status": "untrusted",
		"certificates": []interface{}{map[string]interface{}{
			"chain_order":        0,
			"subject_dn":         "CN=example.com",
			"issuer_dn":          "CN=example.com",
			"fingerprint_sha256": "leaf",
			"key_algorithm":      "ECDSA",
			"key_size":           256,
			"signature_alg":      "ECDSA-SHA256",
		}},
	}))
	if d == nil {
		t.Fatal("nil details")
	}
	assertStrPtr(t, "protocol version", d.ProtocolVersion, "TLS 1.2")
	assertStrPtr(t, "cipher suite", d.CipherSuite, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	assertStrPtr(t, "key exchange", d.KeyExchangeAlgorithm, "ECDHE")
	assertStrPtr(t, "cert subject", d.CertSubject, "CN=example.com")
	assertStrPtr(t, "cert validation", d.CertValidationStatus, "untrusted")
}

func TestExtractCryptoDetails_PassiveClientHelloOnlyEnvelopeInventsNothing(t *testing.T) {
	d := routeWriterViewOf(t, passiveEnvelope("", "", map[string]interface{}{
		"handshake_types":            []interface{}{"ClientHello"},
		"sni":                        "ws.example.com",
		"client_max_offered_version": "TLS 1.3",
		"supported_ciphers":          []interface{}{"TLS_AES_128_GCM_SHA256"},
	}))
	if d == nil {
		t.Fatal("nil details")
	}
	if d.ProtocolVersion != nil {
		t.Errorf("protocol version = %q; the client's offer is not a negotiated version", *d.ProtocolVersion)
	}
	if d.CipherSuite != nil {
		t.Errorf("cipher suite = %q; supported_ciphers is an offer, not a selection", *d.CipherSuite)
	}
	if d.CertSubject != nil {
		t.Errorf("cert subject = %q from a ClientHello", *d.CertSubject)
	}
}
