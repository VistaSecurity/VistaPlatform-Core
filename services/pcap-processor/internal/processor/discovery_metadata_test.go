package processor

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/tlsparse"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// TestDiscoveryFromTLSSession pins the mapping from a reassembled TLS session to
// the discovery row. The server endpoint — not whichever side happened to send
// the observed record — is what becomes the inventory asset.
func TestDiscoveryFromTLSSession(t *testing.T) {
	first := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := &tlsparse.Session{
		ServerIP:            "10.0.0.1",
		ServerPort:          443,
		ClientIP:            "10.0.0.9",
		ClientPort:          51514,
		NegotiatedVersion:   "TLS 1.3",
		CipherSuite:         "TLS_AES_128_GCM_SHA256",
		ClientLegacyVersion: "TLS 1.2",
		ClientMaxOffered:    "TLS 1.3",
		OfferedCipherSuites: []string{"TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		SNI:                 "api.example.com",
		RecordVersion:       "TLS 1.0",
		HandshakeTypes:      []string{"ClientHello", "ServerHello", "Certificate"},
		FirstSeen:           first,
	}

	d := discoveryFromTLSSession(s)

	if d.DestIP != "10.0.0.1" || d.DestPort != 443 {
		t.Errorf("dest = %s:%d, want the server endpoint 10.0.0.1:443", d.DestIP, d.DestPort)
	}
	if d.SourceIP != "10.0.0.9" || d.SourcePort != 51514 {
		t.Errorf("source = %s:%d, want the client endpoint", d.SourceIP, d.SourcePort)
	}
	if d.ProtocolVersion != "TLS 1.3" {
		t.Errorf("protocol version = %q", d.ProtocolVersion)
	}
	if d.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("cipher suite = %q", d.CipherSuite)
	}
	if !d.Timestamp.Equal(first) {
		t.Errorf("timestamp = %v, want %v", d.Timestamp, first)
	}
	if d.RawMetadata["client_max_offered_version"] != "TLS 1.3" {
		t.Errorf("client offer not preserved as metadata: %v", d.RawMetadata)
	}
	if d.RawMetadata["handshake_types"] != "ClientHello,ServerHello,Certificate" {
		t.Errorf("handshake_types = %q", d.RawMetadata["handshake_types"])
	}
}

func TestTLSSessionDedupeKeyPreservesDistinctEndpointEvidence(t *testing.T) {
	base := &tlsparse.Session{
		ServerIP:          "10.0.0.1",
		ServerPort:        443,
		ClientIP:          "10.0.0.9",
		ClientPort:        51514,
		NegotiatedVersion: "TLS 1.3",
		CipherSuite:       "TLS_AES_128_GCM_SHA256",
		SNI:               "api.example.com",
		Certificates: []certificates.CertificateInfo{{
			FingerprintSHA256: "leaf-a",
		}},
	}

	sameEvidenceDifferentClient := *base
	sameEvidenceDifferentClient.ClientIP = "10.0.0.10"
	sameEvidenceDifferentClient.ClientPort = 51515
	if got, want := tlsSessionDedupeKey(&sameEvidenceDifferentClient), tlsSessionDedupeKey(base); got != want {
		t.Fatalf("same endpoint evidence from another client should dedup: got %q want %q", got, want)
	}

	for name, mutate := range map[string]func(*tlsparse.Session){
		"sni": func(s *tlsparse.Session) {
			s.SNI = "admin.example.com"
		},
		"leaf certificate": func(s *tlsparse.Session) {
			s.Certificates[0].FingerprintSHA256 = "leaf-b"
		},
		"negotiated version": func(s *tlsparse.Session) {
			s.NegotiatedVersion = "TLS 1.2"
		},
		"cipher suite": func(s *tlsparse.Session) {
			s.CipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := *base
			changed.Certificates = append([]certificates.CertificateInfo(nil), base.Certificates...)
			mutate(&changed)
			if got, wantNot := tlsSessionDedupeKey(&changed), tlsSessionDedupeKey(base); got == wantNot {
				t.Fatalf("dedupe key collapsed distinct %s evidence: %q", name, got)
			}
		})
	}
}

// TestBuildDiscoveryMetadataShape pins the metadata keys that
// discovery-processor-service reads (converter/sensor_converter.go reads
// "version" and "cipher_suite"; processor/external_crypto.go reads the
// "certificates" array and its canonical leaf field names). Changing these key
// names silently empties PCAP-derived inventory, which is exactly the class of
// defect this rewrite fixes.
func TestBuildDiscoveryMetadataShape(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	d := CryptoDiscovery{
		SourceIP:        "10.0.0.9",
		SourcePort:      51514,
		DestIP:          "10.0.0.1",
		DestPort:        443,
		Protocol:        "TLS",
		ProtocolVersion: "TLS 1.3",
		CipherSuite:     "TLS_AES_128_GCM_SHA256",
		CipherSuites:    []string{"TLS_AES_128_GCM_SHA256"},
		SNI:             "api.example.com",
		Certificates: []certificates.CertificateInfo{{
			SubjectDN:               "CN=api.example.com",
			IssuerDN:                "CN=Example CA",
			SerialNumber:            "4242",
			NotBefore:               notBefore,
			NotAfter:                notAfter,
			KeyAlgorithm:            "ECDSA",
			SignatureAlg:            "ECDSA-SHA256",
			CertificatePEM:          "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			FingerprintSHA256:       "ab12",
			SubjectAlternativeNames: []string{"api.example.com"},
			KeySize:                 256,
			ChainOrder:              0,
		}},
		DiscoveryMethod: "pcap_upload",
		DiscoveryType:   "tls_session",
		RawMetadata:     map[string]string{"reassembled": "true"},
	}

	// Round-trip through JSON exactly as the sensor_discoveries.metadata JSONB
	// column does, so the assertions below see what the consumer sees.
	raw, err := json.Marshal(buildDiscoveryMetadata(d))
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	var meta map[string]interface{}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}

	if meta["version"] != "TLS 1.3" {
		t.Errorf(`metadata["version"] = %v, want "TLS 1.3"`, meta["version"])
	}
	if meta["cipher_suite"] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf(`metadata["cipher_suite"] = %v`, meta["cipher_suite"])
	}
	if meta["sni"] != "api.example.com" {
		t.Errorf(`metadata["sni"] = %v`, meta["sni"])
	}
	if meta["discovery_method"] != "pcap_upload" {
		t.Errorf(`metadata["discovery_method"] = %v`, meta["discovery_method"])
	}

	certs, ok := meta["certificates"].([]interface{})
	if !ok || len(certs) != 1 {
		t.Fatalf(`metadata["certificates"] = %#v, want a 1-element array`, meta["certificates"])
	}
	leaf, ok := certs[0].(map[string]interface{})
	if !ok {
		t.Fatalf("certificate entry is %T, want an object", certs[0])
	}
	for key, want := range map[string]interface{}{
		"subject_dn":         "CN=api.example.com",
		"issuer_dn":          "CN=Example CA",
		"key_algorithm":      "ECDSA",
		"signature_alg":      "ECDSA-SHA256",
		"fingerprint_sha256": "ab12",
		"not_before":         notBefore.Format(time.RFC3339),
		"not_after":          notAfter.Format(time.RFC3339),
	} {
		if leaf[key] != want {
			t.Errorf("certificate[%q] = %v, want %v", key, leaf[key], want)
		}
	}
	if leaf["chain_order"] != float64(0) {
		t.Errorf("certificate[chain_order] = %v, want 0", leaf["chain_order"])
	}
	if leaf["key_size"] != float64(256) {
		t.Errorf("certificate[key_size] = %v, want 256", leaf["key_size"])
	}
	if _, ok := leaf["certificate_pem"].(string); !ok {
		t.Error("certificate_pem missing from the leaf entry")
	}
}

// TestBuildDiscoveryMetadataOmitsUnobservedVersion: a session where the server
// flight was never captured must not carry a "version" key at all. An absent
// key is honest; a back-filled client offer is not.
func TestBuildDiscoveryMetadataOmitsUnobservedVersion(t *testing.T) {
	d := discoveryFromTLSSession(&tlsparse.Session{
		ServerIP:         "10.0.0.1",
		ServerPort:       443,
		ClientMaxOffered: "TLS 1.3",
		HandshakeTypes:   []string{"ClientHello"},
	})
	meta := buildDiscoveryMetadata(d)
	if _, present := meta["version"]; present {
		t.Errorf(`metadata["version"] present (%v) when no ServerHello was captured`, meta["version"])
	}
	if meta["client_max_offered_version"] != "TLS 1.3" {
		t.Errorf("client offer should still be recorded: %v", meta["client_max_offered_version"])
	}
}
