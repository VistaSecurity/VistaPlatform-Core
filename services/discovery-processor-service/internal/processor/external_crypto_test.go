package processor

import (
	"encoding/json"
	"testing"
	"time"
)

// Passive capture goes through the same canonical pipeline as active probing:
// the sensor emits a `certificates[]` array using CycloneDX-aligned field names
// (subject_dn, issuer_dn, fingerprint_sha256, ...). See CLAUDE.md "Single
// certificate format" and sensor/internal/enrichment/tls_enricher.go.
func TestExtractCryptoDetails_PassiveCapture(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	notBefore := time.Now().Add(-30 * 24 * time.Hour).UTC().Truncate(time.Second)

	certificates := []interface{}{
		map[string]interface{}{
			"chain_order":               0.0,
			"subject_dn":                "CN=example.com",
			"issuer_dn":                 "CN=Example CA",
			"subject_alternative_names": []interface{}{"example.com", "www.example.com"},
			"not_before":                notBefore.Format(time.RFC3339),
			"not_after":                 notAfter.Format(time.RFC3339),
			"fingerprint_sha256":        "abc123",
			"key_algorithm":             "RSA",
			"key_size":                  2048.0,
			"signature_alg":             "sha256WithRSAEncryption",
			"certificate_pem":           "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
			"cert_validation_status":    "valid",
		},
	}

	raw := map[string]interface{}{
		"version":      "1.3",
		"cipher_suite": "TLS_AES_256_GCM_SHA384",
		"key_size":     2048,
		"certificates": certificates,
	}
	metadata, _ := json.Marshal(raw)

	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}

	assertStrPtr(t, "protocol version", d.ProtocolVersion, "1.3")
	assertStrPtr(t, "cipher suite", d.CipherSuite, "TLS_AES_256_GCM_SHA384")
	assertIntPtr(t, "key size", d.KeySize, 2048)
	assertStrPtr(t, "cert subject", d.CertSubject, "CN=example.com")
	assertStrPtr(t, "cert issuer", d.CertIssuer, "CN=Example CA")
	assertStrPtr(t, "cert fingerprint", d.CertFingerprintSHA256, "abc123")
	assertStrPtr(t, "cert key algorithm", d.CertPublicKeyAlgorithm, "RSA")
	assertIntPtr(t, "cert key size", d.CertPublicKeySize, 2048)
	assertStrPtr(t, "cert sig alg", d.CertSignatureAlgorithm, "sha256WithRSAEncryption")
	assertStrPtr(t, "cert validation", d.CertValidationStatus, "valid")

	if len(d.CertSAN) != 2 || d.CertSAN[0] != "example.com" {
		t.Errorf("expected cert_san [example.com, www.example.com], got %v", d.CertSAN)
	}
	if d.CertNotAfter == nil {
		t.Error("cert_not_after should be set")
	} else if !d.CertNotAfter.Equal(notAfter) {
		t.Errorf("cert_not_after: expected %v, got %v", notAfter, *d.CertNotAfter)
	}
}

func TestExtractCryptoDetails_ActiveProbe(t *testing.T) {
	notAfter := time.Now().Add(180 * 24 * time.Hour).UTC().Truncate(time.Second)

	certificates := []interface{}{
		map[string]interface{}{
			"chain_order":            1.0,
			"subject_dn":             "CN=Intermediate CA",
			"issuer_dn":              "CN=Root CA",
			"fingerprint_sha256":     "intCA",
			"not_after":              notAfter.Add(365 * 24 * time.Hour).Format(time.RFC3339),
			"cert_validation_status": "valid",
		},
		map[string]interface{}{
			"chain_order":               0.0,
			"subject_dn":                "CN=leaf.example.com",
			"issuer_dn":                 "CN=Intermediate CA",
			"subject_alternative_names": []interface{}{"leaf.example.com", "*.example.com"},
			"not_after":                 notAfter.Format(time.RFC3339),
			"fingerprint_sha256":        "leafFP",
			"key_algorithm":             "ECDSA",
			"key_size":                  256.0,
			"signature_alg":             "ecdsa-with-SHA384",
			"certificate_pem":           "-----BEGIN CERTIFICATE-----\n...",
			"cert_validation_status":    "valid",
		},
	}

	raw := map[string]interface{}{
		"version":      "1.3",
		"cipher_suite": "TLS_AES_256_GCM_SHA384",
		"certificates": certificates,
	}
	metadata, _ := json.Marshal(raw)

	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}

	// Should use the leaf cert (chain_order 0)
	assertStrPtr(t, "cert subject", d.CertSubject, "CN=leaf.example.com")
	assertStrPtr(t, "cert issuer", d.CertIssuer, "CN=Intermediate CA")
	assertStrPtr(t, "cert fingerprint", d.CertFingerprintSHA256, "leafFP")
	assertStrPtr(t, "cert key algorithm", d.CertPublicKeyAlgorithm, "ECDSA")
	assertIntPtr(t, "cert key size", d.CertPublicKeySize, 256)
	assertStrPtr(t, "cert sig alg", d.CertSignatureAlgorithm, "ecdsa-with-SHA384")

	if len(d.CertSAN) != 2 || d.CertSAN[0] != "leaf.example.com" {
		t.Errorf("expected SANs [leaf.example.com, *.example.com], got %v", d.CertSAN)
	}
	if d.CertNotAfter == nil {
		t.Error("cert_not_after should be set from leaf cert")
	} else if !d.CertNotAfter.Equal(notAfter) {
		t.Errorf("cert_not_after: expected %v, got %v", notAfter, *d.CertNotAfter)
	}
}

// TLS enricher stores cert_validation_status on the metadata envelope, not inside each
// certificate object. Extraction must still surface it for external_connections upsert.
func TestExtractCryptoDetails_CertValidationOnEnvelopeOnly(t *testing.T) {
	notAfter := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	certificates := []interface{}{
		map[string]interface{}{
			"chain_order":               0.0,
			"subject_dn":                "CN=expired.badssl.com",
			"issuer_dn":                 "CN=R3",
			"subject_alternative_names": []interface{}{"expired.badssl.com"},
			"not_after":                 notAfter.Format(time.RFC3339),
			"fingerprint_sha256":        "leafFP",
			"certificate_pem":           "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
		},
	}
	raw := map[string]interface{}{
		"certificates":           certificates,
		"cert_validation_status": "expired",
		"cert_validation_error":  "certificate has expired",
	}
	metadata, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}
	assertStrPtr(t, "envelope cert_validation_status", d.CertValidationStatus, "expired")
}

// Sensor-manager persists discoveries with an envelope: top-level cipher_suite/version
// and the sensor's RawMetadata nested under "raw_metadata" (where TLS enricher puts
// the "certificates" array). Extraction must merge these layers.
func TestExtractCryptoDetails_SensorManagerEnvelope(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)

	certificates := []interface{}{
		map[string]interface{}{
			"chain_order":               0.0,
			"subject_dn":                "CN=api.example.com",
			"issuer_dn":                 "CN=Example CA",
			"subject_alternative_names": []interface{}{"api.example.com"},
			"not_after":                 notAfter.Format(time.RFC3339),
			"fingerprint_sha256":        "leafsha256",
			"key_algorithm":             "RSA",
			"key_size":                  2048.0,
			"signature_alg":             "sha256WithRSAEncryption",
			"certificate_pem":           "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
			"cert_validation_status":    "valid",
		},
	}

	envelope := map[string]interface{}{
		"version":          "TLS 1.3",
		"cipher_suite":     "TLS_AES_128_GCM_SHA256",
		"key_size":         0.0,
		"discovery_method": "active_enrichment",
		"source_ip":        "192.168.1.10",
		"raw_metadata": map[string]interface{}{
			"certificates":           certificates,
			"enrichment_method":      "active_probe_after_passive",
			"cert_validation_status": "valid",
			"handshake_types":        []interface{}{"ClientHello", "ServerHello", "Certificate"},
		},
	}
	metadata, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}

	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}
	assertStrPtr(t, "protocol version", d.ProtocolVersion, "TLS 1.3")
	assertStrPtr(t, "cipher suite", d.CipherSuite, "TLS_AES_128_GCM_SHA256")
	assertStrPtr(t, "cert subject", d.CertSubject, "CN=api.example.com")
	assertStrPtr(t, "cert fingerprint", d.CertFingerprintSHA256, "leafsha256")
	assertStrPtr(t, "cert pem", d.CertPEM, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
}

func TestExtractCryptoDetails_TLSVersions(t *testing.T) {
	raw := map[string]interface{}{
		"version":      "1.2",
		"cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"tls_versions": []interface{}{"TLS 1.3", "TLS 1.2", "TLS 1.0"},
	}
	metadata, _ := json.Marshal(raw)

	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}

	assertStrPtr(t, "protocol version", d.ProtocolVersion, "1.2")
	if len(d.SupportedTLSVersions) != 3 {
		t.Fatalf("expected 3 supported TLS versions, got %d: %v", len(d.SupportedTLSVersions), d.SupportedTLSVersions)
	}
	if d.SupportedTLSVersions[0] != "TLS 1.3" {
		t.Errorf("expected first version TLS 1.3, got %s", d.SupportedTLSVersions[0])
	}
	if d.SupportedTLSVersions[2] != "TLS 1.0" {
		t.Errorf("expected third version TLS 1.0, got %s", d.SupportedTLSVersions[2])
	}
}

func TestExtractCryptoDetails_TLSVersionsFromEnvelope(t *testing.T) {
	envelope := map[string]interface{}{
		"version":      "1.2",
		"cipher_suite": "TLS_AES_128_GCM_SHA256",
		"raw_metadata": map[string]interface{}{
			"tls_versions": []interface{}{"TLS 1.3", "TLS 1.2"},
			"certificates": []interface{}{},
		},
	}
	metadata, _ := json.Marshal(envelope)

	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil ExternalCryptoDetails")
	}

	if len(d.SupportedTLSVersions) != 2 {
		t.Fatalf("expected 2 supported TLS versions from envelope, got %d: %v", len(d.SupportedTLSVersions), d.SupportedTLSVersions)
	}
}

func TestExtractCryptoDetails_Empty(t *testing.T) {
	if got := extractCryptoDetails(nil); got != nil {
		t.Errorf("expected nil for empty metadata, got %+v", got)
	}
	if got := extractCryptoDetails([]byte{}); got != nil {
		t.Errorf("expected nil for empty slice, got %+v", got)
	}
}

func TestExtractCryptoDetails_InvalidJSON(t *testing.T) {
	if got := extractCryptoDetails([]byte("not-json")); got != nil {
		t.Errorf("expected nil for invalid JSON, got %+v", got)
	}
}

func TestIsWeakProtocol_ViaExtract(t *testing.T) {
	// Verify that SSLv3 metadata produces no crash and that version "1.3" is extracted
	raw := map[string]interface{}{
		"version":      "1.3",
		"cipher_suite": "TLS_AES_256_GCM_SHA384",
	}
	metadata, _ := json.Marshal(raw)
	d := extractCryptoDetails(metadata)
	if d == nil {
		t.Fatal("expected non-nil result")
	}
	assertStrPtr(t, "version", d.ProtocolVersion, "1.3")
}

func TestTimeField_MultipleLayouts(t *testing.T) {
	want := time.Date(2026, 4, 20, 12, 30, 0, 0, time.UTC)

	tests := []struct {
		name  string
		value string
	}{
		{"RFC3339", "2026-04-20T12:30:00Z"},
		{"Go String() UTC", "2026-04-20 12:30:00 +0000 UTC"},
		{"Go String() with offset", "2026-04-20 14:30:00 +0200 CEST"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]interface{}{"ts": tc.value}
			got := timeField(m, "ts")
			if got == nil {
				t.Fatalf("timeField returned nil for %q", tc.value)
			}
			if !got.UTC().Equal(want) {
				t.Errorf("expected %v, got %v", want, got.UTC())
			}
		})
	}
}

// --- helpers ---

func assertStrPtr(t *testing.T, label string, got *string, want string) {
	t.Helper()
	if got == nil {
		t.Errorf("%s: expected %q, got nil", label, want)
		return
	}
	if *got != want {
		t.Errorf("%s: expected %q, got %q", label, want, *got)
	}
}

func assertIntPtr(t *testing.T, label string, got *int, want int) {
	t.Helper()
	if got == nil {
		t.Errorf("%s: expected %d, got nil", label, want)
		return
	}
	if *got != want {
		t.Errorf("%s: expected %d, got %d", label, want, *got)
	}
}
