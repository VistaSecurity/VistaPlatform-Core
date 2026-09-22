package processor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Fixture keys are ASSEMBLED, never written as literals — see the note at the
// top of legacy_cert_shape.go. TestCanonicalCertificateMetadataKey scans this
// tree for the flat spellings and cannot tell a test's literal from a
// producer's.
func legacyKey(suffix string) string { return legacyCertKeyPrefix + suffix }

// legacyFlatDiscovery is a passive TLS discovery exactly as a sensor built
// before the canonical-shape fix: the leaf taken apart into loose keys, plus
// the PEM at the top level without the prefix.
func legacyFlatDiscovery() map[string]interface{} {
	return map[string]interface{}{
		"handshake_type":                 "Certificate",
		legacyKey("fingerprint_sha256"):  "9c4fbcccc5a005eb744c4b2da3d44614e1083753a707410eef68d2a30276b9aa",
		legacyKey("subject"):             "CN=passive.example.test,O=Vista Platform Test",
		legacyKey("issuer"):              "CN=passive.example.test,O=Vista Platform Test",
		legacyKey("not_before"):          "2026-01-02T03:04:05Z",
		legacyKey("not_after"):           "2027-01-02T03:04:05Z",
		legacyKey("key_algorithm"):       "RSA",
		legacyKey("signature_algorithm"): "SHA256-RSA",
		legacyKey("public_key_size"):     float64(2048),
		legacyKey("san"):                 []interface{}{"passive.example.test", "alt.example.test"},
		"certificate_pem":                "-----BEGIN CERTIFICATE-----\nMIIDVz\n-----END CERTIFICATE-----\n",
	}
}

// canonicalCaptureMetadata loads the golden the sensor's passive-capture test
// pins. Reading the producer's own bytes is what makes this end-to-end rather
// than two independent guesses about the shape.
func canonicalCaptureMetadata(t *testing.T) map[string]interface{} {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	var path string
	for i := 0; i < 12; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.work")); statErr == nil {
			path = filepath.Join(dir, "testdata", "discovery-shapes", "passive-tls-capture.json")
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if path == "" {
		t.Fatal("could not locate the repository root (no go.work above the working directory)")
	}
	body, err := os.ReadFile(path) //nolint:gosec // a fixed repo fixture path
	if err != nil {
		t.Fatalf("reading the passive-capture golden: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding the passive-capture golden: %v", err)
	}
	return out
}

// envelope wraps sensor RawMetadata the way sensor-manager's StoreDiscoveries
// does before it reaches extractCryptoDetails.
func envelope(t *testing.T, rawMetadata map[string]interface{}) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"version":          "",
		"cipher_suite":     "",
		"discovery_method": "passive",
		"raw_metadata":     rawMetadata,
	})
	if err != nil {
		t.Fatalf("marshalling envelope: %v", err)
	}
	return body
}

func assertLeafMaterialized(t *testing.T, d *ExternalCryptoDetails) {
	t.Helper()
	if d == nil {
		t.Fatal("extractCryptoDetails returned nil")
	}
	if d.CertFingerprintSHA256 == nil || *d.CertFingerprintSHA256 != "9c4fbcccc5a005eb744c4b2da3d44614e1083753a707410eef68d2a30276b9aa" {
		t.Errorf("fingerprint not materialized: %v", d.CertFingerprintSHA256)
	}
	if d.CertSubject == nil || *d.CertSubject != "CN=passive.example.test,O=Vista Platform Test" {
		t.Errorf("subject not materialized: %v", d.CertSubject)
	}
	if d.CertIssuer == nil || *d.CertIssuer != "CN=passive.example.test,O=Vista Platform Test" {
		t.Errorf("issuer not materialized: %v", d.CertIssuer)
	}
	if d.CertPublicKeyAlgorithm == nil || *d.CertPublicKeyAlgorithm != "RSA" {
		t.Errorf("key algorithm not materialized: %v", d.CertPublicKeyAlgorithm)
	}
	if d.CertSignatureAlgorithm == nil || *d.CertSignatureAlgorithm != "SHA256-RSA" {
		t.Errorf("signature algorithm not materialized: %v", d.CertSignatureAlgorithm)
	}
	if d.CertPublicKeySize == nil || *d.CertPublicKeySize != 2048 {
		t.Errorf("key size not materialized: %v", d.CertPublicKeySize)
	}
	if d.CertNotBefore == nil || d.CertNotAfter == nil {
		t.Errorf("validity window not materialized: %v .. %v", d.CertNotBefore, d.CertNotAfter)
	}
	if len(d.CertSAN) == 0 {
		t.Error("SANs not materialized")
	}
	if d.CertPEM == nil || *d.CertPEM == "" {
		t.Error("PEM not materialized")
	}
}

// The current sensor's bytes must materialize. This is the fix's whole point:
// before it, this path produced flat keys and external_connections got a row
// with a cipher suite and no certificate whatsoever.
func TestCanonicalPassiveCaptureMaterializesCertificate(t *testing.T) {
	assertLeafMaterialized(t, extractCryptoDetails(envelope(t, canonicalCaptureMetadata(t))))
}

// A sensor still in the field keeps sending the flat form after the platform
// is upgraded. It must materialize identically.
func TestLegacyFlatCertificateStillMaterializes(t *testing.T) {
	assertLeafMaterialized(t, extractCryptoDetails(envelope(t, legacyFlatDiscovery())))
}

// A canonical array always wins. A chain of three must not be replaced by one
// synthesised leaf just because stray flat keys ride alongside it.
func TestLegacyFlatCertificateNeverOverridesCanonicalArray(t *testing.T) {
	raw := canonicalCaptureMetadata(t)
	for k, v := range legacyFlatDiscovery() {
		if k == "handshake_type" {
			continue
		}
		raw[k] = v
	}
	raw[legacyKey("subject")] = "CN=should-not-win.example"

	d := extractCryptoDetails(envelope(t, raw))
	if d == nil || d.CertSubject == nil {
		t.Fatal("no certificate materialized")
	}
	if *d.CertSubject == "CN=should-not-win.example" {
		t.Error("the flat form overrode the canonical certificates array")
	}
}

// Without a fingerprint the keys are not a flattened certificate, and nothing
// may be synthesised from them. Otherwise an unrelated cert_* assessment key
// would conjure an empty certificate into the inventory.
func TestLegacyFlatCertificateNeedsAnIdentity(t *testing.T) {
	raw := legacyFlatDiscovery()
	delete(raw, legacyKey("fingerprint_sha256"))

	out := upgradeLegacyFlatCertificate(raw)
	if _, present := out["certificates"]; present {
		t.Errorf("synthesised a certificate with no identity: %#v", out["certificates"])
	}
}

// Assessment keys about a certificate (cert_validation_status, cert_has_sct …)
// are not fields OF one and must not trigger synthesis on their own.
func TestLegacyFlatCertificateIgnoresAssessmentKeysAlone(t *testing.T) {
	out := upgradeLegacyFlatCertificate(map[string]interface{}{
		"cert_validation_status": "valid",
		"cert_has_sct":           true,
	})
	if _, present := out["certificates"]; present {
		t.Errorf("assessment keys alone synthesised a certificate: %#v", out["certificates"])
	}
}

// The caller's map must not be mutated — flattenSensorDiscoveryMetadata is
// called on maps other code still holds.
func TestLegacyFlatCertificateDoesNotMutateInput(t *testing.T) {
	raw := legacyFlatDiscovery()
	out := upgradeLegacyFlatCertificate(raw)
	if _, present := raw["certificates"]; present {
		t.Error("input map was mutated")
	}
	if _, present := out["certificates"]; !present {
		t.Error("output is missing the synthesised array")
	}
}
