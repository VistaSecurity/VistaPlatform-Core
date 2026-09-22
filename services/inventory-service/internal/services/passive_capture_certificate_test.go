package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The far end of the passive-capture chain.
//
// A sensor's Certificate-handshake observation reaches here as
// IngestFinding.RawData, after discovery-processor has flattened the
// sensor-manager envelope. These tests read the SAME golden the sensor's
// producer test pins, so the shape cannot change at one end without the other
// end being re-checked against it — the binding an import cannot provide
// across module boundaries.
//
// Before the producer emitted the canonical array, this is precisely where the
// data was lost: extractCertificatesFromFinding reads "certificates", the
// sensor wrote loose per-field keys, and a captured certificate materialized
// as nothing at all.

func passiveCaptureGolden(t *testing.T) map[string]interface{} {
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

// extractCertificateData accepts several legacy spellings (`subject` for
// `subject_dn`, `pem` for `certificate_pem`, …) so that older producers keep
// working. That tolerance means materializing successfully does NOT prove the
// producer emitted the canonical names — a drifted shape would still pass.
// Assert the names themselves, so this test fails on the drift too.
func TestPassiveCaptureGoldenUsesCanonicalFieldNames(t *testing.T) {
	certs, ok := passiveCaptureGolden(t)["certificates"].([]interface{})
	if !ok || len(certs) != 1 {
		t.Fatalf(`golden["certificates"] should hold one leaf entry; got %#v`, certs)
	}
	leaf, ok := certs[0].(map[string]interface{})
	if !ok {
		t.Fatalf("certificate entry is not an object: %#v", certs[0])
	}
	for _, name := range []string{
		"subject_dn", "issuer_dn", "serial_number", "not_before", "not_after",
		"fingerprint_sha256", "fingerprint_sha1", "key_algorithm", "key_size",
		"signature_alg", "certificate_pem", "subject_alternative_names",
		"chain_order",
	} {
		if _, present := leaf[name]; !present {
			t.Errorf("canonical field %q is missing from the emitted leaf", name)
		}
	}
}

func TestPassiveCaptureFindingMaterializesCertificate(t *testing.T) {
	f := IngestFinding{RawData: passiveCaptureGolden(t)}

	certs := (&AssetService{}).extractCertificatesFromFinding(f)
	if len(certs) != 1 {
		t.Fatalf("expected exactly 1 certificate from a passive TLS capture, got %d", len(certs))
	}
	c := certs[0]

	if c.SubjectDN != "CN=passive.example.test,O=Vista Platform Test" {
		t.Errorf("subject_dn = %q", c.SubjectDN)
	}
	if c.IssuerDN != "CN=passive.example.test,O=Vista Platform Test" {
		t.Errorf("issuer_dn = %q", c.IssuerDN)
	}
	if c.CommonName != "passive.example.test" {
		t.Errorf("common_name = %q", c.CommonName)
	}
	if c.SerialNumber != "6216097" {
		t.Errorf("serial_number = %q", c.SerialNumber)
	}
	if c.FingerprintSHA256 != "9c4fbcccc5a005eb744c4b2da3d44614e1083753a707410eef68d2a30276b9aa" {
		t.Errorf("fingerprint_sha256 = %q", c.FingerprintSHA256)
	}
	if c.FingerprintSHA1 != "99cf1edd3b0d0b81287524ec9351480d432f2137" {
		t.Errorf("fingerprint_sha1 = %q", c.FingerprintSHA1)
	}
	if c.PublicKeyAlgorithm != "RSA" {
		t.Errorf("public_key_algorithm = %q", c.PublicKeyAlgorithm)
	}
	if c.PublicKeySize != 2048 {
		t.Errorf("public_key_size = %d", c.PublicKeySize)
	}
	if c.SignatureAlgorithm != "SHA256-RSA" {
		t.Errorf("signature_algorithm = %q", c.SignatureAlgorithm)
	}
	if c.NotBefore.IsZero() || c.NotAfter.IsZero() {
		t.Errorf("validity window not parsed: %v .. %v", c.NotBefore, c.NotAfter)
	}
	if c.CertificatePEM == "" {
		t.Error("certificate_pem not carried")
	}
	if len(c.SubjectAlternativeNames) != 3 {
		t.Errorf("subject_alternative_names = %v", c.SubjectAlternativeNames)
	}
	if !c.IsSelfSigned {
		t.Error("a self-signed leaf should be flagged self-signed")
	}
}

// Why the upgrade in discovery-processor is load-bearing rather than cosmetic:
// the flat form reaches this extractor as nothing. If someone ever removes
// upgradeLegacyFlatCertificate, a field sensor's certificates go silently
// missing again, and this test says so.
func TestFlatCertificateShapeMaterializesNothingHere(t *testing.T) {
	// Keys assembled, not written as literals — the canonical-key guard scans
	// this tree and cannot tell a test's literal from a producer's.
	flat := map[string]interface{}{}
	for _, suffix := range []string{"subject", "issuer", "fingerprint_sha256", "key_algorithm"} {
		flat["cert_"+suffix] = "something"
	}

	certs := (&AssetService{}).extractCertificatesFromFinding(IngestFinding{RawData: flat})
	if len(certs) != 0 {
		t.Fatalf("the flat form is not readable here and must materialize nothing; got %d: %+v", len(certs), certs)
	}
}
