package capture

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// The non-reassembled passive TLS path used to flatten the leaf certificate
// into loose cert_* keys. No materializer reads that shape — discovery
// -processor's extractCryptoDetails and inventory-service's
// extractCertificatesFromFinding both look for a "certificates" array — so a
// certificate captured this way reached sensor_discoveries and then no
// certificate inventory at all.
//
// These tests pin the canonical shape at the producer, and write the golden
// the two ingest-side tests read back. Because they consume the SAME bytes
// this test asserts, a change to what the sensor emits cannot pass without the
// materializers being re-checked against it — which is the end-to-end binding
// that no import can provide across module boundaries.

// discoveryShapesDir locates the cross-service fixture directory from the
// repository root (the directory holding go.work).
func discoveryShapesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.work")); statErr == nil {
			return filepath.Join(dir, "testdata", "discovery-shapes")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root (no go.work above the working directory)")
	return ""
}

// fixtureLeafDER decodes the fixed leaf certificate the goldens are built from.
// It is a stored DER blob rather than a freshly generated certificate so that
// the golden is byte-stable: both RSA and ECDSA signing are randomised, so a
// certificate minted per run would change fingerprint, serial and PEM.
func fixtureLeafDER(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(discoveryShapesDir(t), "passive-tls-leaf.der.b64"))
	if err != nil {
		t.Fatalf("reading leaf fixture: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		t.Fatalf("decoding leaf fixture: %v", err)
	}
	return der
}

// tlsCertificateRecord frames a DER leaf as a TLS Certificate handshake record,
// the wire shape analyzeTLS dispatches on (RFC 5246 §7.4.2).
func tlsCertificateRecord(der []byte) []byte {
	certEntry := append([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}, der...)
	listLen := len(certEntry)
	body := append([]byte{byte(listLen >> 16), byte(listLen >> 8), byte(listLen)}, certEntry...)
	handshake := append([]byte{0x0B, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)

	rec := make([]byte, 5, 5+len(handshake))
	rec[0] = 0x16 // handshake content type
	binary.BigEndian.PutUint16(rec[1:3], 0x0303)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(handshake)))
	return append(rec, handshake...)
}

// captureLeafMetadata runs the real dispatch path (analyzeTLS → analyzeCertificate)
// over a Certificate record and returns the discovery's RawMetadata.
func captureLeafMetadata(t *testing.T) map[string]interface{} {
	t.Helper()
	pc := &PacketCapture{}
	d := &models.CryptoDiscovery{Protocol: "TLS", RawMetadata: map[string]interface{}{}}
	pc.analyzeTLS(tlsCertificateRecord(fixtureLeafDER(t)), d)
	return d.RawMetadata
}

func TestPassiveCaptureEmitsCanonicalCertificatesArray(t *testing.T) {
	meta := captureLeafMetadata(t)

	if meta["handshake_type"] != "Certificate" {
		t.Errorf("handshake_type = %v, want Certificate", meta["handshake_type"])
	}

	certs, ok := meta["certificates"].([]interface{})
	if !ok || len(certs) != 1 {
		t.Fatalf(`RawMetadata["certificates"] should hold exactly one leaf entry; got %#v`, meta["certificates"])
	}
	leaf, ok := certs[0].(map[string]interface{})
	if !ok {
		t.Fatalf("certificate entry is not an object: %#v", certs[0])
	}

	// The canonical field names, as read by discovery-processor's
	// extractCryptoDetails and inventory-service's extractCertificateData.
	wantStrings := map[string]string{
		"subject_dn":         "CN=passive.example.test,O=Vista Platform Test",
		"issuer_dn":          "CN=passive.example.test,O=Vista Platform Test",
		"serial_number":      "6216097",
		"not_before":         "2026-01-02T03:04:05Z",
		"not_after":          "2027-01-02T03:04:05Z",
		"key_algorithm":      "RSA",
		"signature_alg":      "SHA256-RSA",
		"fingerprint_sha256": "",
	}
	for k, want := range wantStrings {
		got, _ := leaf[k].(string)
		if got == "" {
			t.Errorf("leaf[%q] is empty — the materializers read this name", k)
			continue
		}
		if want != "" && got != want {
			t.Errorf("leaf[%q] = %q, want %q", k, got, want)
		}
	}
	if n, _ := leaf["key_size"].(int); n != 2048 {
		t.Errorf("leaf[\"key_size\"] = %v, want 2048", leaf["key_size"])
	}
	if order, _ := leaf["chain_order"].(int); order != 0 {
		t.Errorf("leaf[\"chain_order\"] = %v, want 0 (leaf)", leaf["chain_order"])
	}
	pemText, _ := leaf["certificate_pem"].(string)
	if !strings.HasPrefix(pemText, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("leaf[\"certificate_pem\"] is not PEM: %q", pemText)
	}
	sans, _ := leaf["subject_alternative_names"].([]string)
	if len(sans) != 3 {
		t.Errorf("subject_alternative_names = %v, want the 2 DNS names + 1 IP", leaf["subject_alternative_names"])
	}
}

// The flat form must be gone from the producer entirely. Emitting BOTH shapes
// would look harmless and would keep the dead keys alive in every stored
// discovery forever.
func TestPassiveCaptureEmitsNoFlatCertificateKeys(t *testing.T) {
	meta := captureLeafMetadata(t)

	// Assembled from parts, not written as literals, for the same reason
	// upgradeLegacyFlatCertificate assembles them: the canonical-key guard
	// hunts for these spellings and cannot tell a producer from a test.
	for _, suffix := range []string{
		"subject", "issuer", "not_before", "not_after", "fingerprint_sha256",
		"key_algorithm", "signature_algorithm", "public_key_size", "san",
	} {
		if v, present := meta["cert_"+suffix]; present {
			t.Errorf("flat key %q is still emitted (= %v); certificates travel as the canonical array", "cert_"+suffix, v)
		}
	}
	// The PEM was the one legacy key written without the prefix. It belongs
	// inside the entry now.
	if v, present := meta["certificate_pem"]; present {
		t.Errorf("bare top-level certificate_pem is still emitted (= %v)", v)
	}
}

// TestPassiveCaptureGoldenShape pins the exact bytes the ingest-side tests read
// back. Refresh with: go test ./sensor/internal/capture/ -run Golden -update
func TestPassiveCaptureGoldenShape(t *testing.T) {
	golden := filepath.Join(discoveryShapesDir(t), "passive-tls-capture.json")

	got, err := json.MarshalIndent(captureLeafMetadata(t), "", "  ")
	if err != nil {
		t.Fatalf("marshalling captured metadata: %v", err)
	}
	got = append(got, '\n')

	if *updateGolden {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatalf("writing golden: %v", err)
		}
		t.Logf("golden updated: %s", golden)
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden (run with -update to create it): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("the passive-capture discovery shape changed.\n--- golden\n%s\n--- produced\n%s\n"+
			"Re-run with -update, and re-run the ingest-side tests that read this file:\n"+
			"  services/discovery-processor-service/internal/processor -run LegacyFlatCertificate\n"+
			"  services/inventory-service/internal/services -run PassiveCapture",
			want, got)
	}
}
