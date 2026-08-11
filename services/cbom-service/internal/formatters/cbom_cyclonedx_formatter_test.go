package formatters

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/models"
)

func sampleCBOM() *models.CBOMData {
	return &models.CBOMData{
		SerialNumber: "11111111-2222-3333-4444-555555555555",
		BOMVersion:   1,
		GeneratedAt:  time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC),
		ReportTitle:  "Test CBOM",
		SpecVersion:  "1.6",
		Components: []models.CBOMComponent{
			{
				ID:          "c1",
				BOMRef:      "cert-1",
				Name:        "example.com",
				Type:        models.CBOMComponentTypeCertificate,
				AssetID:     "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				Environment: "production",
				RiskLevel:   "high",
				CertificateDetails: &models.CBOMCertificateDetails{
					SubjectName:   "CN=example.com",
					IssuerName:    "CN=Test CA",
					NotValidAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	}
}

// TestCanonicalJSON_IsActuallyCycloneDX pins the fix for an artifact pipeline
// that served our internal shape (serial_number, bom_version, report_title)
// under a Content-Type of application/vnd.cyclonedx+json. Every consumer that
// trusted the header got a document with no bomFormat and no specVersion, and
// nothing in the suite noticed because nothing asserted on the wire format.
func TestCanonicalJSON_IsActuallyCycloneDX(t *testing.T) {
	out, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(sampleCBOM())
	if err != nil {
		t.Fatalf("FormatCBOMAsCanonicalJSON: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want \"CycloneDX\" — this is the field that makes it a CBOM", doc["bomFormat"])
	}
	if doc["specVersion"] != SpecVersion {
		t.Errorf("specVersion = %v, want %q", doc["specVersion"], SpecVersion)
	}
	if _, ok := doc["components"]; !ok {
		t.Error("no components key")
	}

	// The internal shape's field names must not survive into the published
	// document — their presence is the signature of the original bug.
	for _, leaked := range []string{"serial_number", "bom_version", "report_title", "summary", "parameters"} {
		if _, found := doc[leaked]; found {
			t.Errorf("internal field %q leaked into the CycloneDX document", leaked)
		}
	}
}

// TestCanonicalJSON_IsCompactAndStable guards the hashing contract: these bytes
// are hashed and signed, so indentation would bake presentation into the
// signature, and any run-to-run variation would break verification outright.
func TestCanonicalJSON_IsCompactAndStable(t *testing.T) {
	f := NewCycloneDXFormatter()
	first, err := f.FormatCBOMAsCanonicalJSON(sampleCBOM())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if strings.Contains(string(first), "\n") {
		t.Error("canonical bytes contain newlines; expected compact JSON")
	}

	second, err := f.FormatCBOMAsCanonicalJSON(sampleCBOM())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(first) != string(second) {
		t.Error("canonical bytes differ between runs for identical input; the content hash would not be reproducible")
	}

	// The indented form is the same document, just presented differently.
	indented, err := f.FormatCBOMAsJSON(sampleCBOM())
	if err != nil {
		t.Fatalf("indented: %v", err)
	}
	var a, b map[string]any
	if err := json.Unmarshal(first, &a); err != nil {
		t.Fatalf("unmarshal canonical: %v", err)
	}
	if err := json.Unmarshal(indented, &b); err != nil {
		t.Fatalf("unmarshal indented: %v", err)
	}
	if a["bomFormat"] != b["bomFormat"] || a["specVersion"] != b["specVersion"] {
		t.Error("canonical and indented forms disagree on the document identity")
	}
}

// TestVendorProperties_UseVistaNamespace keeps the retired brand out of the
// document we hand to customers and auditors. These property names are part of
// the emitted artifact, not internal naming.
func TestVendorProperties_UseVistaNamespace(t *testing.T) {
	out, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(sampleCBOM())
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	s := string(out)
	// The retired brand, assembled rather than spelled out. This guard has to
	// know the name in order to watch for it, but the name belongs to another
	// product now and should not appear in our source. Assembling it also means
	// a future repo-wide rename cannot quietly rewrite the string being searched
	// for and leave a test that asserts nothing — which happened once already.
	retired := "quanta" + "view"
	if strings.Contains(strings.ToLower(s), retired) {
		t.Error("emitted CycloneDX carries the retired brand")
	}
	for _, want := range []string{"vista:asset-id", "vista:environment", "vista:risk-level"} {
		if !strings.Contains(s, want) {
			t.Errorf("expected vendor property %q in the emitted document", want)
		}
	}
}
