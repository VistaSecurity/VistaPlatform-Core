package formatters

// Schema conformance for the bytes we hash, sign, serve and call evidence.
//
// The CBOM artifact is the flagship Core evidence feature: a customer hands the
// downloaded document to an auditor, who runs it through a CycloneDX validator.
// Until this test existed, nothing checked that it passes — and it did not. The
// formatter declared specVersion 1.6 while populating certificateProperties
// fields that only exist from 1.7 (certificateState is set on EVERY certificate,
// defaulted to "active"), and 1.6 sets additionalProperties:false there. Every
// artifact containing a certificate — which is to say every real artifact —
// failed validation against the version it claimed to be.
//
// The schemas in testdata/cyclonedx are the official ones, taken verbatim from
// github.com/CycloneDX/specification (Apache-2.0). They are vendored rather
// than fetched so the test runs offline and pins one exact spec revision.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/models"
)

const cdxSchemaBase = "http://cyclonedx.org/schema/"

// compileCycloneDXSchema loads the vendored schema set and compiles the
// requested BOM schema. The sibling documents ($refs to spdx, jsf and — in 1.7
// — cryptography-defs) are registered under the URIs the BOM schema resolves
// them to, so nothing reaches the network.
func compileCycloneDXSchema(t *testing.T, bomSchemaFile string) *jsonschema.Schema {
	t.Helper()

	c := jsonschema.NewCompiler()
	c.AssertFormat() // date-time fields are only checked if formats are asserted

	files := []string{
		bomSchemaFile,
		"spdx.schema.json",
		"jsf-0.82.schema.json",
		"cryptography-defs.schema.json",
	}
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join("testdata", "cyclonedx", name))
		if err != nil {
			t.Fatalf("read vendored schema %s: %v", name, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("parse vendored schema %s: %v", name, err)
		}
		if err := c.AddResource(cdxSchemaBase+name, doc); err != nil {
			t.Fatalf("add vendored schema %s: %v", name, err)
		}
	}

	sch, err := c.Compile(cdxSchemaBase + bomSchemaFile)
	if err != nil {
		t.Fatalf("compile %s: %v", bomSchemaFile, err)
	}
	return sch
}

func validateAgainst(t *testing.T, sch *jsonschema.Schema, doc []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		t.Fatalf("emitted document is not valid JSON: %v", err)
	}
	return sch.Validate(inst)
}

// representativeCBOM exercises every field family the emitter can populate,
// including the ones the audit found off-spec: a certificate with a lifecycle
// state and extensions, an algorithm carrying a family, a key with a
// fingerprint, and a protocol whose observed name (SMB) is not in the
// protocolProperties.type enumeration.
func representativeCBOM() *models.CBOMData {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	return &models.CBOMData{
		SerialNumber: "11111111-2222-3333-4444-555555555555",
		BOMVersion:   1,
		GeneratedAt:  time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
		ReportTitle:  "Cryptographic Bill of Materials",
		Components: []models.CBOMComponent{
			{
				ID:          "certificate:c1",
				BOMRef:      "crypto/certificate/c1",
				Name:        "example.com",
				Type:        models.CBOMComponentTypeCertificate,
				AssetID:     "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				Environment: "production",
				RiskLevel:   "high",
				// Depends on the key below (resolvable) and on a component that
				// is not in this document (must be dropped).
				DependsOn: []string{
					"crypto/related-crypto-material/k1",
					"crypto/library/does-not-exist",
				},
				CertificateDetails: &models.CBOMCertificateDetails{
					SerialNumber:       "0a1b2c3d",
					SubjectName:        "CN=example.com",
					IssuerName:         "CN=Test CA",
					CommonName:         "example.com",
					NotValidBefore:     notBefore,
					NotValidAfter:      notAfter,
					FingerprintAlg:     "SHA-256",
					FingerprintContent: strings.Repeat("ab", 32),
					KeyAlgorithm:       "RSA",
					SignatureAlgorithm: "SHA256-RSA",
					CertificateFormat:  "X.509",
					// "expired" is one of our seven lifecycle states and one
					// CycloneDX does not define — it must come out as a custom
					// state, not an invalid pre-defined one.
					CertificateStates: []models.CBOMCertificateState{
						{State: "expired", Reason: "not_after in the past"},
					},
					Extensions: []models.CBOMCertificateExtension{
						{Type: "common", Name: "keyUsage", Value: "digitalSignature"},
						{Type: "custom", Name: "1.3.6.1.4.1.99999.1", Value: "internal-marker"},
					},
					RelatedCryptoAssets: []models.CBOMRelatedCryptoAssetRef{
						{Type: "publicKey", Ref: "crypto/related-crypto-material/k1"},
					},
				},
			},
			{
				ID:     "algorithm:i1:symmetric:aes-256-gcm",
				BOMRef: "crypto/algorithm/aes-256-gcm",
				Name:   "AES-256-GCM",
				Type:   models.CBOMComponentTypeAlgorithm,
				AlgorithmDetails: &models.CBOMAlgorithmDetails{
					Code:                     "AES-256-GCM",
					AlgorithmFamily:          "AES",
					Primitive:                "ae",
					Mode:                     "gcm",
					CryptoFunctions:          []string{"encrypt", "decrypt"},
					ClassicalSecurityLevel:   256,
					NistQuantumSecurityLevel: 5,
					Category:                 "symmetric",
				},
			},
			{
				ID:     "algorithm:i1:key_exchange:curve25519",
				BOMRef: "crypto/algorithm/curve25519",
				Name:   "CURVE25519",
				Type:   models.CBOMComponentTypeAlgorithm,
				AlgorithmDetails: &models.CBOMAlgorithmDetails{
					Code: "CURVE25519",
					// A family our catalogue ships and CycloneDX does not list.
					AlgorithmFamily: "Curve25519",
					Primitive:       "key-agree",
					Category:        "key_exchange",
					// A classical bit count that once leaked into this field.
					NistQuantumSecurityLevel: 128,
				},
			},
			{
				ID:     "key:k1",
				BOMRef: "crypto/related-crypto-material/k1",
				Name:   "RSA public key",
				Type:   models.CBOMComponentTypeKey,
				KeyDetails: &models.CBOMKeyDetails{
					MaterialType:       "public-key",
					ID:                 "k1",
					State:              "active",
					SizeBits:           2048,
					Format:             "PEM",
					FingerprintAlg:     "SHA-256",
					FingerprintContent: strings.Repeat("cd", 32),
					KeyType:            "RSA",
					CreatedAt:          &created,
				},
			},
			{
				ID:     "library:l1",
				BOMRef: "crypto/library/l1",
				Name:   "openssl",
				Type:   models.CBOMComponentTypeLibrary,
				LibraryDetails: &models.CBOMLibraryDetails{
					Name:    "openssl",
					Version: "3.0.14",
					PURL:    "pkg:generic/openssl@3.0.14",
				},
				Provides: []string{"crypto/algorithm/aes-256-gcm"},
			},
			{
				ID:     "protocol:i1",
				BOMRef: "crypto/protocol/i1",
				Name:   "SMB 3.1.1",
				Type:   models.CBOMComponentTypeProtocol,
				DependsOn: []string{
					"crypto/algorithm/aes-256-gcm",
					"crypto/library/l1",
				},
				ProtocolDetails: &models.CBOMProtocolDetails{
					// Not a member of the enum in 1.6 or 1.7.
					Type:             "SMB",
					Version:          "3.1.1",
					CipherSuiteNames: []string{"TLS_AES_256_GCM_SHA384"},
				},
			},
		},
	}
}

// TestEmittedDocument_ValidatesAgainstOfficialCycloneDXSchema is the centrepiece:
// a representative artifact, run through the real emitter, checked against the
// official schema for the version it declares.
func TestEmittedDocument_ValidatesAgainstOfficialCycloneDXSchema(t *testing.T) {
	out, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(representativeCBOM())
	if err != nil {
		t.Fatalf("FormatCBOMAsCanonicalJSON: %v", err)
	}

	var declared struct {
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(out, &declared); err != nil {
		t.Fatalf("unmarshal emitted document: %v", err)
	}

	// The declared version and the schema this test validates against have to be
	// the same thing, or the test proves nothing about what we ship.
	if declared.SpecVersion != SpecVersion {
		t.Fatalf("document declares specVersion %q but the formatter constant is %q",
			declared.SpecVersion, SpecVersion)
	}
	if SpecVersion != "1.7" {
		t.Fatalf("SpecVersion = %q, want \"1.7\" — the emitted field set (certificateState, "+
			"serialNumber, fingerprint, certificateExtensions, algorithmFamily) does not exist "+
			"before 1.7, so declaring anything earlier makes every certificate-bearing artifact "+
			"invalid", SpecVersion)
	}

	sch := compileCycloneDXSchema(t, "bom-1.7.schema.json")
	if err := validateAgainst(t, sch, out); err != nil {
		t.Fatalf("emitted CycloneDX document does not validate against the official "+
			"1.7 schema:\n%v\n--- document ---\n%s", err, string(out))
	}
}

// TestEmittedDocument_IsNotValidAsCycloneDX16 is the other half of the proof.
// It is not a wish that we stay on 1.7 — it demonstrates *why* declaring 1.6
// was a defect: the very same bytes are rejected by the 1.6 schema, because the
// fields we populate did not exist yet. If a future change removes those fields
// and this test starts failing, the honest response is to re-examine the
// declared version, not to delete the test.
func TestEmittedDocument_IsNotValidAsCycloneDX16(t *testing.T) {
	out, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(representativeCBOM())
	if err != nil {
		t.Fatalf("FormatCBOMAsCanonicalJSON: %v", err)
	}

	// Re-label the document as 1.6 — exactly what the code used to claim.
	relabelled := bytes.Replace(out,
		[]byte(`"specVersion":"`+SpecVersion+`"`),
		[]byte(`"specVersion":"1.6"`), 1)
	if bytes.Equal(relabelled, out) {
		t.Fatal("could not re-label the document as 1.6; the specVersion field moved")
	}

	sch := compileCycloneDXSchema(t, "bom-1.6.schema.json")
	if err := validateAgainst(t, sch, relabelled); err == nil {
		t.Fatal("the emitted document validates as CycloneDX 1.6 — either it no longer " +
			"carries the 1.7-only cryptoProperties fields, or the vendored 1.6 schema is wrong")
	}
}

// TestEmittedDocument_ProtocolTypeIsWithinEnum pins the second half of CBOM-1:
// discovered protocols we have no CycloneDX enum member for (smb, rdp) used to
// go out lower-cased and off-spec.
func TestEmittedDocument_ProtocolTypeIsWithinEnum(t *testing.T) {
	out, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(representativeCBOM())
	if err != nil {
		t.Fatalf("format: %v", err)
	}

	doc := decodeDoc(t, out)
	var found bool
	for _, comp := range doc.Components {
		if comp.CryptoProperties == nil || comp.CryptoProperties.ProtocolProperties == nil {
			continue
		}
		found = true
		if got := comp.CryptoProperties.ProtocolProperties.Type; got != "other" {
			t.Errorf("protocolProperties.type = %q, want \"other\" for an SMB observation", got)
		}
		// The observed name must survive somewhere, or we have improved
		// conformance by deleting evidence.
		if !hasProperty(comp.Properties, "vista:protocol-name", "SMB") {
			t.Errorf("observed protocol name was dropped; properties = %+v", comp.Properties)
		}
	}
	if !found {
		t.Fatal("no protocol component in the emitted document")
	}

	for _, in := range []struct{ in, want string }{
		{"TLSv1.3", "tls"}, {"SSLv3", "tls"}, {"SSH-2.0", "ssh"},
		{"IPSEC", "ipsec"}, {"IKEv2", "ike"}, {"rdp", "other"}, {"smb", "other"},
		{"", ""},
	} {
		if got := NormalizeProtocolType(in.in); got != in.want {
			t.Errorf("NormalizeProtocolType(%q) = %q, want %q", in.in, got, in.want)
		}
	}
}

// TestEmittedDocument_DependencyGraphResolves pins CBOM-4: every dependsOn and
// provides entry must name a component defined in the same document. The graph
// used to be written with internal ids (key:<uuid>) against components whose
// bom-refs are crypto/related-crypto-material/<uuid>, so not one edge resolved.
func TestEmittedDocument_DependencyGraphResolves(t *testing.T) {
	out, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(representativeCBOM())
	if err != nil {
		t.Fatalf("format: %v", err)
	}

	doc := decodeDoc(t, out)
	refs := map[string]bool{}
	for _, comp := range doc.Components {
		refs[comp.BOMRef] = true
	}

	var edges int
	for _, dep := range doc.Dependencies {
		if !refs[dep.Ref] {
			t.Errorf("dependency ref %q is not a component in this document", dep.Ref)
		}
		for _, target := range dep.DependsOn {
			edges++
			if !refs[target] {
				t.Errorf("dependsOn %q (from %q) resolves to nothing in this document", target, dep.Ref)
			}
		}
		for _, target := range dep.Provides {
			edges++
			if !refs[target] {
				t.Errorf("provides %q (from %q) resolves to nothing in this document", target, dep.Ref)
			}
		}
	}
	if edges == 0 {
		t.Fatal("no dependency edges emitted; the test fixture no longer exercises the graph")
	}

	// The fixture deliberately includes an edge to a component that isn't here.
	if strings.Contains(string(out), "crypto/library/does-not-exist") {
		t.Error("a dangling dependency edge was emitted instead of dropped")
	}
}

// TestEmittedDocument_OffEnumValuesArePreserved checks that conformance was
// bought by relocating values, not by discarding them.
func TestEmittedDocument_OffEnumValuesArePreserved(t *testing.T) {
	out, err := NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(representativeCBOM())
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	doc := decodeDoc(t, out)

	var sawCurve25519, sawExpiredState bool
	for _, comp := range doc.Components {
		if hasProperty(comp.Properties, "vista:algorithm-family", "Curve25519") {
			sawCurve25519 = true
		}
		if comp.CryptoProperties == nil || comp.CryptoProperties.CertificateProperties == nil {
			continue
		}
		for _, st := range comp.CryptoProperties.CertificateProperties.CertificateState {
			if st.Name == "expired" {
				sawExpiredState = true
			}
			if st.State != "" && st.Name != "" {
				t.Errorf("certificateState entry sets both state and name (%q/%q); "+
					"the schema's oneOf accepts neither shape", st.State, st.Name)
			}
		}
	}
	if !sawCurve25519 {
		t.Error("an algorithm family outside the CycloneDX enum was dropped rather than preserved")
	}
	if !sawExpiredState {
		t.Error("the 'expired' certificate state was dropped rather than emitted as a custom state")
	}
}

// --- helpers ---------------------------------------------------------------

func decodeDoc(t *testing.T, raw []byte) CDXDocument {
	t.Helper()
	var doc CDXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal emitted document: %v", err)
	}
	return doc
}

func hasProperty(props []CDXProperty, name, value string) bool {
	for _, p := range props {
		if p.Name == name && p.Value == value {
			return true
		}
	}
	return false
}
