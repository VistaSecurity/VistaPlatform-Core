package sbom

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

// parseFixture parses testdata/<name> and fails the test if it does not parse
// at all. A warning is not a failure — the whole design is that a document
// parses and reports what it could not use.
func parseFixture(t *testing.T, name string) *Document {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	doc, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return doc
}

// wantComponents compares the component list field by field, reporting the
// first mismatch with both sides rather than dumping two structs.
func wantComponents(t *testing.T, got, want []Component) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d components, want %d:\n got: %s\nwant: %s",
			len(got), len(want), summarise(got), summarise(want))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("component %d:\n got %#v\nwant %#v", i, got[i], want[i])
		}
	}
}

func summarise(cs []Component) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString("\n  " + c.Type + " " + c.BOMRef + " " + c.Product.Identity())
	}
	return b.String()
}

func wantEdges(t *testing.T, got, want []Edge) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dependencies:\n got %v\nwant %v", got, want)
	}
}

func wantWarnings(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("warnings:\n got %q\nwant %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// CycloneDX
// ---------------------------------------------------------------------------

func TestParseCycloneDX15(t *testing.T) {
	doc := parseFixture(t, "cyclonedx-1.5.json")

	if doc.Format != FormatCycloneDX || doc.SpecVersion != "1.5" {
		t.Errorf("format/spec = %q/%q, want cyclonedx/1.5", doc.Format, doc.SpecVersion)
	}
	if doc.Serial != "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" {
		t.Errorf("Serial = %q", doc.Serial)
	}

	// metadata.component is the subject, and is NOT also a component: in
	// CycloneDX the document's subject sits outside the component list.
	if doc.Subject == nil {
		t.Fatal("no subject; metadata.component was not read")
	}
	if want := (software.Product{Name: "billing-api", Vendor: "Example Corp", Version: "4.2.0"}); *doc.Subject != want {
		t.Errorf("Subject = %#v, want %#v", *doc.Subject, want)
	}
	if doc.SubjectType != "application" || doc.SubjectRef != "app-root" {
		t.Errorf("SubjectType/Ref = %q/%q", doc.SubjectType, doc.SubjectRef)
	}

	wantComponents(t, doc.Components, []Component{
		{
			// The purl is folded to canonical form — scheme and type
			// lowercased, name left alone. Deleting the purl passthrough in
			// convertCDXComponent makes this line the first thing that fails.
			Product: software.Product{
				Name: "left-pad", Version: "1.3.0",
				PURL: "pkg:npm/Left-Pad@1.3.0", LicenseID: "MIT",
			},
			Type: "library", BOMRef: "lib-left-pad",
		},
		{
			// `group` is the vendor when there is no publisher; the CPE
			// arrived as a 2.2 URI and is stored as a 2.3 formatted string;
			// the licence is an expression and is kept verbatim rather than
			// collapsed to its first id.
			Product: software.Product{
				Name: "commons-lang3", Vendor: "org.apache.commons", Version: "3.12.0",
				PURL:      "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
				CPE:       "cpe:2.3:a:apache:commons_lang:3.12.0:*:*:*:*:*:*:*",
				LicenseID: "Apache-2.0 OR MIT",
			},
			Type: "library", BOMRef: "lib-commons", Scope: "required",
		},
		{
			Product: software.Product{
				Name: "alpine", Version: "3.20",
				CPE: "cpe:2.3:o:alpinelinux:alpine_linux:3.20:*:*:*:*:*:*:*",
			},
			Type: "operating-system", BOMRef: "os-alpine",
		},
	})

	wantEdges(t, doc.Dependencies, []Edge{
		{From: "app-root", To: "lib-left-pad"},
		{From: "app-root", To: "lib-commons"},
	})
	wantWarnings(t, doc.Warnings, nil)
}

func TestParseCycloneDX16(t *testing.T) {
	doc := parseFixture(t, "cyclonedx-1.6.json")

	if doc.SubjectType != "container" {
		t.Errorf("SubjectType = %q, want container", doc.SubjectType)
	}

	wantComponents(t, doc.Components, []Component{
		{
			// `publisher` beats `group`; the purl's qualifier keys are
			// lowercased and sorted, which is what makes ?OS=linux&arch=amd64
			// and ?arch=amd64&os=linux one catalogue row rather than two.
			Product: software.Product{
				Name: "openssl", Vendor: "Debian OpenSSL Team", Version: "3.0.11-1",
				PURL:      "pkg:deb/debian/openssl@3.0.11-1?arch=amd64&os=linux",
				CPE:       "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*",
				LicenseID: "Apache-2.0",
			},
			Type: "library", BOMRef: "pkg:deb/debian/openssl@3.0.11-1", Scope: "required",
		},
		{
			// The only licence information was a free-text `name`, which is
			// not an SPDX id and does not go in an id column. Dropped, counted.
			Product: software.Product{
				Name: "spring-boot", Vendor: "org.springframework.boot", Version: "3.2.1",
				PURL: "pkg:maven/org.springframework.boot/spring-boot@3.2.1",
			},
			Type: "framework", BOMRef: "lib-spring", Scope: "optional",
		},
		{
			// scope=excluded is KEPT rather than filtered here: the parser
			// reports what the document said, and "this is not in the
			// artefact" is exactly the fact an ingester needs in order not to
			// write an install for it.
			Product: software.Product{Name: "/etc/billing/config.yaml"},
			Type:    "file", BOMRef: "file-config", Scope: "excluded",
		},
		{
			Product: software.Product{Name: "libz"},
			Type:    "library", BOMRef: "lib-unversioned",
		},
		{
			// An unrecognised type is kept verbatim, not blanked.
			Product: software.Product{Name: "some-vendor-thing", Version: "1.0"},
			Type:    "wildly-unofficial-type", BOMRef: "thing-1",
		},
	})

	// The edge to "lib-that-does-not-exist" is dropped: an unresolvable edge
	// asserts a relationship the consumer cannot follow.
	wantEdges(t, doc.Dependencies, []Edge{
		{From: "img-registry.example.test/billing:4.2.0", To: "pkg:deb/debian/openssl@3.0.11-1"},
		{From: "img-registry.example.test/billing:4.2.0", To: "lib-spring"},
		{From: "lib-spring", To: "lib-unversioned"},
	})

	wantWarnings(t, doc.Warnings, []string{
		"1 component has a type outside the CycloneDX enum; kept verbatim",
		"1 component licence dropped: the document gave a licence NAME with no SPDX id or expression",
		"1 dependency edge dropped: it names a component this document does not define",
	})
}

// TestParseCycloneDXUnversionedIdentity is the ledger's warning applied end to
// end: the unversioned component in the 1.6 fixture must still key on
// `name@`, because a NULL identity in the database admits unlimited duplicates
// of the same product.
func TestParseCycloneDXUnversionedIdentity(t *testing.T) {
	doc := parseFixture(t, "cyclonedx-1.6.json")
	for _, c := range doc.Components {
		if c.BOMRef != "lib-unversioned" {
			continue
		}
		if got := c.Product.Identity(); got != "libz@" {
			t.Fatalf("unversioned component identity = %q, want %q", got, "libz@")
		}
		return
	}
	t.Fatal("lib-unversioned is not in the parsed components")
}

func TestParseCycloneDXNested(t *testing.T) {
	doc := parseFixture(t, "cyclonedx-nested.json")

	// Flattened, with containment preserved as Parent at every level.
	wantComponents(t, doc.Components, []Component{
		{Product: software.Product{Name: "payments-war", Version: "9.1"},
			Type: "application", BOMRef: "war-payments"},
		{Product: software.Product{
			Name: "jackson-databind", Vendor: "com.fasterxml.jackson.core", Version: "2.17.1",
			PURL: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.1",
		}, Type: "library", BOMRef: "jar-jackson", Parent: "war-payments"},
		{Product: software.Product{
			Name: "jackson-annotations", Vendor: "com.fasterxml.jackson.core", Version: "2.17.1",
		}, Type: "library", BOMRef: "jar-jackson-annotations", Parent: "jar-jackson"},
		{Product: software.Product{Name: "slf4j-api", Version: "2.0.13"},
			Type: "library", BOMRef: "jar-slf4j", Parent: "war-payments"},
		{Product: software.Product{Name: "guava", Version: "33.2.0-jre"},
			Type: "library", BOMRef: "jar-top-level"},
	})
	wantWarnings(t, doc.Warnings, nil)
}

// TestParseCycloneDXMalformed is the "never a panic, never a whole-document
// failure" contract. Every shape in the fixture is broken in a different way;
// the four intact components must still come through.
func TestParseCycloneDXMalformed(t *testing.T) {
	doc := parseFixture(t, "cyclonedx-malformed.json")

	if doc.Subject != nil {
		t.Errorf("Subject = %#v; metadata.component was a string and must yield none", *doc.Subject)
	}

	wantComponents(t, doc.Components, []Component{
		{Product: software.Product{Name: "good-one", Version: "1.0.0"},
			Type: "library", BOMRef: "good-1"},
		{
			// `"version": 7` is a type mismatch. Reading field by field means
			// the version is absent and the component survives; unmarshalling
			// into a struct would have failed the whole document here.
			Product: software.Product{Name: "wrong-typed-version", PURL: "pkg:npm/wrong-typed-version@7"},
			Type:    "library", BOMRef: "good-2",
		},
		{Product: software.Product{Name: "bad-identifiers", Version: "1.0"},
			Type: "library", BOMRef: "good-3"},
		{Product: software.Product{Name: "licenses-not-an-array"},
			Type: "library", BOMRef: "good-4"},
	})

	wantEdges(t, doc.Dependencies, []Edge{{From: "good-1", To: "good-2"}})

	wantWarnings(t, doc.Warnings, []string{
		// The document declared a subject and it was unreadable. That has to be
		// said: a silently absent subject is indistinguishable from a document
		// that never named one, and only one of those is the user's problem.
		"metadata.component is not a JSON object and was not read; " +
			"the document is treated as having no subject",
		`component "bad-identifiers": dropped unparseable purl "definitely-not-a-purl": software: invalid purl: no scheme separator`,
		`component "bad-identifiers": dropped unparseable cpe "cpe:2.3:a:only:three": software: invalid cpe: a formatted string has 13 colon-separated fields, got 5`,
		"2 components skipped: no name (software_products.name is NOT NULL)",
		"3 components skipped: not a JSON object",
		"2 dependency entries skipped: not a JSON object, or no ref",
		"2 dependency edges dropped: they name components this document does not define",
	})
}

// TestParseVistaCBOMOutput parses the cbom-service formatter's own output.
//
// CycloneDX is an OUTPUT of this platform and, per the charter, an input too.
// If our own document did not parse here, the first customer to round-trip one
// would find out for us. The crypto components must be SKIPPED — counted, not
// errored — and the one real library must become a product.
func TestParseVistaCBOMOutput(t *testing.T) {
	doc := parseFixture(t, "vista-cbom-1.7.json")

	if doc.SpecVersion != "1.7" {
		t.Errorf("SpecVersion = %q, want 1.7 (the version formatters.SpecVersion emits)", doc.SpecVersion)
	}
	if doc.SubjectType != "application" {
		t.Errorf("SubjectType = %q, want application", doc.SubjectType)
	}

	wantComponents(t, doc.Components, []Component{
		{
			Product: software.Product{Name: "OpenSSL", Version: "3.0.13", PURL: "pkg:generic/openssl@3.0.13"},
			Type:    "library", BOMRef: "lib-openssl",
		},
	})

	// The library→algorithm relation in our CBOM is `provides`, not
	// `dependsOn`, and its far end is a skipped crypto component either way.
	wantEdges(t, doc.Dependencies, nil)

	wantWarnings(t, doc.Warnings, []string{
		"2 cryptographic components skipped: cryptographic assets belong to the CBOM path, not the software catalogue",
	})
}

// ---------------------------------------------------------------------------
// SPDX
// ---------------------------------------------------------------------------

func TestParseSPDX23(t *testing.T) {
	doc := parseFixture(t, "spdx-2.3.json")

	if doc.Format != FormatSPDX || doc.SpecVersion != "SPDX-2.3" {
		t.Errorf("format/spec = %q/%q", doc.Format, doc.SpecVersion)
	}
	// SPDX has no serial; documentNamespace is the unique-per-document field
	// the spec provides and is what makes a re-ingest idempotent.
	if doc.Serial != "https://example.test/spdx/billing-api-4.2.0-2b7b0e5a" {
		t.Errorf("Serial = %q, want the documentNamespace", doc.Serial)
	}
	if doc.SubjectRef != "SPDXRef-Package-billing-api" || doc.SubjectType != "application" {
		t.Errorf("Subject ref/type = %q/%q", doc.SubjectRef, doc.SubjectType)
	}

	wantComponents(t, doc.Components, []Component{
		{
			Product: software.Product{
				Name: "billing-api", Vendor: "Example Corp", Version: "4.2.0", LicenseID: "Apache-2.0",
			},
			Type: "application", BOMRef: "SPDXRef-Package-billing-api",
		},
		{
			// purl from PACKAGE_MANAGER/purl, CPE from SECURITY/cpe23Type,
			// and Parent from the alpine CONTAINS relationship — the SPDX
			// equivalent of a CycloneDX nested component.
			Product: software.Product{
				Name: "openssl", Vendor: "Debian OpenSSL Team", Version: "3.0.11-1",
				PURL:      "pkg:deb/debian/openssl@3.0.11-1?arch=amd64",
				CPE:       "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*",
				LicenseID: "Apache-2.0",
			},
			Type: "library", BOMRef: "SPDXRef-Package-openssl", Parent: "SPDXRef-Package-alpine",
		},
		{
			// `originator: Person: …` supplies the vendor when supplier is
			// absent; the cpe22Type ref is converted to a 2.3 string, so it
			// dedupes against a cpe23Type ref for the same product;
			// licenseConcluded was NOASSERTION, so there is no licence — and
			// licenseDeclared (Zlib) is deliberately NOT substituted.
			Product: software.Product{
				Name: "zlib", Vendor: "Mark Adler", Version: "1.3.1",
				CPE: "cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*",
			},
			Type: "library", BOMRef: "SPDXRef-Package-zlib",
		},
		{
			// supplier NOASSERTION yields no vendor, not the literal string;
			// licenseConcluded NONE yields no licence.
			Product: software.Product{Name: "alpine", Version: "3.20"},
			Type:    "operating-system", BOMRef: "SPDXRef-Package-alpine",
		},
		{
			// ARCHIVE has no CycloneDX equivalent and maps to "" rather than
			// being forced into a type it is not.
			Product: software.Product{Name: "vendor-archive", Version: "0.1"},
			Type:    "", BOMRef: "SPDXRef-Package-unmapped-purpose",
		},
	})

	wantEdges(t, doc.Dependencies, []Edge{
		{From: "SPDXRef-Package-billing-api", To: "SPDXRef-Package-openssl"},
		{From: "SPDXRef-Package-openssl", To: "SPDXRef-Package-zlib"},
	})

	wantWarnings(t, doc.Warnings, []string{
		"2 package licences dropped: licenseConcluded was NOASSERTION or NONE",
		"2 file entries not ingested: SPDX files are not software products",
		"1 relationship dropped: it names an element this document does not define as a package",
		"2 relationships of types this model has no home for were ignored " +
			"(only DESCRIBES, DEPENDS_ON and CONTAINS are mapped)",
	})
}

func TestParseSPDX22(t *testing.T) {
	doc := parseFixture(t, "spdx-2.2.json")

	if doc.SpecVersion != "SPDX-2.2" {
		t.Errorf("SpecVersion = %q", doc.SpecVersion)
	}
	// DESCRIBED_BY is the reverse spelling of DESCRIBES and names the same
	// subject. A parser that read only DESCRIBES would return no subject here.
	if doc.SubjectRef != "SPDXRef-Package-root" {
		t.Errorf("SubjectRef = %q, want SPDXRef-Package-root from the DESCRIBED_BY relationship", doc.SubjectRef)
	}
	// A 2.2 document writing the PACKAGE-MANAGER hyphen spelling of the
	// external-ref category. `referenceCategory` is not consulted at all —
	// `referenceType` alone is unambiguous and the category has three
	// spellings in the wild — and this fixture is what proves the hyphen form
	// costs nothing. Losing the purl here would key the catalogue on
	// name@version and dedupe against nothing.
	var curl *Component
	for i := range doc.Components {
		if doc.Components[i].BOMRef == "SPDXRef-Package-curl" {
			curl = &doc.Components[i]
		}
	}
	if curl == nil {
		t.Fatal("curl package missing")
	}
	if curl.Product.PURL != "pkg:generic/curl@8.5.0" {
		t.Errorf("curl purl = %q; the PACKAGE-MANAGER hyphen spelling was not read", curl.Product.PURL)
	}
	if curl.Product.LicenseID != "curl" {
		t.Errorf("curl licence = %q, want the SPDX id \"curl\"", curl.Product.LicenseID)
	}
	wantWarnings(t, doc.Warnings, nil)
}

// TestSPDXSubjectIsAlsoAComponent states an asymmetry between the formats that
// an ingester has to know about: in CycloneDX the subject sits OUTSIDE the
// component list, in SPDX it is one OF the packages. Writing both without
// noticing would create the subject's product twice.
func TestSPDXSubjectIsAlsoAComponent(t *testing.T) {
	doc := parseFixture(t, "spdx-2.3.json")
	if doc.Subject == nil {
		t.Fatal("no subject")
	}
	found := false
	for _, c := range doc.Components {
		if c.BOMRef == doc.SubjectRef {
			found = true
		}
	}
	if !found {
		t.Error("SPDX subject is not in Components; the documented asymmetry has changed")
	}

	cdx := parseFixture(t, "cyclonedx-1.5.json")
	for _, c := range cdx.Components {
		if c.BOMRef == cdx.SubjectRef {
			t.Error("CycloneDX subject appears in Components; the documented asymmetry has changed")
		}
	}
}

// parseString parses an inline document and fails if it does not parse at all.
// Used for the one-behaviour cases that would distort a golden fixture.
func parseString(t *testing.T, in string) *Document {
	t.Helper()
	doc, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return doc
}

// TestSPDXUnresolvedDescribesWarns: the document NAMES a subject and we have no
// package by that id. Returning no subject in silence is the shape this package
// exists not to have — the CycloneDX side warns on the equivalent
// metadata.component case, and ADR-0004 D3 may create an application asset from
// the subject, so "there wasn't one" and "we lost it" are not the same answer.
func TestSPDXUnresolvedDescribesWarns(t *testing.T) {
	doc := parseString(t, `{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
		"documentDescribes":["SPDXRef-Package-ghost"],
		"packages":[{"SPDXID":"SPDXRef-Package-a","name":"a","versionInfo":"1"}]
	}`)

	if doc.Subject != nil {
		t.Errorf("Subject = %#v, want none", *doc.Subject)
	}
	wantWarnings(t, doc.Warnings, []string{
		"1 document subject not resolved: DESCRIBES names an element this document does not define as a package",
	})

	// The same shape through the relationship spelling rather than the
	// shorthand, because a document may use either.
	rel := parseString(t, `{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
		"packages":[{"SPDXID":"SPDXRef-Package-a","name":"a"}],
		"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES",
			"relatedSpdxElement":"SPDXRef-Package-ghost"}]
	}`)
	if len(rel.Warnings) != 1 || !strings.Contains(rel.Warnings[0], "subject not resolved") {
		t.Errorf("warnings = %q; a DESCRIBES naming a ghost must say so", rel.Warnings)
	}

	// The inverse polarity: a DESCRIBES that resolves must warn about nothing.
	ok := parseString(t, `{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
		"documentDescribes":["SPDXRef-Package-a"],
		"packages":[{"SPDXID":"SPDXRef-Package-a","name":"a"}],
		"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES",
			"relatedSpdxElement":"SPDXRef-Package-a"}]
	}`)
	if ok.SubjectRef != "SPDXRef-Package-a" {
		t.Errorf("SubjectRef = %q", ok.SubjectRef)
	}
	wantWarnings(t, ok.Warnings, nil)
}

// TestSPDXContainsEndsMustBePackages: Component.Parent is documented as the
// BOMRef of the component this one sits inside, so it has to name a component.
//
// `SPDXRef-DOCUMENT CONTAINS pkg` is the shape that used to break it: the
// document is not a component, and recording its id as a Parent made every
// top-level package look nested inside a container no consumer could resolve —
// a stronger claim than the document made.
func TestSPDXContainsEndsMustBePackages(t *testing.T) {
	fromDocument := parseString(t, `{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
		"packages":[{"SPDXID":"SPDXRef-Package-a","name":"a"}],
		"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"CONTAINS",
			"relatedSpdxElement":"SPDXRef-Package-a"}]
	}`)
	if got := fromDocument.Components[0].Parent; got != "" {
		t.Errorf("Parent = %q; the document containing a package means the package is TOP LEVEL", got)
	}
	// And it is not an error either — the document said something true.
	wantWarnings(t, fromDocument.Warnings, nil)

	// A container this document does not define as a package: dropped and
	// counted, the same rule DEPENDS_ON keeps on both of its ends.
	fromFile := parseString(t, `{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
		"packages":[{"SPDXID":"SPDXRef-Package-a","name":"a"}],
		"relationships":[{"spdxElementId":"SPDXRef-File-x","relationshipType":"CONTAINS",
			"relatedSpdxElement":"SPDXRef-Package-a"}]
	}`)
	if got := fromFile.Components[0].Parent; got != "" {
		t.Errorf("Parent = %q; it names an element that is not a component in this document", got)
	}
	wantWarnings(t, fromFile.Warnings, []string{
		"1 relationship dropped: it names an element this document does not define as a package",
	})

	// The inverse polarity: a CONTAINS between two real packages still records
	// the parent, or this fix has thrown away the containment it exists to keep.
	real := parseString(t, `{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
		"packages":[{"SPDXID":"SPDXRef-Package-a","name":"a"},{"SPDXID":"SPDXRef-Package-b","name":"b"}],
		"relationships":[{"spdxElementId":"SPDXRef-Package-a","relationshipType":"CONTAINS",
			"relatedSpdxElement":"SPDXRef-Package-b"}]
	}`)
	if got := real.Components[1].Parent; got != "SPDXRef-Package-a" {
		t.Errorf("Parent = %q, want SPDXRef-Package-a", got)
	}
	wantWarnings(t, real.Warnings, nil)
}

// TestSPDXDocumentLocalLicenseRefDropped: `LicenseRef-0` is an id the DOCUMENT
// defines, in a section this parser does not read. Two SBOMs from two build
// systems both emit `LicenseRef-0` for two unrelated licences, so storing it in
// a tenant-wide catalogue MERGES them under one value — the unrecoverable
// direction of the asymmetry this package decides everything else by, and one
// step worse than the free-text `license.name` the CycloneDX side already drops
// for being indistinguishable from an SPDX id.
func TestSPDXDocumentLocalLicenseRefDropped(t *testing.T) {
	doc := parseString(t, `{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
		"packages":[
			{"SPDXID":"SPDXRef-a","name":"a","licenseConcluded":"LicenseRef-0"},
			{"SPDXID":"SPDXRef-b","name":"b","licenseConcluded":"DocumentRef-x:LicenseRef-2"}
		]
	}`)
	for _, c := range doc.Components {
		if c.Product.LicenseID != "" {
			t.Errorf("%s kept licence %q; a document-local ref names nothing in a tenant catalogue",
				c.BOMRef, c.Product.LicenseID)
		}
	}
	wantWarnings(t, doc.Warnings, []string{
		"2 package licences dropped: licenseConcluded was a document-local LicenseRef-, " +
			"which names nothing outside the document it came from",
	})

	// The inverse polarity, and the reason the check is on the BARE value only:
	// an expression carries real SPDX ids alongside the ref, and dropping the
	// whole string to be rid of the ref would lose them. A real id is untouched.
	kept := parseString(t, `{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
		"packages":[
			{"SPDXID":"SPDXRef-a","name":"a","licenseConcluded":"MIT AND LicenseRef-1"},
			{"SPDXID":"SPDXRef-b","name":"b","licenseConcluded":"Apache-2.0"},
			{"SPDXID":"SPDXRef-c","name":"c","licenseConcluded":"LicenseRef-Acme-Internal-1.0"},
			{"SPDXID":"SPDXRef-d","name":"d","licenseConcluded":"LicenseRef-1 OR MIT"}
		]
	}`)
	// Third: a longer document-local ref goes the same way as the short one —
	// the length of the id is not what makes it meaningless.
	//
	// Fourth is the case that makes the whitespace test load-bearing rather
	// than decorative. An expression BEGINNING with a ref passes a bare prefix
	// check, so without the "is this an expression" test first it would be
	// dropped whole and take the MIT with it.
	for i, want := range []string{"MIT AND LicenseRef-1", "Apache-2.0", "", "LicenseRef-1 OR MIT"} {
		if got := kept.Components[i].Product.LicenseID; got != want {
			t.Errorf("component %d licence = %q, want %q", i, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

// TestRedactsPEM is the mutation target named in the workstream brief: delete
// the redactStrings call in Parse and this fails.
//
// A PEM private key in an SBOM is not hypothetical — free-text fields get
// pasted into — and CLAUDE.md's rule is absolute: collect posture, never key
// material. The last two assertions are the inverse polarity, which matters as
// much: a CERTIFICATE block is posture and must survive, and an over-strict
// scrubber that ate it would be the same bug pointed the other way.
func TestRedactsPEM(t *testing.T) {
	doc := parseFixture(t, "cyclonedx-pem.json")

	var seen []string
	collect := func(s string) { seen = append(seen, s) }
	if doc.Subject != nil {
		collect(doc.Subject.Name)
		collect(doc.Subject.Vendor)
		collect(doc.Subject.Version)
		collect(doc.Subject.PURL)
		collect(doc.Subject.CPE)
		collect(doc.Subject.LicenseID)
	}
	for _, c := range doc.Components {
		collect(c.Product.Name)
		collect(c.Product.Vendor)
		collect(c.Product.Version)
		collect(c.Product.PURL)
		collect(c.Product.CPE)
		collect(c.Product.LicenseID)
		collect(c.BOMRef)
		collect(c.Type)
		collect(c.Scope)
		collect(c.Parent)
	}
	// Warnings quote input text, which makes them a leak path of their own —
	// and the one nobody inspects.
	seen = append(seen, doc.Warnings...)

	for _, s := range seen {
		if strings.Contains(s, "PRIVATE KEY") {
			t.Errorf("a PEM private key survived into the parsed document: %q", s)
		}
	}

	// And it was actually there to be caught, so this test cannot pass by the
	// fixture quietly losing its key material.
	if !strings.Contains(doc.Subject.Vendor, "[redacted]") {
		t.Errorf("subject vendor = %q; the fixture's key was expected to be masked here", doc.Subject.Vendor)
	}
	found := false
	for _, w := range doc.Warnings {
		if strings.Contains(w, "[redacted]") {
			found = true
		}
	}
	if !found {
		t.Error("no warning carries a [redacted] marker; the warning leak path is untested")
	}

	// The inverse polarity, which matters as much as the forward one. A
	// CERTIFICATE block is exactly what this platform is in business to
	// inventory; a scrubber that ate it would destroy the posture data while
	// looking like it was working. redact.MustNotRedact makes the same point
	// about field names.
	certKept := false
	for _, c := range doc.Components {
		if strings.Contains(c.Product.Name, "BEGIN CERTIFICATE") {
			certKept = true
		}
	}
	if !certKept {
		t.Error("the CERTIFICATE block did not survive: an over-strict scrubber is the same bug " +
			"pointed the other way, and it destroys the inventory we exist to produce")
	}
}

// ---------------------------------------------------------------------------
// Detection and refusals
// ---------------------------------------------------------------------------

func TestDetection(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantFormat Format
		wantErr    error
	}{
		{
			name: "cyclonedx 1.4 is the floor",
			in:   `{"bomFormat":"CycloneDX","specVersion":"1.4"}`, wantFormat: FormatCycloneDX,
		},
		{
			name: "cyclonedx 1.7", in: `{"bomFormat":"CycloneDX","specVersion":"1.7"}`,
			wantFormat: FormatCycloneDX,
		},
		{
			name: "specVersion alone is enough", in: `{"specVersion":"1.6","components":[]}`,
			wantFormat: FormatCycloneDX,
		},
		{
			name: "bomFormat case-insensitive", in: `{"bomFormat":"cyclonedx","specVersion":"1.6"}`,
			wantFormat: FormatCycloneDX,
		},
		{
			// A newer minor is parsed, not refused: refusing would make every
			// future CycloneDX release an outage for every customer.
			name: "cyclonedx 1.9 parses with a warning", in: `{"bomFormat":"CycloneDX","specVersion":"1.9"}`,
			wantFormat: FormatCycloneDX,
		},
		{name: "spdx 2.2", in: `{"spdxVersion":"SPDX-2.2"}`, wantFormat: FormatSPDX},
		{name: "spdx 2.3", in: `{"spdxVersion":"SPDX-2.3"}`, wantFormat: FormatSPDX},

		{
			name: "cyclonedx 1.3 is below the floor", in: `{"bomFormat":"CycloneDX","specVersion":"1.3"}`,
			wantErr: ErrUnsupportedSpecVersion,
		},
		{
			name: "cyclonedx 2.0", in: `{"bomFormat":"CycloneDX","specVersion":"2.0"}`,
			wantErr: ErrUnsupportedSpecVersion,
		},
		{
			name: "cyclonedx with no specVersion", in: `{"bomFormat":"CycloneDX","components":[]}`,
			wantErr: ErrUnsupportedSpecVersion,
		},
		{
			name: "spdx 3.0 is a different model, refused by name", in: `{"spdxVersion":"SPDX-3.0"}`,
			wantErr: ErrUnsupportedSpecVersion,
		},
		{name: "spdx 2.1", in: `{"spdxVersion":"SPDX-2.1"}`, wantErr: ErrUnsupportedSpecVersion},

		{
			name:    "cyclonedx XML is out of scope",
			in:      `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"></bom>`,
			wantErr: ErrUnsupportedEncoding,
		},
		{name: "plain JSON object", in: `{"hello":"world"}`, wantErr: ErrUnknownFormat},
		{name: "JSON array", in: `[{"bomFormat":"CycloneDX"}]`, wantErr: ErrMalformed},
		{name: "not JSON", in: `this is a sentence`, wantErr: ErrMalformed},
		{name: "truncated JSON", in: `{"bomFormat":"CycloneDX",`, wantErr: ErrMalformed},
		{name: "empty", in: ``, wantErr: ErrMalformed},
		{name: "whitespace only", in: "  \n\t ", wantErr: ErrMalformed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := Parse(strings.NewReader(tc.in))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want one wrapping %v", err, tc.wantErr)
				}
				if doc != nil {
					t.Error("a refused document must return nil, not a partial parse")
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if doc.Format != tc.wantFormat {
				t.Errorf("Format = %q, want %q", doc.Format, tc.wantFormat)
			}
		})
	}
}

func TestNewerSpecVersionWarns(t *testing.T) {
	doc, err := Parse(strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.9","components":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Warnings) != 1 || !strings.Contains(doc.Warnings[0], "newer than") {
		t.Errorf("warnings = %q; a newer spec version must say so", doc.Warnings)
	}
}

// TestUTF8BOM: a Windows exporter prepends one, and encoding/json rejects it
// as "invalid character 'ï'" — an error message that sends the user nowhere.
func TestUTF8BOM(t *testing.T) {
	in := "\xef\xbb\xbf" + `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	if _, err := Parse(strings.NewReader(in)); err != nil {
		t.Fatalf("a document with a UTF-8 BOM must parse: %v", err)
	}
}

func TestNilReader(t *testing.T) {
	if _, err := Parse(nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("Parse(nil) = %v, want ErrMalformed rather than a panic", err)
	}
}

// ---------------------------------------------------------------------------
// Caps
// ---------------------------------------------------------------------------

// TestSizeCap generates the over-cap document rather than committing one: a
// 32 MiB fixture in git to prove a size check works is a bad trade.
func TestSizeCap(t *testing.T) {
	head := `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"`
	tail := `","components":[]}`
	padding := strings.Repeat("a", MaxDocumentBytes)
	_, err := Parse(strings.NewReader(head + padding + tail))

	var limit *LimitError
	if !errors.As(err, &limit) {
		t.Fatalf("err = %v, want a *LimitError", err)
	}
	if limit.Limit != "bytes" || limit.Max != MaxDocumentBytes {
		t.Errorf("limit = %+v", limit)
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("err does not wrap ErrTooLarge")
	}

	// Exactly at the cap is accepted; the check is "more than", not "at least".
	exact := head + strings.Repeat("a", MaxDocumentBytes-len(head)-len(tail)) + tail
	if len(exact) != MaxDocumentBytes {
		t.Fatalf("test built a %d byte document, wanted exactly %d", len(exact), MaxDocumentBytes)
	}
	if _, err := Parse(strings.NewReader(exact)); err != nil {
		t.Errorf("a document of exactly MaxDocumentBytes must parse: %v", err)
	}
}

func TestComponentCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[`)
	for i := 0; i <= MaxComponents; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"type":"library","name":"c"}`)
	}
	b.WriteString(`]}`)

	_, err := Parse(strings.NewReader(b.String()))
	var limit *LimitError
	if !errors.As(err, &limit) {
		t.Fatalf("err = %v, want a *LimitError", err)
	}
	if limit.Limit != "components" || limit.Max != MaxComponents {
		t.Errorf("limit = %+v", limit)
	}
	if !errors.Is(err, ErrTooManyComponents) {
		t.Error("err does not wrap ErrTooManyComponents")
	}
}

func TestSPDXComponentCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"spdxVersion":"SPDX-2.3","packages":[`)
	for i := 0; i <= MaxComponents; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"name":"p"}`)
	}
	b.WriteString(`]}`)

	if _, err := Parse(strings.NewReader(b.String())); !errors.Is(err, ErrTooManyComponents) {
		t.Fatalf("err = %v, want ErrTooManyComponents", err)
	}
}

// TestNestingDepth is a crash guard, not a policy one. A recursive walk over
// attacker-controlled nesting is the cheapest stack overflow there is, and a
// stack overflow is not an error any caller can handle.
func TestNestingDepth(t *testing.T) {
	const depth = maxNestingDepth + 20
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[`)
	for i := 0; i < depth; i++ {
		b.WriteString(`{"type":"library","name":"n","bom-ref":"r","components":[`)
	}
	for i := 0; i < depth; i++ {
		b.WriteString(`]}`)
	}
	b.WriteString(`]}`)

	doc, err := Parse(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("deep nesting must be bounded, not fatal: %v", err)
	}
	if len(doc.Components) > maxNestingDepth+1 {
		t.Errorf("got %d components from a %d-deep document; the depth bound did not fire", len(doc.Components), depth)
	}
	found := false
	for _, w := range doc.Warnings {
		if strings.Contains(w, "nesting deeper than") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning about the depth bound: %q", doc.Warnings)
	}
}

// TestWarningCap: every per-entry warning is driven by input, so an
// adversarial document would otherwise turn a bounded parse into an unbounded
// allocation.
func TestWarningCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[`)
	for i := 0; i < maxWarnings*3; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"type":"library","name":"c","purl":"not-a-purl"}`)
	}
	b.WriteString(`]}`)

	doc, err := Parse(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Warnings) > maxWarnings+8 {
		t.Errorf("got %d warnings from a document designed to produce %d; the cap did not fire",
			len(doc.Warnings), maxWarnings*3)
	}
	last := doc.Warnings[len(doc.Warnings)-1]
	if !strings.Contains(last, "further warnings suppressed") {
		t.Errorf("last warning = %q; a truncated list must say it was truncated", last)
	}
}

func TestLimitErrorMessage(t *testing.T) {
	e := &LimitError{Limit: "components", Max: 100, Got: 431}
	if !strings.Contains(e.Error(), "431") || !strings.Contains(e.Error(), "100") {
		t.Errorf("Error() = %q; it must name both the observed value and the cap", e.Error())
	}
	unknown := &LimitError{Limit: "bytes", Max: 100, Got: -1}
	if !strings.Contains(unknown.Error(), "more than 100") {
		t.Errorf("Error() = %q", unknown.Error())
	}
}
