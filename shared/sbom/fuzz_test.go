package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// FuzzParse is the standing proof of the one contract this package cannot
// test by example: an SBOM arrives by upload, so every byte of it is
// attacker-controlled, and a panic in the parser takes the request handler —
// and in a worker, the worker — with it.
//
// The post-conditions asserted on every returned document are the ones a
// consumer would otherwise have to re-check:
//
//  1. No panic, for any input. Nesting is bounded ([maxNestingDepth]), both
//     caps are enforced before allocation, and every field is read through the
//     tolerant accessors rather than unmarshalled into a struct.
//  2. Exactly one of (document, error). A parser that returns both, or
//     neither, leaves the caller with no way to decide.
//  3. Every returned component is WRITABLE: it has a name (the column is NOT
//     NULL) and a non-empty identity (an empty one collapses the catalogue).
//     A fuzzer that produces a component we would then fail to insert has
//     found a real bug, not a parser curiosity.
//  4. No PEM private key survives, in any field or any warning. Redaction runs
//     over the assembled document, so it cannot be bypassed by a field shape
//     nobody thought of.
//  5. Both caps hold on the output as well as on the input.
//
// `errors.Is` on the returned error is deliberately NOT asserted: a pile of
// random bytes may legitimately be reported as malformed OR as an unknown
// format, and pinning that would test the fuzzer rather than the parser.
//
// The seed corpus is every fixture in testdata plus the hand-written cases
// below, which are the shapes that have historically broken JSON parsers:
// deep nesting, huge numbers, duplicate keys, lone surrogates, and a document
// whose every value is the wrong type.
func FuzzParse(f *testing.F) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		f.Fatalf("glob fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		f.Fatal("no fixtures found; the corpus would be the hand-written seeds only")
	}
	for _, name := range fixtures {
		data, err := os.ReadFile(name) //nolint:gosec // test fixture path, built from a glob of testdata
		if err != nil {
			f.Fatalf("read %s: %v", name, err)
		}
		f.Add(string(data))
	}

	for _, seed := range []string{
		``,
		`{}`,
		`[]`,
		`null`,
		`{"bomFormat":"CycloneDX"}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":null}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":{}}`,
		`{"bomFormat":"CycloneDX","specVersion":1.6}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","name":"b"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"\ud800"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","version":1e400}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"99999999999999999999.0"}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","bom-ref":"r","components":[{"name":"b","bom-ref":"r"}]}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","bom-ref":"x"}],"dependencies":[{"ref":"x","dependsOn":["x"]}]}`,
		`{"spdxVersion":"SPDX-2.3"}`,
		`{"spdxVersion":"SPDX-2.3","packages":"not an array"}`,
		`{"spdxVersion":"SPDX-2.3","packages":[{"name":"a","externalRefs":[{}]}]}`,
		`{"spdxVersion":"SPDX-2.3","relationships":[{"spdxElementId":"a","relationshipType":"CONTAINS","relatedSpdxElement":"a"}]}`,
		`{"spdxVersion":"SPDX-2.3","documentDescribes":[null,1,"SPDXRef-x"],"packages":[{"name":"a","SPDXID":"SPDXRef-x"}]}`,
		`{"spdxVersion":"SPDX-2.3","packages":[{"name":"a","licenseConcluded":"NOASSERTION","supplier":"Organization:"}]}`,
		// A containment rooted at the document itself: the package is top
		// level, and the document id must not become a Parent naming something
		// that is not a component.
		`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"SPDXRef-a","name":"a"}],` +
			`"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-a"}]}`,
		// Document-local licence ids, bare and as part of an expression.
		`{"spdxVersion":"SPDX-2.3","packages":[{"name":"a","licenseConcluded":"LicenseRef-0"},` +
			`{"name":"b","licenseConcluded":"LicenseRef-1 OR MIT"}]}`,
		// A declared subject that resolves to nothing.
		`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","documentDescribes":["SPDXRef-ghost"],` +
			`"packages":[{"SPDXID":"SPDXRef-a","name":"a"}]}`,
		// A metadata.component that is not an object: declared and unreadable.
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":"a string"},"components":[]}`,
		"\xef\xbb\xbf" + `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		`<bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		doc, err := Parse(strings.NewReader(in))

		if doc == nil {
			if err == nil {
				t.Fatal("Parse returned (nil, nil): it must say which")
			}
			return
		}
		if err != nil {
			t.Fatalf("Parse returned both a document and an error %v", err)
		}

		if len(doc.Components) > MaxComponents {
			t.Fatalf("returned %d components, cap is %d", len(doc.Components), MaxComponents)
		}

		// The leak check is "running the redactor again changes nothing",
		// not "the text contains PRIVATE KEY". The first is exactly the
		// property Parse promises — every string has already been through
		// [redact.TextPEM] — and it cannot over- or under-trigger. The second
		// is what this test asserted first, and the fuzzer immediately found
		// a component legitimately NAMED "PRIVATE KEY" (kept as a seed), which
		// is not key material and which redact.TextPEM correctly leaves alone.
		// A guard that fires on a value the redactor is right to pass is the
		// over-strict half of the same bug; see redact.MustNotRedact.
		leaks := func(field, s string) {
			t.Helper()
			if redact.TextPEM(s) != s {
				t.Fatalf("%s did not go through redaction: %q", field, s)
			}
		}

		for i, c := range doc.Components {
			if !c.Product.Identifiable() {
				t.Fatalf("component %d has no name; software_products.name is NOT NULL "+
					"and this row could not be written: %#v", i, c)
			}
			if c.Product.Identity() == "" {
				t.Fatalf("component %d has an empty identity, which collapses the "+
					"catalogue onto one key: %#v", i, c)
			}
			leaks("component name", c.Product.Name)
			leaks("component vendor", c.Product.Vendor)
			leaks("component version", c.Product.Version)
			leaks("component purl", c.Product.PURL)
			leaks("component cpe", c.Product.CPE)
			leaks("component licence", c.Product.LicenseID)
			leaks("component bom-ref", c.BOMRef)
			leaks("component parent", c.Parent)
		}

		if doc.Subject != nil {
			if !doc.Subject.Identifiable() {
				t.Fatalf("subject has no name: %#v", *doc.Subject)
			}
			leaks("subject name", doc.Subject.Name)
			leaks("subject vendor", doc.Subject.Vendor)
			leaks("subject version", doc.Subject.Version)
			leaks("subject purl", doc.Subject.PURL)
			leaks("subject cpe", doc.Subject.CPE)
			leaks("subject licence", doc.Subject.LicenseID)
		}

		// Every edge must resolve, or a consumer following the graph lands on
		// a component that is not there.
		known := knownRefs(doc)
		for _, e := range doc.Dependencies {
			if e.From == "" || e.To == "" {
				t.Fatalf("edge with an empty end: %#v", e)
			}
			if e.From == e.To {
				t.Fatalf("self-edge %#v: a traversal that follows it loops", e)
			}
			if !known[e.From] || !known[e.To] {
				t.Fatalf("edge %#v names a ref this document does not define", e)
			}
		}

		for _, w := range doc.Warnings {
			leaks("warning", w)
		}
		if len(doc.Warnings) > maxWarnings*2 {
			t.Fatalf("returned %d warnings; the cap is %d plus the counted summaries",
				len(doc.Warnings), maxWarnings)
		}
	})
}
