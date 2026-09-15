package xbom

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// -update rewrites the golden files. Run it deliberately, read the diff, and
// commit it — a golden regenerated without reading the diff is a test that
// asserts whatever the code currently does.
var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata/")

const cdxSchemaBase = "http://cyclonedx.org/schema/"

// cycloneDXSchemaDir is the vendored schema set, shared with the formatters
// package rather than copied.
//
// One copy, deliberately: two copies of a spec drift, and the day they disagree
// is the day one of the two tests is validating against a version nothing
// emits. The files are Apache-2.0 from github.com/CycloneDX/specification; see
// that directory's README.
var cycloneDXSchemaDir = filepath.Join("..", "formatters", "testdata", "cyclonedx")

// compileCycloneDX17 loads the vendored 1.7 schema and its siblings, offline.
func compileCycloneDX17(t *testing.T) *jsonschema.Schema {
	t.Helper()

	c := jsonschema.NewCompiler()
	// Without this, `format: iri-reference` on service.endpoints and
	// `format: date-time` on the timestamps are annotations rather than
	// assertions — and the endpoint IRIs are exactly the thing most likely to
	// be malformed.
	c.AssertFormat()

	for _, name := range []string{
		"bom-1.7.schema.json",
		"spdx.schema.json",
		"jsf-0.82.schema.json",
		"cryptography-defs.schema.json",
	} {
		raw, err := os.ReadFile(filepath.Join(cycloneDXSchemaDir, name))
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
	sch, err := c.Compile(cdxSchemaBase + "bom-1.7.schema.json")
	if err != nil {
		t.Fatalf("compile bom-1.7.schema.json: %v", err)
	}
	return sch
}

func buildFixture(t *testing.T, kind string) []byte {
	t.Helper()
	doc, err := BuildDocument(kind, fixtureSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument(%s): %v", kind, err)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal %s: %v", kind, err)
	}
	return out
}

// TestEachKind_ValidatesAgainstOfficialCycloneDX17Schema is the conformance
// half: what we hand a customer must pass the validator their auditor runs.
//
// The CBOM kind already has this proof in the formatters package; these three
// kinds populate an entirely different half of the spec — `services`,
// `vulnerabilities`, `evidence.occurrences`, `licenses`, `cpe`, the
// `dependencies` graph — none of which the existing test touches.
func TestEachKind_ValidatesAgainstOfficialCycloneDX17Schema(t *testing.T) {
	sch := compileCycloneDX17(t)
	for _, kind := range []string{"sbom", "hbom", "inventory"} {
		t.Run(kind, func(t *testing.T) {
			out := buildFixture(t, kind)

			var declared struct {
				SpecVersion string `json:"specVersion"`
			}
			if err := json.Unmarshal(out, &declared); err != nil {
				t.Fatalf("unmarshal emitted document: %v", err)
			}
			// Validating against a version the document does not claim would
			// prove nothing about what ships.
			if declared.SpecVersion != "1.7" {
				t.Fatalf("document declares specVersion %q, want 1.7", declared.SpecVersion)
			}

			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(out))
			if err != nil {
				t.Fatalf("emitted document is not valid JSON: %v", err)
			}
			if err := sch.Validate(inst); err != nil {
				t.Fatalf("%s does not validate against the official CycloneDX 1.7 schema:\n%v\n--- document ---\n%s",
					kind, err, string(out))
			}
		})
	}
}

// TestEachKind_MatchesGolden pins the exact bytes per kind.
//
// The golden files are the readable record of what each kind contains: a
// reviewer checks the mapping by reading them, not by reading the assembler.
func TestEachKind_MatchesGolden(t *testing.T) {
	for _, kind := range []string{"sbom", "hbom", "inventory"} {
		t.Run(kind, func(t *testing.T) {
			got := buildFixture(t, kind)
			// Indented on disk so a diff is readable; the assembler's own
			// output is compact, and the indentation is applied only here.
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, got, "", "  "); err != nil {
				t.Fatalf("indent: %v", err)
			}
			assertGolden(t, kind+".cdx.json", pretty.Bytes())
		})
	}
}

// TestEachKind_IsByteStableAcrossAssemblies is the determinism proof, and it is
// the one that matters most.
//
// The canonical bytes ARE the content hash. If an unchanged inventory assembled
// twice produced different bytes, every regenerated artifact would have a new
// hash, a comparison would report changes that did not happen, and "the
// artifact changed" would stop meaning anything. Map iteration order in Go is
// deliberately randomised per run, so this catches a map that reached the
// output without a sort in front of it — which is not hypothetical: the
// assembler groups by product, by asset and by dependency source, three maps
// whose key order would otherwise leak straight into the document.
func TestEachKind_IsByteStableAcrossAssemblies(t *testing.T) {
	for _, kind := range []string{"sbom", "hbom", "inventory"} {
		t.Run(kind, func(t *testing.T) {
			first := buildFixture(t, kind)
			// Several times, not twice: one repeat has a real chance of
			// agreeing with the first by luck on a small map.
			for i := 0; i < 12; i++ {
				again := buildFixture(t, kind)
				if !bytes.Equal(first, again) {
					t.Fatalf("assembly %d differs from the first — the document is not deterministic\n--- first ---\n%s\n--- again ---\n%s",
						i+2, first, again)
				}
			}
		})
	}
}

// TestInventory_OnlyVulnerabilityProducerFindingsAppear guards the rule that a
// finding is not a CVE.
//
// The fixture's two findings are both from the `vulnerability` producer, which
// is the only producer the SOURCE query selects — so this asserts the shape the
// document gives them, and the source query's WHERE clause is what keeps the
// others out. Both halves are needed: a reader that accepted any producer would
// pass this test on this fixture.
func TestInventory_OnlyVulnerabilityProducerFindingsAppear(t *testing.T) {
	doc, err := BuildDocument("inventory", fixtureSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	if len(doc.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %d, want 2", len(doc.Vulnerabilities))
	}
	for _, v := range doc.Vulnerabilities {
		kind := ""
		for _, p := range v.Properties {
			if p.Name == propVulnKind {
				kind = p.Value
			}
		}
		if kind != "known_vulnerability" {
			t.Errorf("vulnerability %s carries kind %q; only the vulnerability producer's findings belong here", v.BOMRef, kind)
		}
	}
}

// TestInventory_UnscoredCVEHasNoRating is the three-valued-logic guard: a CVE
// the catalogue has not scored must carry NO rating, not a 0.0.
//
// A 0.0 in a ratings array reads as "scored, and harmless" to every consumer,
// which is the exact collapse — "didn't check" rendered as "passed" — that this
// codebase has paid for repeatedly.
func TestInventory_UnscoredCVEHasNoRating(t *testing.T) {
	doc, err := BuildDocument("inventory", fixtureSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	for _, v := range doc.Vulnerabilities {
		if v.BOMRef != refVuln+findingNoCVE.String() {
			continue
		}
		if v.ID != "" {
			t.Errorf("a finding with no CVE id emitted id %q", v.ID)
		}
		if len(v.Ratings) != 0 {
			t.Errorf("a finding with no catalogue score emitted %d rating(s): %+v", len(v.Ratings), v.Ratings)
		}
		if v.Source != nil {
			t.Errorf("a finding with no CVE id named a source: %+v", v.Source)
		}
		return
	}
	t.Fatal("the no-CVE finding is missing from the document entirely")
}

// TestInventory_DependencyGraphDropsOutOfScopeEdges: an edge to an asset that
// is not in this document would be a dangling refLinkType — a relationship
// asserted to a component the reader cannot resolve.
func TestInventory_DependencyGraphDropsOutOfScopeEdges(t *testing.T) {
	snap := fixtureSnapshot()
	// Point one edge at an asset that is not in the snapshot.
	snap.Relationships = append(snap.Relationships, Relationship{
		FromAssetID: assetServer,
		ToAssetID:   fixtureTenant, // any id that is not one of the four assets
		Type:        "depends_on",
		Status:      "active",
	})
	doc, err := BuildDocument("inventory", snap, fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	known := map[string]struct{}{}
	for _, c := range doc.Components {
		known[c.BOMRef] = struct{}{}
	}
	for _, s := range doc.Services {
		known[s.BOMRef] = struct{}{}
	}
	for _, dep := range doc.Dependencies {
		for _, target := range dep.DependsOn {
			if _, ok := known[target]; !ok {
				t.Errorf("dependency %s → %s points outside the document", dep.Ref, target)
			}
		}
	}
}

// TestSBOM_HasNoDependencyGraph. An install record says a product is PRESENT on
// a host; it says nothing about anything depending on it. Emitting a graph
// anyway would be an invented relationship in a signed document.
func TestSBOM_HasNoDependencyGraph(t *testing.T) {
	doc, err := BuildDocument("sbom", fixtureSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	if len(doc.Dependencies) != 0 {
		t.Errorf("sbom emitted %d dependency entries; an install is not a dependency", len(doc.Dependencies))
	}
	if len(doc.Components) != 2 {
		t.Fatalf("components = %d, want 2 (one per PRODUCT, not per install)", len(doc.Components))
	}
	// openssl is installed on two assets and must be ONE component with two
	// occurrences — the per-product collapse that keeps a 500-host fleet
	// readable.
	for _, c := range doc.Components {
		if c.Name != "openssl" {
			continue
		}
		if c.Evidence == nil || len(c.Evidence.Occurrences) != 2 {
			t.Errorf("openssl occurrences = %+v, want 2", c.Evidence)
		}
	}
}

// TestHBOM_ContainsOnlyHardwareClasses, and only hw.* facts. Membership is the
// class registry's CycloneDXType, so the HBOM cannot drift from the taxonomy.
func TestHBOM_ContainsOnlyHardwareClasses(t *testing.T) {
	doc, err := BuildDocument("hbom", fixtureSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("components = %d, want 2 (the server and the switch; not the service or the bucket)", len(doc.Components))
	}
	for _, c := range doc.Components {
		if c.Type != "device" {
			t.Errorf("%s has type %q, want device", c.BOMRef, c.Type)
		}
		for _, p := range c.Properties {
			if strings.HasPrefix(p.Name, propFactPrefix) && !strings.HasPrefix(p.Name, propFactPrefix+"hw.") {
				t.Errorf("%s carries non-hardware fact %s — an HBOM that carried os.* would be an inventory snapshot under a narrower name", c.BOMRef, p.Name)
			}
		}
	}
}

// TestInventory_ServiceClassAssetsGoToServices: the class registry says a class
// whose CycloneDXType is "service" is emitted into the services array, not
// components. That is the taxonomy's decision, and this is where it is honoured.
func TestInventory_ServiceClassAssetsGoToServices(t *testing.T) {
	doc, err := BuildDocument("inventory", fixtureSnapshot(), fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	for _, c := range doc.Components {
		if c.BOMRef == refAsset+assetService.String() {
			t.Fatalf("a business_service asset was emitted as a component; its class maps to CycloneDX `service`")
		}
	}
	found := false
	for _, s := range doc.Services {
		if s.BOMRef == refAsset+assetService.String() {
			found = true
		}
	}
	if !found {
		t.Fatal("the business_service asset is missing from the services array")
	}
	// Two endpoints plus the one service-class asset.
	if len(doc.Services) != 3 {
		t.Errorf("services = %d, want 3 (2 endpoints + 1 service-class asset)", len(doc.Services))
	}
}

// TestBuildDocument_RejectsUnknownKind. Emitting an empty document for a kind
// nobody implemented would be indistinguishable from an empty inventory.
func TestBuildDocument_RejectsUnknownKind(t *testing.T) {
	if _, err := BuildDocument("cbom", fixtureSnapshot(), fixtureInput()); err == nil {
		t.Error("BuildDocument(cbom) should refuse — the crypto kind is assembled by the CBOM pipeline, not here")
	}
	if _, err := BuildDocument("nonsense", fixtureSnapshot(), fixtureInput()); err == nil {
		t.Error("BuildDocument(nonsense) should refuse")
	}
}

// TestEndpointIRI covers the format the schema asserts. A bare host:port is not
// an IRI reference, and `AssertFormat` is on in the schema test above — but the
// cases that matter (IPv6, no port) do not all appear in the fixture.
func TestEndpointIRI(t *testing.T) {
	cases := []struct {
		name string
		in   Endpoint
		want string
	}{
		{"tcp v4", Endpoint{Address: "192.0.2.10", Port: 443, HasPort: true, Transport: "tcp"}, "tcp://192.0.2.10:443"},
		{"fqdn wins over address", Endpoint{Address: "192.0.2.10", FQDN: "a.example.com", Port: 443, HasPort: true, Transport: "tcp"}, "tcp://a.example.com:443"},
		{"ipv6 is bracketed", Endpoint{Address: "2001:db8::1", Port: 443, HasPort: true, Transport: "tcp"}, "tcp://[2001:db8::1]:443"},
		{"udp keeps its transport", Endpoint{Address: "192.0.2.10", Port: 161, HasPort: true, Transport: "udp"}, "udp://192.0.2.10:161"},
		// An at-rest face has nothing to address. Emitting a scheme with no
		// port would publish a listening socket that does not exist.
		{"no port yields nothing", Endpoint{Address: "192.0.2.10", Transport: "none"}, ""},
		{"no host yields nothing", Endpoint{Port: 443, HasPort: true, Transport: "tcp"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := endpointIRI(tc.in); got != tc.want {
				t.Errorf("endpointIRI = %q, want %q", got, tc.want)
			}
		})
	}
}

// assertGolden compares against testdata/<name>, or rewrites it under -update.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("updated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run `go test ./internal/xbom -update` to create it)", path, err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Errorf("output differs from %s\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}
