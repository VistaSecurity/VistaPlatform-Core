package services

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/sbom"
	"github.com/vistasecurity/vistaplatform/shared/software"
)

func plannedIdentities(rows []plannedInstall) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.identity)
	}
	return out
}

// The CycloneDX shape: the subject sits OUTSIDE the component list, so it has
// to be added or the asset created from a document shows nothing.
func TestSBOMPlanAddsACycloneDXSubjectThatIsNotAComponent(t *testing.T) {
	doc := &sbom.Document{
		Subject:    &software.Product{Name: "billing", Version: "2.1.0"},
		SubjectRef: "pkg:billing",
		Components: []sbom.Component{
			{Product: software.Product{Name: "openssl", Version: "3.0.13"}, BOMRef: "c1"},
		},
	}
	res := &SBOMIngestResult{}
	rows := (&SBOMIngestService{}).plan(doc, res)

	want := []string{"openssl@3.0.13", "billing@2.1.0"}
	if got := plannedIdentities(rows); !equalStrings(got, want) {
		t.Fatalf("planned %v, want %v", got, want)
	}
}

// The SPDX shape: the subject IS one of the packages. Writing it again would
// give the subject's product two catalogue rows — which is the asymmetry
// SBOM_INGESTION.md warns a writer about by name.
func TestSBOMPlanDoesNotDoubleWriteAnSPDXSubject(t *testing.T) {
	doc := &sbom.Document{
		Subject:    &software.Product{Name: "billing", Version: "2.1.0"},
		SubjectRef: "SPDXRef-Package-billing",
		Components: []sbom.Component{
			{Product: software.Product{Name: "billing", Version: "2.1.0"}, BOMRef: "SPDXRef-Package-billing"},
			{Product: software.Product{Name: "openssl", Version: "3.0.13"}, BOMRef: "SPDXRef-Package-openssl"},
		},
	}
	rows := (&SBOMIngestService{}).plan(doc, &SBOMIngestResult{})
	want := []string{"billing@2.1.0", "openssl@3.0.13"}
	if got := plannedIdentities(rows); !equalStrings(got, want) {
		t.Fatalf("planned %v, want %v — the subject must not be written twice", got, want)
	}
}

// Deduplication is by IDENTITY, not by bom-ref: a document may list one purl
// under two refs, and the catalogue has one row for it.
func TestSBOMPlanDeduplicatesByIdentity(t *testing.T) {
	doc := &sbom.Document{
		Components: []sbom.Component{
			{Product: software.Product{Name: "openssl", Version: "3.0.13", PURL: "pkg:generic/openssl@3.0.13"}, BOMRef: "a"},
			{Product: software.Product{Name: "OpenSSL", Version: "3.0.13", PURL: "pkg:generic/openssl@3.0.13"}, BOMRef: "b"},
		},
	}
	rows := (&SBOMIngestService{}).plan(doc, &SBOMIngestResult{})
	if len(rows) != 1 {
		t.Fatalf("planned %d rows, want 1: %v", len(rows), plannedIdentities(rows))
	}
}

// `scope: excluded` says the component is NOT in the artefact. Recording it as
// an install would be a false positive in an inventory whose whole job is to be
// believed — and the count is reported so the user can reconcile it.
func TestSBOMPlanDropsExcludedComponents(t *testing.T) {
	doc := &sbom.Document{
		Components: []sbom.Component{
			{Product: software.Product{Name: "openssl", Version: "3.0.13"}, BOMRef: "a", Scope: "required"},
			{Product: software.Product{Name: "junit", Version: "5.10.0"}, BOMRef: "b", Scope: "excluded"},
			{Product: software.Product{Name: "mockito", Version: "5.0.0"}, BOMRef: "c", Scope: "EXCLUDED"},
		},
	}
	res := &SBOMIngestResult{}
	rows := (&SBOMIngestService{}).plan(doc, res)

	if got := plannedIdentities(rows); !equalStrings(got, []string{"openssl@3.0.13"}) {
		t.Fatalf("planned %v, want only the required component", got)
	}
	if res.ComponentsExcluded != 2 {
		t.Fatalf("components_excluded = %d, want 2 — the count is how a user reconciles our number with theirs",
			res.ComponentsExcluded)
	}
}

// An EXCLUDED component still registers its bom-ref, so a subject pointing at
// it is not re-added through the back door.
func TestSBOMPlanExcludedSubjectIsNotResurrected(t *testing.T) {
	doc := &sbom.Document{
		Subject:    &software.Product{Name: "junit", Version: "5.10.0"},
		SubjectRef: "b",
		Components: []sbom.Component{
			{Product: software.Product{Name: "junit", Version: "5.10.0"}, BOMRef: "b", Scope: "excluded"},
		},
	}
	rows := (&SBOMIngestService{}).plan(doc, &SBOMIngestResult{})
	if len(rows) != 0 {
		t.Fatalf("planned %v; an excluded component must not come back as the subject", plannedIdentities(rows))
	}
}

func TestSoftwareSortClause(t *testing.T) {
	// `version` must order on version_sort. Sorting the raw string puts 1.10
	// below 1.9, which inverts every answer the column is used for.
	clause, ok := SoftwareSortClause("version")
	if !ok {
		t.Fatal("`version` is not an accepted sort")
	}
	if !strings.Contains(clause, "version_sort") {
		t.Fatalf("the version sort does not use version_sort: %q", clause)
	}
	if !strings.Contains(clause, "NULLS LAST") {
		t.Fatalf("a NULL version_sort must be ordered explicitly, not left to the planner: %q", clause)
	}

	if _, ok := SoftwareSortClause(""); !ok {
		t.Error("an absent sort must fall back to the default rather than being an error")
	}
	// An allowlist, not an interpolated column name.
	if _, ok := SoftwareSortClause("name; DROP TABLE software_products"); ok {
		t.Error("an unknown sort must be refused")
	}
}

// Every accepted ordering must end in a unique column.
//
// LIMIT/OFFSET partitions a result set only when the ordering is TOTAL. With
// ties the planner may return a tied row on page 1 and again on page 2, or on
// neither, and the choice can differ between two runs of the same statement —
// so a user paging through an asset's software silently sees one library twice
// and never sees another.
//
// The ties here are the common case rather than the corner: one upload writes
// now() into every row it touches inside ONE transaction, so `last_seen` and
// `first_seen` tie across an asset's ENTIRE install list, and `name` ties for
// the two catalogue rows that one product with two purls deliberately produces.
func TestSoftwareSortClausesAreTotalOrderings(t *testing.T) {
	for _, key := range []string{"name", "version", "vendor", "last_seen", "first_seen"} {
		clause, ok := SoftwareSortClause(key)
		if !ok {
			t.Fatalf("%q is not an accepted sort", key)
		}
		if !strings.HasSuffix(clause, "i.id ASC") {
			t.Errorf("sort %q = %q — it must end in the install's primary key, or LIMIT/OFFSET does not partition",
				key, clause)
		}
	}
}

// The search term is a LIKE pattern, and a LIKE pattern the user did not write
// is a search that answers a different question.
//
// Not an injection test — the term is a bound parameter either way. It is about
// `%` and `_` meaning themselves. The purl case is the one that bites: purls
// percent-encode what a namespace may not carry literally, so `@angular/core`
// is published as `pkg:npm/%40angular/core`, and the unescaped form of that
// search reads "anything, then 40angular".
func TestSBOMLikePatternEscapesTheWildcards(t *testing.T) {
	cases := map[string]string{
		"openssl":            `%openssl%`,
		"OpenSSL":            `%openssl%`,
		"pkg:npm/%40angular": `%pkg:npm/\%40angular%`,
		"log4j_core":         `%log4j\_core%`,
		`back\slash`:         `%back\\slash%`,
		"%":                  `%\%%`,
		"_":                  `%\_%`,
	}
	for term, want := range cases {
		if got := likePattern(term); got != want {
			t.Errorf("likePattern(%q) = %q, want %q", term, got, want)
		}
	}
}

func TestSBOMSourceRefNamesTheUpload(t *testing.T) {
	// The producer prefix is what identity.Source.Producer() reads and what the
	// Approvals facet groups on, so it has to be stable.
	ref := sbomSourceRef(uuid.MustParse("1b4e28ba-2fa1-11d2-883f-0016d3cca427"))
	if !strings.HasPrefix(ref, "sbom:") {
		t.Fatalf("source ref %q must start with the `sbom:` producer", ref)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
