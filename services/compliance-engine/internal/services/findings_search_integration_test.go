package services

// Free-text search on the org-wide Findings list.
//
// The Findings page has always had a search box and it used to narrow the rows
// the BROWSER already held. The page fetches at most five pages of 200, so on a
// tenant with more findings than that the box was searching a prefix of the
// stream: a product installed on the 1,200th finding answered "no findings
// match", which is indistinguishable on screen from a clean estate.
//
// That is why the headline test here seeds 1,500 findings and searches for the
// one at position 1,200. A unit test over the WHERE-builder cannot show it —
// the bug was never in the predicate, it was in WHERE the predicate ran — and a
// smaller fixture would pass with the filtering left in the client.
//
// The rest pin the parts of "matched server-side" that are easy to get subtly
// wrong: that `total` and `producer_counts` are narrowed by the same predicate
// as the rows (a page whose total disagrees with its rows is the divergence the
// `has_findings` facet was withdrawn for), that the kind is matched as it is
// PRINTED (underscores opened out, which is exactly the client's `kindLabel`),
// and that `%` and `_` are literal characters rather than wildcards.
//
// Skips unless TEST_DATABASE_URL is set; `make test-integration-db` runs them.

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

func TestIntegration_ListFindings_SearchReachesPastThePageCap(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	asset := insertAsset(t, db, tenant, "web-01.example.com")

	// 1,500 findings. The client's cap is five pages of 200, so anything from
	// 1,001 onwards is unreachable to a browser-side filter.
	const total = 1500
	const needlePosition = 1200
	var needle uuid.UUID
	for i := 1; i <= total; i++ {
		install := insertInstall(t, db, tenant, asset, fmt.Sprintf("package-%04d", i), "1.0.0")
		summary := fmt.Sprintf("package-%04d 1.0.0 is end of life", i)
		if i == needlePosition {
			// A product name nothing else carries. Deliberately NOT a prefix of
			// the generated ones: a search that matched by accident would prove
			// nothing about reaching past the cap.
			summary = "libneedle 3.2.1 is end of life"
		}
		id := insertFindingRow(t, db, tenant, "eol", "software_end_of_life",
			"software_install", install, "medium", 50, summary)
		if i == needlePosition {
			needle = id
		}
	}

	got, matched, err := svc.ListFindings(tenant, FindingListFilters{Search: "libneedle"}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if matched != 1 {
		t.Fatalf("total = %d, want 1 — the search matched %d of %d findings", matched, matched, total)
	}
	if len(got) != 1 || got[0].ID != needle {
		t.Fatalf("got %d rows (%v), want exactly the finding at position %d (%s)",
			len(got), idsOf(got), needlePosition, needle)
	}

	// And the same term through the per-producer tally, which the page's
	// facet chips render. A count computed under a DIFFERENT predicate from the
	// list is how a chip reading 4 opens a page of 1,500.
	counts, err := svc.CountFindingsByProducer(tenant, FindingListFilters{Search: "libneedle"})
	if err != nil {
		t.Fatalf("CountFindingsByProducer: %v", err)
	}
	if counts["eol"] != 1 {
		t.Errorf("producer_counts[eol] = %d under the same search, want 1 — the chip and the list describe different sets", counts["eol"])
	}
}

func TestIntegration_ListFindings_SearchMatchesSummarySubjectLabelAndKind(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	asset := insertAsset(t, db, tenant, "db-07.example.com")

	summaryHit := insertFindingRow(t, db, tenant, "eol", "os_end_of_life",
		"asset", asset, "high", 70, "db-07 runs an end-of-life operating system")

	// A row whose SUMMARY does not carry the term but whose subject label does.
	labelHit := insertFindingRow(t, db, tenant, "vulnerability", "known_vulnerability",
		"software_install", insertInstall(t, db, tenant, asset, "zlib", "1.2.11"),
		"critical", 95, "an advisory matched this install")
	if _, err := db.Exec(`UPDATE findings SET subject_label = 'zlib 1.2.11' WHERE id = $1`, labelHit); err != nil {
		t.Fatalf("set subject_label: %v", err)
	}

	cases := []struct {
		term string
		want uuid.UUID
		why  string
	}{
		{"operating system", summaryHit, "the summary is the row's headline and must be searchable"},
		{"zlib", labelHit, "the subject label is what the row PRINTS as the thing; a search box that ignores it looks broken"},
		// The kind, matched as the client prints it. `kindLabel` is literally
		// underscores→spaces, so "end of life" has to find
		// `software_end_of_life` — typing what is on screen must match it.
		{"end of life", summaryHit, "the kind must be matched with its underscores opened out, the way it is displayed"},
	}
	for _, tc := range cases {
		got, _, err := svc.ListFindings(tenant, FindingListFilters{Search: tc.term}, 1, 50)
		if err != nil {
			t.Fatalf("ListFindings(%q): %v", tc.term, err)
		}
		if !containsID(got, tc.want) {
			t.Errorf("searching %q returned %v, missing %s — %s", tc.term, idsOf(got), tc.want, tc.why)
		}
	}

	// A term matching nothing returns nothing, rather than everything. The
	// failure mode of a badly built LIKE is a predicate that is always true.
	got, n, err := svc.ListFindings(tenant, FindingListFilters{Search: "log4shell"}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if n != 0 || len(got) != 0 {
		t.Errorf("an unmatched term returned %d rows (total %d); the predicate is not narrowing", len(got), n)
	}
}

// The HOST, which is the most natural thing to type on this page.
//
// made a software_install finding render its PACKAGE as the title with
// the host as a context line underneath — nine end-of-life packages on one
// machine must not be nine identical rows — and pinned that the search still
// finds such a finding by its host. When the search moved to the server that
// assertion had to move with it, or the behaviour would have been deleted in
// silence: nothing in an end-of-life summary carries the hostname.
//
// The predicate is an EXISTS in the SHARED WHERE, not a column of the page
// query's join, so the rows, the total and the per-producer counts all narrow
// together. This checks all three.
func TestIntegration_ListFindings_SearchMatchesTheHost(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	host := insertAsset(t, db, tenant, "web-01.internal")
	other := insertAsset(t, db, tenant, "db-09.internal")

	// A software finding on web-01 whose summary names only the package.
	onHost := insertFindingRow(t, db, tenant, "eol", "software_end_of_life",
		"software_install", insertInstall(t, db, tenant, host, "nginx", "1.20.0"),
		"medium", 50, "nginx 1.20.0 is end of life")
	// A finding whose subject IS an asset, reached by the same arm.
	assetSubject := insertFindingRow(t, db, tenant, "hygiene", "no_owner",
		"asset", host, "low", 0, "this asset has no owner")
	// And one on a different host, which must NOT come back. A different
	// version, because a product identity is (name, version) and two installs
	// of the same one would collide on the catalogue's uniqueness constraint.
	insertFindingRow(t, db, tenant, "eol", "software_end_of_life",
		"software_install", insertInstall(t, db, tenant, other, "nginx", "1.20.1"),
		"medium", 50, "nginx 1.20.1 is end of life")

	got, n, err := svc.ListFindings(tenant, FindingListFilters{Search: "web-01"}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings(host): %v", err)
	}
	if n != 2 || !containsID(got, onHost) || !containsID(got, assetSubject) {
		t.Fatalf("searching the hostname returned %d rows (%v), want the two findings on web-01 — "+
			"the host is on screen as the context line and must be searchable", n, idsOf(got))
	}

	counts, err := svc.CountFindingsByProducer(tenant, FindingListFilters{Search: "web-01"})
	if err != nil {
		t.Fatalf("CountFindingsByProducer: %v", err)
	}
	if counts["eol"] != 1 || counts["hygiene"] != 1 {
		t.Errorf("producer_counts under the same search = %v, want eol:1 hygiene:1 — the chips and the list "+
			"describe different sets", counts)
	}

	// The package name still matches too, and matches BOTH hosts' findings —
	// the host arm narrows nothing it should not.
	if _, n, err = svc.ListFindings(tenant, FindingListFilters{Search: "nginx"}, 1, 50); err != nil {
		t.Fatalf("ListFindings(package): %v", err)
	}
	if n != 2 {
		t.Errorf("searching the package returned %d findings, want both installs of it", n)
	}
}

// `%` and `_` are LITERAL. Unescaped they are LIKE wildcards, so a person
// searching for "99% CPU" or a term with an underscore would silently match
// every finding the tenant has while the box read as a narrowing search.
func TestIntegration_ListFindings_SearchWildcardsAreLiteral(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	asset := insertAsset(t, db, tenant, "app-02.example.com")

	literal := insertFindingRow(t, db, tenant, "hygiene", "no_owner",
		"asset", asset, "low", 0, "app-02 reports 99% disk usage and has no owner")
	insertFindingRow(t, db, tenant, "hygiene", "no_class",
		"asset", asset, "low", 0, "app-02 has no class")
	// A Windows path, which is how a backslash reaches a summary in practice.
	backslash := insertFindingRow(t, db, tenant, "hygiene", "no_location",
		"asset", asset, "low", 0, `app-02 exposes C:\Windows\System32 over SMB`)

	// The bare wildcard matches NOTHING: no summary here contains a literal
	// percent sign followed by nothing. If it were interpreted, it would match
	// both rows.
	got, n, err := svc.ListFindings(tenant, FindingListFilters{Search: "%"}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if n != 1 || !containsID(got, literal) {
		t.Errorf("searching %%%% returned %d rows (%v), want only the one whose text contains a literal percent sign", n, idsOf(got))
	}

	// An underscore is one literal character, not "any character".
	if _, n, err = svc.ListFindings(tenant, FindingListFilters{Search: "app_02"}, 1, 50); err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if n != 0 {
		t.Errorf("searching app_02 matched %d rows; the underscore was treated as a wildcard and matched app-02", n)
	}

	// The BACKSLASH, which is the one the other two depend on. Postgres's
	// default LIKE escape character is `\`, so escaping `%` and `_` without
	// escaping the backslash first turns a trailing backslash into an escape of
	// the pattern's own closing `%` — the term `\` would then mean "contains a
	// literal percent sign" and return the 99% row instead of the path.
	got, n, err = svc.ListFindings(tenant, FindingListFilters{Search: `\`}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings(backslash): %v", err)
	}
	if n != 1 || !containsID(got, backslash) {
		t.Errorf("searching a lone backslash returned %d rows (%v), want only the summary that contains one — "+
			"the backslash is being read as LIKE's escape character rather than as a character", n, idsOf(got))
	}

	// And a term whose backslash is in the middle still finds the path it names.
	if got, n, err = svc.ListFindings(tenant, FindingListFilters{Search: `C:\Windows`}, 1, 50); err != nil {
		t.Fatalf("ListFindings(path): %v", err)
	}
	if n != 1 || !containsID(got, backslash) {
		t.Errorf("searching %q returned %d rows (%v), want the row whose summary carries that path", `C:\Windows`, n, idsOf(got))
	}
}

// Whitespace is not a search. A box the user cleared to spaces must widen back
// to the whole list rather than filter on nothing and return it anyway — the
// two look the same until the term is `%   %`.
func TestIntegration_ListFindings_BlankSearchIsNoFilter(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	asset := insertAsset(t, db, tenant, "edge-01.example.com")
	insertFindingRow(t, db, tenant, "hygiene", "no_owner", "asset", asset, "low", 0, "edge-01 has no owner")

	for _, term := range []string{"", "   ", "\t"} {
		_, n, err := svc.ListFindings(tenant, FindingListFilters{Search: term}, 1, 50)
		if err != nil {
			t.Fatalf("ListFindings(%q): %v", term, err)
		}
		if n != 1 {
			t.Errorf("a blank search (%q) returned %d findings, want the whole list (1)", term, n)
		}
	}
}

// --- small helpers ---------------------------------------------------------

func containsID(rows []models.ComplianceFinding, want uuid.UUID) bool {
	for _, r := range rows {
		if r.ID == want {
			return true
		}
	}
	return false
}

func idsOf(rows []models.ComplianceFinding) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}
