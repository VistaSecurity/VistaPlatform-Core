package services

// The Dashboard's "Critical findings" tile and the rows its link opens, driven
// against a real database and compared as SETS.
//
// Everything else guarding this pairing compares one number to another, or one
// piece of source text to another:
//
//   - TestIntegration_GetFindingStatistics_ExcludesResolvedAndSuppressed reads
//     the tile's number and asserts it is 2;
//   - TestDashboardCriticalTile_RouteCarriesItsNarrowings asserts the route
//     names the rung the tile reads;
//   - the frontend guards assert the page reads the parameter and sends it on.
//
// None of them would notice the tile counting three rows while the destination
// listed three DIFFERENT rows. Equal counts are the weakest evidence of one
// set — it is exactly the coincidence a tenant reports as "the number is right
// but my finding is not there", which is the bug this whole pairing exists to
// prevent, one layer in.
//
// So this one seeds a tenant whose findings differ on every axis the two
// surfaces narrow on — producer, severity, workflow status, tenant — takes the
// severity filter FROM THE TILE'S OWN ROUTE (parsed out of
// dashboard-metrics.ts, not typed here, so breaking the link breaks this too),
// asks the list endpoint for it, applies the page's Open chip the way the page
// does, and compares the resulting id set to the ids it seeded. Then, and only
// then, it checks the tile's number against that set's size.
//
// It runs as the RLS app role — the role the service actually connects as —
// because the owner pool is not subject to RLS and a policy that hid rows from
// one surface and not the other would be invisible under it.
//
// Skips unless TEST_DATABASE_URL is set; `make test-integration-db` runs it.

import (
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// tileLinkSeverity is the severity the Dashboard's critical tile links through,
// read out of DASHBOARD_CRITICAL_FINDINGS_ROUTE rather than written here.
//
// The point of this test is that the tile's number and the page its LINK opens
// describe one set. A hand-typed "critical" would keep passing after someone
// dropped `?severity=critical` from the route, which is precisely the drift
// being guarded.
func tileLinkSeverity(t *testing.T) string {
	t.Helper()
	metrics := readRepoFile(t, statsRepoRoot(t), dashboardMetricsRel)
	m := reCritRoute.FindStringSubmatch(metrics)
	if m == nil {
		t.Fatalf("could not find DASHBOARD_CRITICAL_FINDINGS_ROUTE in %s", dashboardMetricsRel)
	}
	route := m[1]
	i := strings.Index(route, "?")
	if i < 0 {
		t.Fatalf("the tile's route %q carries no query string, so it names no severity — "+
			"the page it opens would list every rung while the tile counts one", route)
	}
	q, err := url.ParseQuery(route[i+1:])
	if err != nil {
		t.Fatalf("tile route %q has an unparseable query: %v", route, err)
	}
	sev := q.Get("severity")
	if sev == "" {
		t.Fatalf("the tile's route %q carries no `severity` parameter. The tile counts one rung of the "+
			"ladder; its destination lists every severity unless the link says otherwise.", route)
	}
	return sev
}

// pageOpenRows applies the Findings page's `Open` chip to a list result.
//
// The page fetches every workflow status and drops these two in the browser
// (isOpenWf, frontend-v2/src/sections/findings/model.ts), where the tile's
// rollup drops them in SQL (FindingListFilters.WorkflowOpen). Two spellings of
// one idea in two languages is the reason this test exists; this function is
// the TypeScript one, restated so the comparison is between what the tenant
// would actually see and what the tile would actually say.
func pageOpenRows(rows []findingRowID) []uuid.UUID {
	out := []uuid.UUID{}
	for _, r := range rows {
		if r.workflow == "RESOLVED" || r.workflow == "SUPPRESSED" {
			continue
		}
		out = append(out, r.id)
	}
	return out
}

type findingRowID struct {
	id       uuid.UUID
	workflow string
}

func sortedIDs(ids []uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	sort.Strings(out)
	return out
}

func TestIntegration_CriticalTile_AndTheRowsItsLinkOpens_AreOneSet(t *testing.T) {
	owner := testdb.Connect(t) // skips if TEST_DATABASE_URL unset
	ownerDB := sqlx.NewDb(owner, "postgres")
	tenant := testdb.NewTenant(t, owner)
	ownerSvc := &FindingsService{db: ownerDB}

	asset := insertAsset(t, ownerDB, tenant, "web-04.example.com")

	// ── the rows that must be in BOTH ────────────────────────────────────────
	// Three producers, two workflow statuses, one severity. "Open" is not
	// "untouched": a NOTIFIED finding is one somebody has merely been told
	// about, and dropping it would empty the tile of everything under triage.
	want := map[string]uuid.UUID{}

	eolInstall := insertInstall(t, ownerDB, tenant, asset, "openssl-open", "1.1.1")
	want["eol/NEW"] = insertFindingRow(t, ownerDB, tenant, "eol", "software_end_of_life",
		"software_install", eolInstall, "critical", 95, "openssl 1.1.1 is end of life")

	vulnInstall := insertInstall(t, ownerDB, tenant, asset, "log4j-open", "2.14.0")
	vulnID := insertFindingRow(t, ownerDB, tenant, "vulnerability", "known_vulnerability",
		"software_install", vulnInstall, "critical", 98, "log4j 2.14.0 is affected by CVE-2021-44228")
	mustSetWorkflow(t, ownerDB, vulnID, "NOTIFIED")
	want["vulnerability/NOTIFIED"] = vulnID

	// Compliance, on an ACTIVATED framework — the producer the licence gate
	// applies to. Without it, "every producer" would be proven for the
	// producers that have no gate to fail.
	_, newLicensedControl := seedPublishedFramework(t, ownerDB, tenant, "tile-set-lic", true)
	licControl, licSubject := newLicensedControl("critical"), uuid.New()
	licFinding := activeViolation(licControl, licSubject)
	licFinding.Severity = "critical"
	mustUpsert(t, ownerSvc, tenant, licControl, licSubject, licFinding, "ACTIVE")
	want["compliance/NEW"] = licFinding.ID

	// ── the rows that must be in NEITHER ─────────────────────────────────────
	// One per axis, so a narrowing that silently stops applying has a row
	// waiting to walk through the hole it leaves.

	// WORKFLOW: suppressed with a reason, and resolved. The tenant has dealt
	// with these; the page's Open chip hides them, so the tile must not count
	// them.
	supInstall := insertInstall(t, ownerDB, tenant, asset, "openssl-suppressed", "1.1.1")
	supID := insertFindingRow(t, ownerDB, tenant, "eol", "software_end_of_life",
		"software_install", supInstall, "critical", 95, "accepted, compensating control")
	mustSetWorkflow(t, ownerDB, supID, "SUPPRESSED")

	resInstall := insertInstall(t, ownerDB, tenant, asset, "openssl-resolved", "1.1.1")
	resID := insertFindingRow(t, ownerDB, tenant, "eol", "software_end_of_life",
		"software_install", resInstall, "critical", 95, "upgraded to 3.0")
	mustSetWorkflow(t, ownerDB, resID, "RESOLVED")

	// SEVERITY: an open High. In the page's unfiltered stream, never in the
	// Critical rung the tile counts.
	highInstall := insertInstall(t, ownerDB, tenant, asset, "nginx-high", "1.18.0")
	insertFindingRow(t, ownerDB, tenant, "eol", "software_end_of_life",
		"software_install", highInstall, "high", 70, "nginx 1.18.0 is end of life")

	// TENANT: another tenant's open Critical, written by the owner pool.
	other := testdb.NewTenant(t, owner)
	otherAsset := insertAsset(t, ownerDB, other, "not-yours.example.com")
	insertFindingRow(t, ownerDB, other, "eol", "os_end_of_life",
		"asset", otherAsset, "critical", 95, "another tenant's end-of-life host")

	// Guard the FIXTURE before trusting the comparison: an UPDATE that silently
	// did nothing would leave every row NEW, and "3 == 3" would then be
	// arithmetic rather than evidence.
	for id, wantWf := range map[uuid.UUID]string{supID: "SUPPRESSED", resID: "RESOLVED", vulnID: "NOTIFIED"} {
		var got string
		if err := ownerDB.Get(&got, `SELECT workflow_status FROM findings WHERE id = $1`, id); err != nil {
			t.Fatalf("read back workflow_status for %s: %v", id, err)
		}
		if got != wantWf {
			t.Fatalf("fixture did not take: finding %s has workflow_status %q, want %q", id, got, wantWf)
		}
	}

	// ── the two surfaces, as the service actually connects ───────────────────
	app := testdb.ConnectAsAppRole(t, owner)
	appSvc := &FindingsService{db: sqlx.NewDb(app, "postgres")}

	// THE PAGE. `?severity=<the tile's rung>` is what the link carries and what
	// the page hands the server; the Open chip is applied over the result the
	// way the page applies it.
	rows, total, err := appSvc.ListFindings(tenant, FindingListFilters{Severity: tileLinkSeverity(t)}, 1, 200)
	if err != nil {
		t.Fatalf("ListFindings as %s: %v", testdb.RLSAppRole, err)
	}
	listed := make([]findingRowID, 0, len(rows))
	for _, r := range rows {
		listed = append(listed, findingRowID{id: r.ID, workflow: strings.ToUpper(r.WorkflowStatus)})
	}
	if total != len(rows) {
		t.Fatalf("fixture outgrew one page: total=%d rows=%d — this test compares SETS and must see them all",
			total, len(rows))
	}
	pageIDs := pageOpenRows(listed)

	// THE TILE.
	stats, err := appSvc.GetFindingStatistics(tenant)
	if err != nil {
		t.Fatalf("GetFindingStatistics as %s: %v", testdb.RLSAppRole, err)
	}

	// ── one set ──────────────────────────────────────────────────────────────
	wantIDs := make([]uuid.UUID, 0, len(want))
	for _, id := range want {
		wantIDs = append(wantIDs, id)
	}
	gotS, wantS := sortedIDs(pageIDs), sortedIDs(wantIDs)
	if strings.Join(gotS, ",") != strings.Join(wantS, ",") {
		t.Errorf("the rows the tile's link opens are not the rows it should show.\n"+
			" got: %v\nwant: %v (%v)\n"+
			"Seeded: 3 open Criticals across eol/vulnerability/compliance; excluded by design are one "+
			"SUPPRESSED Critical, one RESOLVED Critical, one open High, and another tenant's Critical.",
			gotS, wantS, keysOf(want))
	}

	if stats.AllProducerSeverityCounts.Critical != len(wantIDs) {
		t.Errorf("the tile says %d and its destination shows %d rows.\n"+
			"These are the same question asked twice — every producer's OPEN Criticals — and a tenant who "+
			"clicks the number and counts the rows is entitled to the same answer.",
			stats.AllProducerSeverityCounts.Critical, len(wantIDs))
	}
	// Said separately from the equality above so a failure reads as what it is:
	// the count agreeing with a WRONG set is the coincidence this test exists
	// to catch, and it can only be reported once both have been checked.
	if stats.AllProducerSeverityCounts.Critical != len(pageIDs) {
		t.Errorf("tile count %d vs %d rows on the page it opens (set: %v)",
			stats.AllProducerSeverityCounts.Critical, len(pageIDs), gotS)
	}
}

func keysOf(m map[string]uuid.UUID) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustSetWorkflow(t *testing.T, db *sqlx.DB, id uuid.UUID, status string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE findings SET workflow_status = $1 WHERE id = $2`, status, id); err != nil {
		t.Fatalf("set workflow_status %s on %s: %v", status, id, err)
	}
}
