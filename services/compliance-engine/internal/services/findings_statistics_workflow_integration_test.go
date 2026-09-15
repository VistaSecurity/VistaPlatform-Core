package services

// The WORKFLOW scope of the Dashboard's "Critical findings" number, against a
// real database.
//
// findings_statistics_scope_test.go pins the SQL text and the tile's wording;
// neither proves the predicate does anything. A guard on an expression is a
// guard on what someone MEANT — the fix that taught two services' JWT middleware
// to consult the revocation denylist was mutation-tested and merged and never
// ran, because nothing checked the wiring. So this drives GetFindingStatistics
// over rows in every workflow status and reads the number the tile would show.
//
// What it pins:
//
//  1. a SUPPRESSED Critical is not in the tile's count — the tenant accepted it
//     with a reason, and the Findings page's Open chip hides it, so a tile that
//     counts it sends the user somewhere the row cannot be found;
//  2. a RESOLVED Critical is not in it either;
//  3. NEW and NOTIFIED both are — "open" is not "untouched", and dropping
//     NOTIFIED would hide every finding somebody had merely been told about;
//  4. the COMPLIANCE rollup (severity_counts) is unaffected, because the two
//     rollups answer different questions and a change to one must not silently
//     become a change to both.
//
// Skips unless TEST_DATABASE_URL is set; `make test-integration-db` runs it.

import (
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_GetFindingStatistics_ExcludesResolvedAndSuppressed(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	asset := insertAsset(t, db, tenant, "web-03.example.com")

	// Four non-compliance Criticals, one per workflow status. Non-compliance so
	// no framework licence is in play — this test is about the workflow axis
	// only, and a licence gate failure would look identical from the number.
	//
	// A DISTINCT software install per status, not four findings on one: the
	// schema carries findings_open_subject_uniq over
	// (tenant, producer, kind, subject_type, subject_id, control_id) for every
	// non-ARCHIVED row, so one subject can hold only one of these at a time.
	// That constraint is the same "open" idea this test is about, enforced in
	// the table — worth knowing before reading the fixture as needlessly fussy.
	byStatus := map[string]uuid.UUID{}
	for _, st := range []string{"NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"} {
		install := insertInstall(t, db, tenant, asset, "openssl-"+st, "1.1.1")
		id := insertFindingRow(t, db, tenant, "eol", "software_end_of_life",
			"software_install", install, "critical", 95, "openssl 1.1.1 is end of life ("+st+")")
		if _, err := db.Exec(`UPDATE findings SET workflow_status = $1 WHERE id = $2`, st, id); err != nil {
			t.Fatalf("set workflow_status %s: %v", st, err)
		}
		byStatus[st] = id
	}

	// Guard the FIXTURE before trusting the assertion. If the UPDATE silently
	// did nothing — a status the enum rejects, a typo in the column — every row
	// would still be NEW and "2" would be arithmetic rather than evidence.
	for st, id := range byStatus {
		var got string
		if err := db.Get(&got, `SELECT workflow_status FROM findings WHERE id = $1`, id); err != nil {
			t.Fatalf("read back workflow_status for %s: %v", st, err)
		}
		if got != st {
			t.Fatalf("fixture did not take: finding %s has workflow_status %q, want %q — "+
				"the assertions below would be measuring nothing", id, got, st)
		}
	}

	stats, err := svc.GetFindingStatistics(tenant)
	if err != nil {
		t.Fatalf("GetFindingStatistics: %v", err)
	}

	if stats.AllProducerSeverityCounts.Critical != 2 {
		t.Errorf("all_producer_severity_counts.critical = %d, want 2 (NEW + NOTIFIED).\n"+
			"This is the Dashboard's \"Critical findings\" tile. A RESOLVED or SUPPRESSED finding in it "+
			"means the number does not fall when the tenant triages, and the Findings page the tile links "+
			"to opens on its Open chip — so the row driving the count is the one row the destination "+
			"will not show.", stats.AllProducerSeverityCounts.Critical)
	}

	// The compliance rollup counts every ACTIVE row whatever its workflow
	// status, and is deliberately NOT narrowed with it. Asserted so a future
	// edit that "makes them consistent" has to do it on purpose: they answer
	// different questions, and this one has no UI consumer to notice.
	if stats.SeverityCounts.Critical != 0 {
		t.Errorf("severity_counts.critical = %d, want 0 — these are eol findings, not failed "+
			"framework controls", stats.SeverityCounts.Critical)
	}

	// The workflow tallies are a separate rollup and must still see all four,
	// so this narrowing cannot be mistaken for rows going missing from the
	// table.
	if stats.ResolvedFindings != 0 || stats.SuppressedFindings != 0 {
		t.Logf("workflow tallies are compliance-scoped: resolved=%d suppressed=%d",
			stats.ResolvedFindings, stats.SuppressedFindings)
	}
}
