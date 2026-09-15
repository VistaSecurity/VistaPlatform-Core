package services

// The two indexes behind the class-proposal queue, against a real Postgres.
//
// Both were wrong in the same quiet way: an index that exists, is used by
// nothing, and prevents something it was never meant to prevent.
//
//  1. `idx_asset_history_pending_class_proposal` keyed on
//     `changes_json->>'proposed_class_key'` alone. A CONFLICT proposal names no
//     class, so it stores `""` — present, because the partial predicate needs
//     the key to be there, and empty. Every conflict on an asset therefore
//     collapsed onto the key `(tenant, asset, '')` and the second one was
//     swallowed by the writer's `ON CONFLICT DO NOTHING`. An asset the catalogue
//     argued over twice showed the reviewer the first disagreement and dropped
//     the second, silently, for as long as the first stayed pending.
//
//  2. The Approvals LIST query — `action`, `kind`, pending — says nothing about
//     `proposed_class_key`, so the planner could not prove the query's predicate
//     implied the unique index's, and every page seq-scanned an append-only
//     table that grows without bound.
//
// Skips without TEST_DATABASE_URL. RFC 5737 documentation addresses throughout.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// Two DIFFERENT conflicts about one asset are two questions, and a reviewer
// gets both.
//
// MUTATION: revert the index expression to
// `(tenant_id, asset_id, (changes_json ->> 'proposed_class_key'))` and the
// second insert is swallowed, leaving one row.
func TestIntegration_ClassProposalIndex_TwoDifferentConflictsBothQueue(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	assetID := seedPlainAsset(t, svc, db, tenant, "argued-over", "192.0.2.81", "98:3b:7c:dd:ee:01")

	insertConflictProposal(t, db, tenant, assetID, []string{"printer", "multifunction_device"})
	insertConflictProposal(t, db, tenant, assetID, []string{"router", "switch"})

	if n := countPendingConflicts(t, db, tenant, assetID); n != 2 {
		t.Errorf("%d pending conflict proposals, want 2 — 'printer or multifunction device?' "+
			"and 'router or switch?' are different questions, and suppressing the second "+
			"means a disagreement nobody is ever asked about", n)
	}
}

// The SAME conflict, arriving again on the next coalescing window, is still one
// question.
//
// The other polarity, and the one an index that simply stopped deduplicating
// would get wrong: the evidence behind a conflict never changes (the
// disagreement is in the CATALOGUE), so without this the queue refills with the
// identical row on every poll.
func TestIntegration_ClassProposalIndex_TheSameConflictIsStillOneQuestion(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	assetID := seedPlainAsset(t, svc, db, tenant, "argued-once", "192.0.2.82", "98:3b:7c:dd:ee:02")

	insertConflictProposal(t, db, tenant, assetID, []string{"printer", "multifunction_device"})
	// Same pair, opposite order: the engine returns tied classes in the order
	// they SCORED, and a rule edit that changes only the order has not changed
	// the disagreement.
	insertConflictProposal(t, db, tenant, assetID, []string{"multifunction_device", "printer"})

	if n := countPendingConflicts(t, db, tenant, assetID); n != 1 {
		t.Errorf("%d pending conflict proposals for one repeated disagreement, want 1 — the "+
			"conflict key is sorted precisely so the order the classes scored in does not "+
			"make a second question", n)
	}
}

// The Approvals queue's own read uses an index.
//
// EXPLAIN with seq scans ENABLED, on a table with enough rows for the planner to
// have a real choice. Turning `enable_seqscan` off would make this pass against
// any index at all, including one whose predicate the planner cannot use — which
// is the exact bug being fixed.
func TestIntegration_ClassProposalIndex_TheQueueQueryIsCovered(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	assetID := seedPlainAsset(t, svc, db, tenant, "queue-load", "192.0.2.83", "98:3b:7c:dd:ee:03")

	// Enough rows that a seq scan is the expensive option, and mostly NOT
	// proposals — which is the shape asset_history really has, and the shape a
	// partial index is worth anything on.
	bulkAssetHistory(t, db, tenant, assetID, 4000)
	for i := range 40 {
		insertClassProposal(t, db, tenant, assetID, fmt.Sprintf("server_%d", i))
	}
	analyze(t, db, "asset_history")

	plan := explainQueueQuery(t, db, tenant)
	t.Logf("EXPLAIN of the Approvals queue query:\n%s", plan)
	if !strings.Contains(plan, "idx_asset_history_class_proposal_queue") {
		t.Errorf("the Approvals queue query does not use its index. Plan:\n%s\n\n"+
			"A partial index is only usable when the planner can PROVE the query's "+
			"predicate implies the index's; if this regressed, check that the two "+
			"predicates still match verbatim.", plan)
	}
}

// --- helpers ---------------------------------------------------------------

// insertConflictProposal writes the row the shared writer writes for a
// conflict: no class, the tied classes, and the sorted conflict key.
//
// Written through SQL rather than by provoking a real rule conflict, because a
// conflict needs two curated rules that disagree and seeding those would make
// the test about the catalogue rather than the index. The PAYLOAD is the
// writer's, which is what the index reads.
func insertConflictProposal(t *testing.T, db *database.DB, tenant, assetID uuid.UUID, classes []string) {
	t.Helper()
	sorted := append([]string(nil), classes...)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	payload := fmt.Sprintf(
		`{"kind":"class_proposal","proposed_class_key":"","conflicting_classes":["%s"],"conflict_key":"%s","status":"pending"}`,
		strings.Join(classes, `","`), strings.Join(sorted, "|"))
	insertProposalRow(t, db, tenant, assetID, payload)
}

// insertClassProposal writes an ordinary (non-conflict) pending proposal.
func insertClassProposal(t *testing.T, db *database.DB, tenant, assetID uuid.UUID, classKey string) {
	t.Helper()
	payload := fmt.Sprintf(
		`{"kind":"class_proposal","proposed_class_key":"%s","status":"pending"}`, classKey)
	insertProposalRow(t, db, tenant, assetID, payload)
}

func insertProposalRow(t *testing.T, db *database.DB, tenant, assetID uuid.UUID, payload string) {
	t.Helper()
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`
			INSERT INTO asset_history (tenant_id, asset_id, source, action, changes_json)
			VALUES ($1, $2, 'classifier:rules', 'class_proposed', $3::jsonb)
			ON CONFLICT DO NOTHING`, tenant, assetID, payload)
		return e
	}); err != nil {
		t.Fatalf("insert proposal row: %v", err)
	}
}

func countPendingConflicts(t *testing.T, db *database.DB, tenant, assetID uuid.UUID) int {
	t.Helper()
	var n int
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT count(*) FROM asset_history
			 WHERE tenant_id = $1 AND asset_id = $2
			   AND action = 'class_proposed'
			   AND COALESCE(changes_json->>'proposed_class_key', '') = ''
			   AND COALESCE(changes_json->>'status', 'pending') = 'pending'`,
			tenant, assetID).Scan(&n)
	}); err != nil {
		t.Fatalf("count conflicts: %v", err)
	}
	return n
}

// bulkAssetHistory writes n ordinary history rows, so the proposal rows are the
// small minority a partial index is for.
func bulkAssetHistory(t *testing.T, db *database.DB, tenant, assetID uuid.UUID, n int) {
	t.Helper()
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`
			INSERT INTO asset_history (tenant_id, asset_id, source, action, changes_json)
			SELECT $1, $2, 'sensor', 'updated', '{"kind":"noise"}'::jsonb
			  FROM generate_series(1, $3)`, tenant, assetID, n)
		return e
	}); err != nil {
		t.Fatalf("bulk asset history: %v", err)
	}
}

// analyze runs ANALYZE as the OWNER. The tenant-scoped app role cannot, and a
// planner working off default estimates would choose a seq scan on a table it
// believes has ten rows — which would fail this test for a reason that has
// nothing to do with the index.
func analyze(t *testing.T, db *database.DB, table string) {
	t.Helper()
	if _, err := db.Exec("ANALYZE " + table); err != nil {
		t.Fatalf("analyze %s: %v", table, err)
	}
}

// explainQueueQuery EXPLAINs the verbatim predicate ListPending runs.
func explainQueueQuery(t *testing.T, db *database.DB, tenant uuid.UUID) string {
	t.Helper()
	var lines []string
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(`
			EXPLAIN SELECT id FROM asset_history
			 WHERE `+classProposalPredicate+`
			 ORDER BY created_at DESC LIMIT 50`, tenant)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var line string
			if e := rows.Scan(&line); e != nil {
				return e
			}
			lines = append(lines, line)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("explain: %v", err)
	}
	return strings.Join(lines, "\n")
}
