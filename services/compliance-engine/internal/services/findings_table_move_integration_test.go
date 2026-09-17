package services

// Workstream 3.1: the compliance producer moved off `compliance_findings` and
// onto the one `findings` table every producer writes (ADR-0005 D3). The table
// was replaced outright — no view, no backfill, no dual-write (ADR-0007).
//
// These are the properties that move with it and that nothing else pins.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// The identity of a compliance finding is (control, SUBJECT), not the subject
// alone — two controls failing on one server are two things to triage, assign
// and raise a ticket at.
//
// The unified table's open-row unique index is
// `(tenant_id, producer, kind, subject_type, subject_id, control_id)` with
// NULLS NOT DISTINCT. Drop `control_id` from it and this test fails: the second
// control's INSERT hits the first control's row through ON CONFLICT, updates it,
// and one of the two violations disappears without an error anywhere.
func TestIntegration_Findings_TwoControlsOnOneSubjectAreTwoFindings(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	subject := uuid.New()
	controlA, controlB := uuid.New(), uuid.New()

	mustUpsert(t, svc, tenant, controlA, subject, activeViolation(controlA, subject), "ACTIVE")
	mustUpsert(t, svc, tenant, controlB, subject, activeViolation(controlB, subject), "ACTIVE")

	var rows int
	if err := db.Get(&rows,
		`SELECT count(*) FROM findings WHERE tenant_id = $1 AND subject_id = $2`, tenant, subject); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 2 {
		t.Fatalf("two controls failing on one subject produced %d finding(s), want 2 — the "+
			"(control, subject) pair is the unit of reconciliation, and collapsing it loses a "+
			"violation silently", rows)
	}

	// And re-running converges rather than growing: the same two pairs, twice.
	mustUpsert(t, svc, tenant, controlA, subject, activeViolation(controlA, subject), "ACTIVE")
	mustUpsert(t, svc, tenant, controlB, subject, activeViolation(controlB, subject), "ACTIVE")
	if err := db.Get(&rows,
		`SELECT count(*) FROM findings WHERE tenant_id = $1 AND subject_id = $2`, tenant, subject); err != nil {
		t.Fatalf("recount: %v", err)
	}
	if rows != 2 {
		t.Fatalf("a second converged pass produced %d rows, want 2", rows)
	}
}

// Every row this producer writes declares itself. Without `producer`/`kind` on
// the row, the first other producer to ship (workstream 3.5) would have its
// end-of-life and missing-owner findings counted by the Findings page, the
// dashboard severity tiles and the framework rollups — silently, because
// nothing in any of those queries would error.
func TestIntegration_Findings_CarryTheProducerAndKind(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	c, a := uuid.New(), uuid.New()
	mustUpsert(t, svc, tenant, c, a, activeViolation(c, a), "ACTIVE")

	var producer, kind, subjectType string
	var score int
	if err := db.QueryRow(
		`SELECT producer, kind, subject_type, score FROM findings WHERE tenant_id = $1 AND subject_id = $2`,
		tenant, a).Scan(&producer, &kind, &subjectType, &score); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	if producer != "compliance" || kind != "control_noncompliant" {
		t.Errorf("finding declares producer=%q kind=%q, want compliance/control_noncompliant", producer, kind)
	}
	if subjectType != "certificate" {
		t.Errorf("subject_type = %q, want the certificate the measurement was taken on", subjectType)
	}
	// The registry sets control_noncompliant's feeds_risk to false, so this
	// producer contributes nothing to the per-asset risk rollup. A nonzero score
	// here would be picked up by workstream 3.2's recompute and would swamp it:
	// one failing control touching 400 assets would raise all 400.
	if score != 0 {
		t.Errorf("score = %d, want 0 — compliance does not feed the per-asset risk rollup", score)
	}
}

// A merged-away asset's findings are retired, and the survivor is re-evaluated.
//
// The merge path reaches this service as two ordinary events, so the property
// under test is that OnAssetDeleted now matches on `subject_id` — it matched
// `asset_id` on a table that no longer exists, and a rename that missed here
// would leave every merged-away asset's findings ACTIVE forever, still counted
// in the tenant's score for an asset that is gone from the inventory.
func TestIntegration_AssetMerged_RetiresTheMergedAwayAssetsFindings(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	mergedAway, survivor := uuid.New(), uuid.New()
	control := uuid.New()

	onAsset := func(subject uuid.UUID) *models.ComplianceFinding {
		f := activeViolation(control, subject)
		f.SubjectType = SubjectAsset
		return f
	}
	mustUpsert(t, svc, tenant, control, mergedAway, onAsset(mergedAway), "ACTIVE")
	mustUpsert(t, svc, tenant, control, survivor, onAsset(survivor), "ACTIVE")

	if err := svc.OnAssetDeleted(context.Background(), events.AssetDeletedEvent{
		EventID: uuid.New(), TenantID: tenant, AssetID: mergedAway, Source: "merge",
	}); err != nil {
		t.Fatalf("OnAssetDeleted: %v", err)
	}

	state := func(subject uuid.UUID) string {
		t.Helper()
		var s string
		if err := db.QueryRow(
			`SELECT detection_state FROM findings WHERE tenant_id = $1 AND subject_id = $2`,
			tenant, subject).Scan(&s); err != nil {
			t.Fatalf("read state for %s: %v", subject, err)
		}
		return s
	}
	if got := state(mergedAway); got != "INACTIVE" {
		t.Errorf("the merged-away asset's finding is %s, want INACTIVE — it is still scoring a "+
			"tenant for an asset that no longer appears in their inventory", got)
	}
	// The other polarity, which is the half a subject-id rename could silently
	// invert: the SURVIVOR's finding must be untouched.
	if got := state(survivor); got != "ACTIVE" {
		t.Errorf("the survivor's finding is %s, want ACTIVE — the deletion retired the wrong "+
			"asset's findings", got)
	}
}

// The score is the same number it was before the table moved.
//
// The rollup is a DB fold over the materialized findings, so it depends on the
// table, the severity vocabulary AND the producer scope all lining up. This
// pins the ARITHMETIC against a hand-computed expectation rather than against
// whatever the code now returns: one Critical control failing and one Low
// control passing, under the severity-weighted model (Critical=4, Low=1), is
// 1/(4+1) of the weight passing = 20.
//
// If any part of the move had gone wrong — a read that lost its rows, a
// severity that no longer matched a filter, a producer scope that excluded the
// compliance rows — this number would move, and it is the number a customer
// sees on their posture scorecard.
func TestIntegration_FrameworkScore_SurvivesTheTableMove(t *testing.T) {
	f := newEvalFixture(t)
	f.failCritical(t)

	assessments, err := loadControlAssessments(context.Background(), f.db.DB, f.tenant,
		[]uuid.UUID{f.critical, f.low}, "platform")
	if err != nil {
		t.Fatalf("loadControlAssessments: %v", err)
	}
	outcomes := outcomesFromAssessments(f.controls,
		func(c models.Control) uuid.UUID { return c.ID },
		func(c models.Control) string { return c.BaselineSeverity },
		assessments)
	got := scoreForTest(t, outcomes)

	if got.Total != 2 || got.Failing != 1 || got.Passing != 1 || got.NotAssessed != 0 {
		t.Fatalf("breakdown = %+v, want 2 total / 1 failing / 1 passing / 0 not assessed — the "+
			"fold no longer sees the findings it is folding", got)
	}
	if got.Score == nil {
		t.Fatal("score is nil for a framework with two assessed controls")
	}
	if *got.Score != 20 {
		t.Fatalf("score = %d, want 20 (Critical fails at weight 4, Low passes at weight 1, "+
			"so 1/5 of the weight passes). A different number means the table move changed "+
			"what a customer's scorecard reports.", *got.Score)
	}
}
