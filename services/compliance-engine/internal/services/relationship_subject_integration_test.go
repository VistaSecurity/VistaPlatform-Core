package services

// An orphan-relationship finding is reachable from the asset that still exists.
//
// `hygiene/orphan_relationship` is the only kind written on a `relationship`
// subject, and its whole content is "an edge from THIS asset points at one that
// is gone". Until the relationship path was added to
// `shared/findings.AssetSubjects`, that finding appeared on the global Findings
// list and NOWHERE ELSE: not on either asset's Findings tab, not in the
// `has_findings` facet, not behind a `finding:(…)` query. The one surface where
// somebody would go and fix the broken edge never showed it.
//
// This drives the REAL per-asset read — GetFindingsByAsset, the query behind
// the asset page's Findings tab — rather than the helper. Delete the
// relationship entry from AssetSubjects and this goes red; that is the point,
// because a test over AssetSubjects alone would still pass with the path
// present and the read wired to something else.
//
// Skips without TEST_DATABASE_URL.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

// seedOrphanEdge builds what the hygiene producer's orphan case looks like in
// the database: two assets joined by an edge, one of them then archived, and
// the finding the producer writes on the EDGE.
//
// The missing end is archived rather than deleted because that is the case the
// producer actually raises on — a hard delete would take the row's foreign key
// with it — and because the surviving end is what the finding has to be
// reachable from either way.
func seedOrphanEdge(t *testing.T, db *sqlx.DB, tenant uuid.UUID) (survivor, missing, edge uuid.UUID) {
	t.Helper()
	survivor, missing, edge = uuid.New(), uuid.New(), uuid.New()
	for _, a := range []struct {
		id     uuid.UUID
		host   string
		status string
	}{
		{survivor, "edge-survivor.example.test", "monitoring"},
		{missing, "edge-missing.example.test", "archived"},
	} {
		if _, err := db.Exec(`
			INSERT INTO assets (id, tenant_id, class_key, class_path, hostname, asset_status)
			VALUES ($1, $2, 'server', 'server', $3, $4)`, a.id, tenant, a.host, a.status); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}
	if _, err := db.Exec(`
		INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type)
		VALUES ($1, $2, $3, $4, 'runs_on')`, edge, tenant, survivor, missing); err != nil {
		t.Fatalf("seed relationship: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO findings (
			id, tenant_id, producer, kind, subject_type, subject_id, subject_label,
			severity, score, summary, evidence, source_kind,
			detection_state, workflow_status, occurrence_count,
			first_seen, last_seen, last_evaluated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'runs_on edge',
			'low', 0, 'Relationship points at a missing asset', '{}'::jsonb, 'measured',
			'ACTIVE', 'NEW', 1, now(), now(), now())`,
		uuid.New(), tenant, sharedfindings.ProducerHygiene, sharedfindings.KindOrphanRelationship,
		sharedfindings.SubjectRelationship, edge); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return survivor, missing, edge
}

func TestIntegration_OrphanRelationshipFinding_IsVisibleOnTheSurvivingAsset(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	survivor, _, edge := seedOrphanEdge(t, db, tenant)

	got, err := svc.GetFindingsByAsset(tenant, survivor)
	if err != nil {
		t.Fatalf("GetFindingsByAsset: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the asset page's Findings tab returned %d findings for an asset whose only "+
			"relationship points at a missing one, want 1 — an orphan edge is the asset owner's "+
			"work, and a finding only the global list can see is one nobody acts on", len(got))
	}
	if got[0].SubjectType != sharedfindings.SubjectRelationship || got[0].SubjectID != edge {
		t.Errorf("finding names subject (%s, %s), want (%s, %s)",
			got[0].SubjectType, got[0].SubjectID, sharedfindings.SubjectRelationship, edge)
	}
}

// The other polarity, which is the half that makes the path a path rather than
// a widening: an UNRELATED asset does not inherit the edge's finding.
//
// Without this, "reachable from either end" and "reachable from everywhere"
// look identical from the passing side.
func TestIntegration_OrphanRelationshipFinding_DoesNotLeakToAnUnrelatedAsset(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	seedOrphanEdge(t, db, tenant)

	bystander := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, class_key, class_path, hostname)
		VALUES ($1, $2, 'server', 'server', 'edge-bystander.example.test')`,
		bystander, tenant); err != nil {
		t.Fatalf("seed bystander: %v", err)
	}

	got, err := svc.GetFindingsByAsset(tenant, bystander)
	if err != nil {
		t.Fatalf("GetFindingsByAsset: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("an asset that is neither end of the edge carries %d of its findings, want 0",
			len(got))
	}
}

// And the missing end, for completeness: an edge is reached from either end, so
// the archived asset's own page would show it too. Nothing renders that page,
// which is exactly why the surviving end is the one the first test pins — but
// the query must not depend on which end survived, because the producer does
// not control which direction the edge was written in.
func TestIntegration_OrphanRelationshipFinding_ReachableFromEitherEnd(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	_, missing, edge := seedOrphanEdge(t, db, tenant)

	got, err := svc.GetFindingsByAsset(tenant, missing)
	if err != nil {
		t.Fatalf("GetFindingsByAsset: %v", err)
	}
	if len(got) != 1 || got[0].SubjectID != edge {
		t.Fatalf("the edge is not reachable from its other end: %d findings", len(got))
	}
}
