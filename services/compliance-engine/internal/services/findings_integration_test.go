package services

// Database-integration tests for the compliance engine's finding/history WRITE path
// (upsertFinding + markFindingInactive) — the materialization behavior the pure-logic
// unit tests (reconcilePlan / buildAssetViolations) cannot reach. They assert the
// guarantees the engine's correctness rests on:
//
//  1. every pass<->fail flip writes exactly one compliance_finding_history row;
//  2. a resurfaced violation preserves workflow state (a SUPPRESSED finding stays
//     suppressed) while a non-suppressed one resets to NEW;
//  3. repeated identical reconciles converge — no duplicate findings, no history churn,
//     and (W2-13) no row churn either: a pass that changes nothing writes nothing;
//  4. the certificate→asset link lookup that scopes a certificate-change reconcile
//     resolves BOTH binding paths.
//
// They skip unless TEST_DATABASE_URL is set (see shared/testdb): CI runs them in the
// nightly backend job; locally use `make test-integration-db`.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newFindingsServiceIT(t *testing.T) (*FindingsService, *sqlx.DB, uuid.UUID) {
	raw := testdb.Connect(t) // skips if TEST_DATABASE_URL unset
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	return &FindingsService{db: db}, db, tenant // metricsService nil is a safe no-op
}

// activeViolation builds a representative ACTIVE finding for (control, asset).
func activeViolation(control, asset uuid.UUID) *models.ComplianceFinding {
	return &models.ComplianceFinding{
		ID:        uuid.New(),
		ControlID: control,
		AssetID:   asset,
		AssetType: "certificate",
		Severity:  "High",
		Summary:   "quantum-vulnerable",
	}
}

func countHistory(t *testing.T, db *sqlx.DB, findingID uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.Get(&n, `SELECT count(*) FROM compliance_finding_history WHERE finding_id = $1`, findingID); err != nil {
		t.Fatalf("count history: %v", err)
	}
	return n
}

func mustUpsert(t *testing.T, svc *FindingsService, tenant, control, asset uuid.UUID, f *models.ComplianceFinding, state string) {
	t.Helper()
	if err := svc.upsertFinding(context.Background(), tenant, control, asset, f, state); err != nil {
		t.Fatalf("upsert %s: %v", state, err)
	}
}

func mustInactivate(t *testing.T, svc *FindingsService, tenant, control, asset uuid.UUID) {
	t.Helper()
	if err := svc.markFindingInactive(context.Background(), tenant, control, asset); err != nil {
		t.Fatalf("mark inactive: %v", err)
	}
}

// 1. Every pass<->fail flip writes exactly one history row, recording the transition.
func TestIntegration_FindingFlip_WritesOneHistoryRowPerTransition(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	control, asset := uuid.New(), uuid.New()
	f := activeViolation(control, asset)

	// fail -> ACTIVE (creation)
	mustUpsert(t, svc, tenant, control, asset, f, "ACTIVE")

	var state, wf string
	var occ int
	if err := db.QueryRow(
		`SELECT detection_state, workflow_status, occurrence_count FROM compliance_findings WHERE id = $1`, f.ID,
	).Scan(&state, &wf, &occ); err != nil {
		t.Fatalf("load finding: %v", err)
	}
	if state != "ACTIVE" || wf != "NEW" || occ != 1 {
		t.Fatalf("after create: state=%s wf=%s occ=%d, want ACTIVE/NEW/1", state, wf, occ)
	}
	if got := countHistory(t, db, f.ID); got != 1 {
		t.Fatalf("history after create = %d, want 1", got)
	}

	// pass -> INACTIVE (exactly one more history row, recording ACTIVE->INACTIVE)
	mustInactivate(t, svc, tenant, control, asset)

	if err := db.QueryRow(`SELECT detection_state FROM compliance_findings WHERE id = $1`, f.ID).Scan(&state); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if state != "INACTIVE" {
		t.Fatalf("after inactivate: state=%s, want INACTIVE", state)
	}
	if got := countHistory(t, db, f.ID); got != 2 {
		t.Fatalf("history after flip = %d, want 2", got)
	}

	var oldV, newV string
	if err := db.QueryRow(
		`SELECT old_value, new_value FROM compliance_finding_history
		   WHERE finding_id = $1 AND field_name = 'detection_state'
		   ORDER BY changed_at DESC LIMIT 1`, f.ID,
	).Scan(&oldV, &newV); err != nil {
		t.Fatalf("latest history: %v", err)
	}
	if oldV != "ACTIVE" || newV != "INACTIVE" {
		t.Fatalf("latest history = %s->%s, want ACTIVE->INACTIVE", oldV, newV)
	}
}

//  2. A resurfaced violation preserves workflow state: a SUPPRESSED finding stays
//     suppressed (so suppressed noise doesn't reappear), while a non-suppressed one
//     resets to NEW (so a genuinely-returned issue is surfaced again).
func TestIntegration_Resurface_PreservesWorkflowState(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	// (a) SUPPRESSED survives a fail -> pass -> fail cycle.
	cS, aS := uuid.New(), uuid.New()
	fS := activeViolation(cS, aS)
	mustUpsert(t, svc, tenant, cS, aS, fS, "ACTIVE")
	if _, err := db.Exec(`UPDATE compliance_findings SET workflow_status = 'SUPPRESSED' WHERE id = $1`, fS.ID); err != nil {
		t.Fatalf("suppress: %v", err)
	}
	mustInactivate(t, svc, tenant, cS, aS)
	mustUpsert(t, svc, tenant, cS, aS, fS, "ACTIVE") // resurface

	var wf, state string
	var resurfaced *time.Time
	var occ int
	if err := db.QueryRow(
		`SELECT workflow_status, detection_state, resurfaced_at, occurrence_count FROM compliance_findings WHERE id = $1`, fS.ID,
	).Scan(&wf, &state, &resurfaced, &occ); err != nil {
		t.Fatalf("load suppressed: %v", err)
	}
	if wf != "SUPPRESSED" {
		t.Fatalf("resurfaced suppressed finding wf=%s, want SUPPRESSED (preserved)", wf)
	}
	if state != "ACTIVE" || resurfaced == nil || occ != 2 {
		t.Fatalf("resurface: state=%s resurfaced_at=%v occ=%d, want ACTIVE/non-nil/2", state, resurfaced, occ)
	}

	// (b) a non-suppressed finding resets to NEW on resurface (the other CASE branch).
	cN, aN := uuid.New(), uuid.New()
	fN := activeViolation(cN, aN)
	mustUpsert(t, svc, tenant, cN, aN, fN, "ACTIVE")
	if _, err := db.Exec(`UPDATE compliance_findings SET workflow_status = 'RESOLVED' WHERE id = $1`, fN.ID); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	mustInactivate(t, svc, tenant, cN, aN)
	mustUpsert(t, svc, tenant, cN, aN, fN, "ACTIVE") // resurface

	if err := db.QueryRow(`SELECT workflow_status FROM compliance_findings WHERE id = $1`, fN.ID).Scan(&wf); err != nil {
		t.Fatalf("load non-suppressed: %v", err)
	}
	if wf != "NEW" {
		t.Fatalf("resurfaced non-suppressed finding wf=%s, want NEW (reset)", wf)
	}
}

//  3. Repeated identical reconciles converge: one finding, no duplicates, no history
//     churn — and (W2-13) no ROW churn either. A pass that changes nothing must not
//     rewrite the row: occurrence_count and updated_at stay put, so a converged tenant
//     costs zero row versions per pass instead of one per active finding.
func TestIntegration_RepeatedReconcile_ConvergesNoDuplicates(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	control, asset := uuid.New(), uuid.New()
	f := activeViolation(control, asset)

	mustUpsert(t, svc, tenant, control, asset, f, "ACTIVE")

	var firstUpdatedAt time.Time
	if err := db.QueryRow(`SELECT updated_at FROM compliance_findings WHERE id = $1`, f.ID).Scan(&firstUpdatedAt); err != nil {
		t.Fatalf("load updated_at: %v", err)
	}

	for i := 0; i < 2; i++ {
		mustUpsert(t, svc, tenant, control, asset, f, "ACTIVE")
	}

	var n int
	if err := db.Get(&n,
		`SELECT count(*) FROM compliance_findings WHERE tenant_id = $1 AND control_id = $2 AND asset_id = $3`,
		tenant, control, asset); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if n != 1 {
		t.Fatalf("duplicate findings: count=%d, want 1", n)
	}

	var state string
	var occ int
	var updatedAt time.Time
	if err := db.QueryRow(`SELECT detection_state, occurrence_count, updated_at FROM compliance_findings WHERE id = $1`, f.ID).
		Scan(&state, &occ, &updatedAt); err != nil {
		t.Fatalf("load: %v", err)
	}
	if state != "ACTIVE" {
		t.Fatalf("convergence: state=%s, want ACTIVE", state)
	}
	// The no-op skip: the two extra identical passes wrote nothing at all.
	if occ != 1 {
		t.Fatalf("row churn: occurrence_count=%d after 2 no-op reconciles, want 1 (unchanged findings must not be rewritten)", occ)
	}
	if !updatedAt.Equal(firstUpdatedAt) {
		t.Fatalf("row churn: updated_at moved (%s -> %s) on a reconcile that changed nothing", firstUpdatedAt, updatedAt)
	}
	// Detection state never changed across the three identical reconciles, so only the
	// creation history row should exist — no per-reconcile churn.
	if got := countHistory(t, db, f.ID); got != 1 {
		t.Fatalf("history churn: %d rows, want 1 (no state changes across identical reconciles)", got)
	}
}

//  4. (W2-13) The no-op skip must not swallow REAL changes, and must still refresh a
//     finding whose last_seen has aged past findingLastSeenRefreshInterval. Both
//     polarities, because a skip that can't be defeated is the same class of bug as a
//     guard that can't fail.
func TestIntegration_UpsertFinding_SkipsNoOpsButWritesRealChanges(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	reload := func(id uuid.UUID) (severity, summary string, occ int, evidence string) {
		t.Helper()
		if err := db.QueryRow(
			`SELECT severity, summary, occurrence_count, evidence::text FROM compliance_findings WHERE id = $1`, id,
		).Scan(&severity, &summary, &occ, &evidence); err != nil {
			t.Fatalf("reload: %v", err)
		}
		return
	}

	// (a) severity change is material → written.
	c, a := uuid.New(), uuid.New()
	f := activeViolation(c, a)
	mustUpsert(t, svc, tenant, c, a, f, "ACTIVE")

	raised := *f
	raised.Severity = "Critical"
	mustUpsert(t, svc, tenant, c, a, &raised, "ACTIVE")
	if sev, _, occ, _ := reload(f.ID); sev != "Critical" || occ != 2 {
		t.Fatalf("severity change: severity=%s occ=%d, want Critical/2 (a material change must write)", sev, occ)
	}

	// (b) summary change is material → written.
	reworded := raised
	reworded.Summary = "quantum-vulnerable (RSA-2048)"
	mustUpsert(t, svc, tenant, c, a, &reworded, "ACTIVE")
	if _, sum, occ, _ := reload(f.ID); sum != reworded.Summary || occ != 3 {
		t.Fatalf("summary change: summary=%q occ=%d, want the new summary and occ=3", sum, occ)
	}

	// (c) evidence change is material → written, and compares with jsonb semantics: the
	// SAME evidence re-marshalled in a different key order must NOT count as a change
	// (a byte comparison would rewrite the row on every single pass).
	withEvidence := reworded
	withEvidence.Evidence = map[string]interface{}{"algorithm": "RSA", "key_size": 2048}
	mustUpsert(t, svc, tenant, c, a, &withEvidence, "ACTIVE")
	_, _, occAfterEvidence, storedEvidence := reload(f.ID)
	if occAfterEvidence != 4 {
		t.Fatalf("evidence change: occ=%d, want 4 (new evidence must write)", occAfterEvidence)
	}
	if !strings.Contains(storedEvidence, "2048") {
		t.Fatalf("evidence not persisted: %s", storedEvidence)
	}

	reordered := withEvidence
	reordered.Evidence = map[string]interface{}{"key_size": 2048, "algorithm": "RSA"}
	mustUpsert(t, svc, tenant, c, a, &reordered, "ACTIVE")
	if _, _, occ, _ := reload(f.ID); occ != 4 {
		t.Fatalf("semantically-identical evidence rewrote the row: occ=%d, want 4", occ)
	}

	// (d) last_seen aged past the refresh interval → refreshed even with nothing else
	// changed, so the freshness indicator stays coarse-but-honest.
	if _, err := db.Exec(
		`UPDATE compliance_findings SET last_seen = now() - interval '2 hours', updated_at = now() - interval '2 hours' WHERE id = $1`,
		f.ID); err != nil {
		t.Fatalf("age last_seen: %v", err)
	}
	mustUpsert(t, svc, tenant, c, a, &reordered, "ACTIVE")
	if _, _, occ, _ := reload(f.ID); occ != 5 {
		t.Fatalf("stale last_seen was not refreshed: occ=%d, want 5", occ)
	}

	// The whole sequence contained no detection-state transition, so history still holds
	// only the creation row: material field changes are not audit transitions.
	if got := countHistory(t, db, f.ID); got != 1 {
		t.Fatalf("history rows = %d, want 1", got)
	}
}

//  5. (W2-13) The batched write path materializes a whole pass in one transaction and
//     reports created/updated/skipped honestly — the counters the pass logs, and the
//     evidence that a converged pass performs zero writes.
func TestIntegration_UpsertFindings_BatchWritesAndCounts(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	const n = 25
	items := make([]findingUpsert, 0, n)
	for i := 0; i < n; i++ {
		c, a := uuid.New(), uuid.New()
		items = append(items, findingUpsert{
			ControlID:      c,
			AssetID:        a,
			Finding:        activeViolation(c, a),
			DetectionState: "ACTIVE",
		})
	}

	first := svc.upsertFindings(context.Background(), tenant, items)
	if first.Created != n || first.Updated != 0 || first.Skipped != 0 || first.Failed != 0 {
		t.Fatalf("first pass = %+v, want %d created and nothing else", first, n)
	}

	second := svc.upsertFindings(context.Background(), tenant, items)
	if second.Skipped != n || second.Created != 0 || second.Updated != 0 || second.Failed != 0 {
		t.Fatalf("converged pass = %+v, want %d skipped and zero writes", second, n)
	}
	if second.Processed() != n {
		t.Fatalf("Processed() = %d, want %d (a skipped pair is still an active finding)", second.Processed(), n)
	}

	var rows int
	if err := db.Get(&rows, `SELECT count(*) FROM compliance_findings WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != n {
		t.Fatalf("batch wrote %d rows, want %d", rows, n)
	}

	// A pair that genuinely flips is written even in a batch that is otherwise a no-op.
	items[0].Finding.Severity = "Critical"
	third := svc.upsertFindings(context.Background(), tenant, items)
	if third.Updated != 1 || third.Skipped != n-1 {
		t.Fatalf("mixed pass = %+v, want 1 updated / %d skipped", third, n-1)
	}
}

//  6. (W2-13) upsertFinding's ON CONFLICT arbiter must actually infer the partial unique
//     index idx_findings_identity — the batch path depends on a duplicate raising no
//     error (a unique violation would abort the whole chunk's transaction, not just the
//     one pair). Insert the identity twice with DIFFERENT finding ids: the second must
//     converge onto the first row rather than erroring or duplicating.
func TestIntegration_UpsertFinding_DuplicateIdentityConvergesViaOnConflict(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	c, a := uuid.New(), uuid.New()

	first := activeViolation(c, a)
	mustUpsert(t, svc, tenant, c, a, first, "ACTIVE")

	// A second writer that never saw the first row (distinct id) — the race the partial
	// unique index backstops.
	racer := activeViolation(c, a)
	racer.Severity = "Critical"
	if err := svc.upsertFindingChunk(context.Background(), tenant, []findingUpsert{{
		ControlID: c, AssetID: a, Finding: racer, DetectionState: "ACTIVE",
	}}); err != nil {
		t.Fatalf("duplicate-identity upsert must not error (ON CONFLICT should absorb it): %v", err)
	}

	var rows int
	if err := db.Get(&rows,
		`SELECT count(*) FROM compliance_findings WHERE tenant_id = $1 AND control_id = $2 AND asset_id = $3`,
		tenant, c, a); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("duplicate identity produced %d rows, want 1", rows)
	}
	var sev string
	if err := db.QueryRow(`SELECT severity FROM compliance_findings WHERE id = $1`, first.ID).Scan(&sev); err != nil {
		t.Fatalf("reload original row: %v", err)
	}
	if sev != "Critical" {
		t.Fatalf("conflicting write did not converge onto the existing row: severity=%s, want Critical", sev)
	}
}

//  7. (W2-13) assetsForCertificate must resolve BOTH certificate→asset binding paths.
//     crypto_implementations.certificate_id is the primary/leaf binding;
//     crypto_implementation_certificates carries the chain certificates. The pre-W2-13
//     query consulted only the junction, so a LEAF certificate — the common case —
//     resolved to zero assets and the scoped reconcile would have had nothing to do.
func TestIntegration_AssetsForCertificate_ResolvesBothLinkPaths(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	ctx := context.Background()

	leafCert, chainCert := uuid.New(), uuid.New()
	directAsset, junctionAsset := uuid.New(), uuid.New()
	implDirect, implJunction := uuid.New(), uuid.New()

	insertCert := func(id uuid.UUID, cn string) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name, fingerprint_sha256)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			id, tenant, "CN="+cn, "CN=Test CA", cn, strings.ReplaceAll(id.String(), "-", "")+strings.ReplaceAll(uuid.New().String(), "-", "")); err != nil {
			t.Fatalf("insert certificate %s: %v", cn, err)
		}
	}
	insertCert(leafCert, "leaf.example.test")
	insertCert(chainCert, "chain.example.test")

	insertImpl := func(id, asset uuid.UUID, certID *uuid.UUID) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO crypto_implementations_partitioned (id, tenant_id, asset_id, protocol, certificate_id, discovery_method)
			VALUES ($1, $2, $3, 'TLS', $4, 'passive')`, id, tenant, asset, certID); err != nil {
			t.Fatalf("insert implementation: %v", err)
		}
	}
	insertImpl(implDirect, directAsset, &leafCert)
	insertImpl(implJunction, junctionAsset, nil)

	if _, err := db.Exec(`
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'intermediate')`, implJunction, chainCert); err != nil {
		t.Fatalf("insert junction row: %v", err)
	}

	// (a) the leaf binding — the path the old junction-only query missed entirely.
	got, err := svc.assetsForCertificate(ctx, tenant, leafCert)
	if err != nil {
		t.Fatalf("assetsForCertificate(leaf): %v", err)
	}
	if len(got) != 1 || got[0] != directAsset {
		t.Fatalf("leaf certificate resolved to %v, want [%s] (crypto_implementations.certificate_id)", got, directAsset)
	}

	// (b) the chain binding via the junction still resolves.
	got, err = svc.assetsForCertificate(ctx, tenant, chainCert)
	if err != nil {
		t.Fatalf("assetsForCertificate(chain): %v", err)
	}
	if len(got) != 1 || got[0] != junctionAsset {
		t.Fatalf("chain certificate resolved to %v, want [%s]", got, junctionAsset)
	}

	// (c) an unbound certificate resolves to nothing — which is NOT a reason to skip the
	// reconcile; certReconcileTargets still reconciles the certificate itself.
	got, err = svc.assetsForCertificate(ctx, tenant, uuid.New())
	if err != nil {
		t.Fatalf("assetsForCertificate(unbound): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unbound certificate resolved to %v, want none", got)
	}
	if targets, tenantWide := certReconcileTargets(leafCert, got); tenantWide || len(targets) != 1 {
		t.Fatalf("unbound certificate scoping: targets=%v tenantWide=%v, want the cert alone", targets, tenantWide)
	}
}
