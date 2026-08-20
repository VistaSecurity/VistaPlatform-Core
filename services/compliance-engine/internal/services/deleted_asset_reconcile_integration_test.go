package services

// Database-integration tests for B-09: findings for a DELETED asset must not
// resurrect on the next whole-tenant reconcile.
//
// Asset deletion is a soft delete — inventory-service's DeleteAsset stamps
// network_assets.deleted_at and deliberately leaves crypto_implementations alone
// — and FindingsService.OnAssetDeleted then flips that asset's findings to
// INACTIVE. But none of the ten `JOIN network_assets na` sites in
// measurement_extractor.go filtered on deleted_at, so the next whole-tenant
// reconcile re-extracted the deleted asset, recomputed the same violation, and
// upsertFindings flipped the row straight back to ACTIVE with workflow_status
// reset to NEW and resurfaced_at stamped. The tenant's score dropped again for an
// asset that no longer exists, and their triage state was gone.
//
// Only a real database shows this: the resurrection lives entirely in the SQL
// the extractor emits and in the ACTIVE/INACTIVE transition upsertFindings picks.
//
// Skips unless TEST_DATABASE_URL is set (shared/testdb); `make test-integration-db`.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// deletionFixture is one tenant with one TLS 1.0 endpoint and a published
// framework whose single control flags exactly that, so a reconcile produces
// precisely one finding whose fate is unambiguous.
type deletionFixture struct {
	db        *sqlx.DB
	tenant    uuid.UUID
	framework uuid.UUID
	assetID   uuid.UUID
	implID    uuid.UUID
	controlID uuid.UUID
	findings  *FindingsService
}

func newDeletionFixture(t *testing.T) *deletionFixture {
	t.Helper()
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	roleID, userID := uuid.New(), uuid.New()
	suffix := roleID.String()[:8]
	if _, err := db.Exec(`INSERT INTO platform_roles (id, name, display_name) VALUES ($1, $2, $3)`,
		roleID, "del-role-"+suffix, "Del Role"); err != nil {
		t.Fatalf("seed platform role: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_roles WHERE id = $1`, roleID) })
	if _, err := db.Exec(`
		INSERT INTO platform_users (id, email, password_hash, first_name, last_name, role_id)
		VALUES ($1, $2, 'x', 'Del', 'User', $3)`,
		userID, "del-"+suffix+"@example.test", roleID); err != nil {
		t.Fatalf("seed platform user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_users WHERE id = $1`, userID) })

	frameworkID, controlID := uuid.New(), uuid.New()
	if _, err := db.Exec(`
		INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, created_by)
		VALUES ($1, $2, 'Deletion Framework', '1.0', 'integration fixture', 'IT Org', 'published', $3)`,
		frameworkID, "del-fw-"+suffix, userID); err != nil {
		t.Fatalf("seed framework: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, frameworkID) })

	if _, err := db.Exec(`
		INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant)
		VALUES ($1, $2, 'DEL-1', 'No deprecated TLS', 'integration fixture control', 'High', true)`,
		controlID, frameworkID); err != nil {
		t.Fatalf("seed control: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO measurement_types (code, name, data_type)
		VALUES ('tls_version', 'TLS version', 'string')
		ON CONFLICT (code) DO NOTHING`); err != nil {
		t.Fatalf("seed measurement type: %v", err)
	}
	var typeID uuid.UUID
	if err := db.Get(&typeID, `SELECT id FROM measurement_types WHERE code = 'tls_version'`); err != nil {
		t.Fatalf("read measurement type: %v", err)
	}
	// A match IS the violation: any TLS 1.0 endpoint fails this control.
	if _, err := db.Exec(`
		INSERT INTO control_measurements (control_id, framework_type, measurement_type_id, rule_type, predicate)
		VALUES ($1, 'platform', $2, 'pattern', '{"pattern": "^TLS1\\.0$", "match_means_violation": true}'::jsonb)`,
		controlID, typeID); err != nil {
		t.Fatalf("seed control measurement: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
		VALUES ($1, $2, 'active')`, tenant, frameworkID); err != nil {
		t.Fatalf("seed license: %v", err)
	}

	// RFC 5737 documentation address — never a real or lab network.
	assetID, implID := uuid.New(), uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets_partitioned (id, tenant_id, hostname, ip_address, port, asset_type)
		VALUES ($1, $2, 'tls10.example.test', '192.0.2.10', 443, 'server')`,
		assetID, tenant); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations_partitioned (id, tenant_id, asset_id, protocol, protocol_version, discovery_method)
		VALUES ($1, $2, $3, 'TLS', 'TLS1.0', 'passive')`,
		implID, tenant, assetID); err != nil {
		t.Fatalf("seed crypto implementation: %v", err)
	}

	extractor := NewMeasurementExtractor(db)
	evaluator := NewRuleEvaluator(db, extractor)
	findings := NewFindingsService(db, db, evaluator, nil, NewEvaluationService(db, evaluator), nil)

	return &deletionFixture{
		db: db, tenant: tenant, framework: frameworkID, assetID: assetID, implID: implID,
		controlID: controlID, findings: findings,
	}
}

// detectionState returns the single finding's detection_state, or "" if there is
// no finding row at all.
func (f *deletionFixture) detectionState(t *testing.T) string {
	t.Helper()
	var states []string
	if err := f.db.Select(&states, `
		SELECT detection_state FROM compliance_findings
		WHERE tenant_id = $1 AND control_id = $2 AND asset_id = $3`,
		f.tenant, f.controlID, f.assetID); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	if len(states) == 0 {
		return ""
	}
	if len(states) > 1 {
		t.Fatalf("expected at most one finding for (control, asset), got %d", len(states))
	}
	return states[0]
}

// TestIntegration_Reconcile_DeletedAssetFindingsStayInactive is the headline
// B-09 regression: delete the asset, then run the whole-tenant reconcile that
// every re-evaluate trigger funnels through (Posture Re-evaluate, framework
// publish, the admin re-evaluate button, a cert fan-out). The finding must stay
// INACTIVE.
func TestIntegration_Reconcile_DeletedAssetFindingsStayInactive(t *testing.T) {
	f := newDeletionFixture(t)
	ctx := context.Background()

	// 1. The asset is live and violating: the reconcile opens the finding.
	if _, err := f.findings.EvaluateTenantFrameworks(ctx, f.tenant); err != nil {
		t.Fatalf("initial EvaluateTenantFrameworks: %v", err)
	}
	if got := f.detectionState(t); got != "ACTIVE" {
		t.Fatalf("after first reconcile detection_state = %q, want ACTIVE — "+
			"the fixture must actually produce a violation or the rest of this test proves nothing", got)
	}

	// 2. The tenant deletes the asset. Exactly what inventory-service does:
	//    a soft delete on network_assets only (crypto_implementations untouched),
	//    followed by OnAssetDeleted flipping the findings INACTIVE.
	if _, err := f.db.Exec(
		`UPDATE network_assets SET deleted_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		f.tenant, f.assetID); err != nil {
		t.Fatalf("soft-delete asset: %v", err)
	}
	if _, err := f.db.Exec(`
		UPDATE compliance_findings SET detection_state = 'INACTIVE', updated_at = NOW()
		WHERE tenant_id = $1 AND asset_id = $2 AND detection_state = 'ACTIVE'`,
		f.tenant, f.assetID); err != nil {
		t.Fatalf("inactivate findings: %v", err)
	}
	if got := f.detectionState(t); got != "INACTIVE" {
		t.Fatalf("after deletion detection_state = %q, want INACTIVE", got)
	}

	// 3. Any re-evaluate at all. This is the step that used to resurrect it.
	if _, err := f.findings.EvaluateTenantFrameworks(ctx, f.tenant); err != nil {
		t.Fatalf("post-deletion EvaluateTenantFrameworks: %v", err)
	}
	if got := f.detectionState(t); got != "INACTIVE" {
		t.Fatalf("after re-evaluate detection_state = %q, want INACTIVE — "+
			"the deleted asset was re-extracted and its finding resurrected", got)
	}

	// The rollup must agree with the extractor: the soft-deleted asset leaves its
	// crypto_implementations rows behind, but those rows are no longer live
	// inventory. Counting them here made the control PASS and the framework score
	// 100 after all in-scope evidence had been removed.
	var score sql.NullInt64
	var passing, failing, notAssessed int
	if err := f.db.QueryRow(`
		SELECT score, controls_passing, controls_failing, controls_not_assessed
		FROM tenant_framework_scores
		WHERE tenant_id = $1 AND platform_framework_id = $2`,
		f.tenant, f.framework).Scan(&score, &passing, &failing, &notAssessed); err != nil {
		t.Fatalf("read post-delete rollup: %v", err)
	}
	if score.Valid || passing != 0 || failing != 0 || notAssessed != 1 {
		t.Fatalf("post-delete rollup score=%v passing=%d failing=%d not_assessed=%d, want nil/0/0/1",
			score, passing, failing, notAssessed)
	}

	// Triage state must survive too: the resurrect path rewrote workflow_status
	// to NEW and stamped resurfaced_at, which is how a triaged finding lost its
	// history on an unrelated re-evaluate.
	var resurfacedAt *string
	if err := f.db.QueryRow(`
		SELECT resurfaced_at::text FROM compliance_findings
		WHERE tenant_id = $1 AND asset_id = $2`, f.tenant, f.assetID).Scan(&resurfacedAt); err != nil {
		t.Fatalf("read resurfaced_at: %v", err)
	}
	if resurfacedAt != nil {
		t.Fatalf("resurfaced_at = %v, want NULL — the finding was flipped back to ACTIVE at some point", *resurfacedAt)
	}

	// Idempotent: a second pass must not change the answer either.
	if _, err := f.findings.EvaluateTenantFrameworks(ctx, f.tenant); err != nil {
		t.Fatalf("second post-deletion EvaluateTenantFrameworks: %v", err)
	}
	if got := f.detectionState(t); got != "INACTIVE" {
		t.Fatalf("after second re-evaluate detection_state = %q, want INACTIVE", got)
	}
}

// TestIntegration_Reconcile_DeletedCryptoImplementationIsOutOfScope pins the
// SECOND predicate. na.deleted_at alone is not enough: a crypto-implementation
// delete stamps ci.deleted_at and leaves the asset live, so an extractor filtering
// only the asset would keep measuring a configuration the tenant removed.
func TestIntegration_Reconcile_DeletedCryptoImplementationIsOutOfScope(t *testing.T) {
	f := newDeletionFixture(t)
	ctx := context.Background()

	if _, err := f.findings.EvaluateTenantFrameworks(ctx, f.tenant); err != nil {
		t.Fatalf("initial EvaluateTenantFrameworks: %v", err)
	}
	if got := f.detectionState(t); got != "ACTIVE" {
		t.Fatalf("after first reconcile detection_state = %q, want ACTIVE", got)
	}

	// The configuration goes away; the asset stays.
	if _, err := f.db.Exec(
		`UPDATE crypto_implementations_partitioned SET deleted_at = NOW() WHERE id = $1`, f.implID); err != nil {
		t.Fatalf("soft-delete crypto implementation: %v", err)
	}

	// The reconcile must now see nothing in scope and inactivate the finding
	// itself — this is the convergence half of the same rule.
	if _, err := f.findings.EvaluateTenantFrameworks(ctx, f.tenant); err != nil {
		t.Fatalf("post-deletion EvaluateTenantFrameworks: %v", err)
	}
	if got := f.detectionState(t); got != "INACTIVE" {
		t.Fatalf("after removing the crypto implementation detection_state = %q, want INACTIVE — "+
			"the extractor is still measuring a deleted configuration", got)
	}
}

// TestIntegration_Extractor_SkipsDeletedInventory is the same rule one layer
// down, asserted directly against the extractor, so a future query added without
// the predicates fails here with a clear cause rather than as a puzzling
// resurrection two layers up.
func TestIntegration_Extractor_SkipsDeletedInventory(t *testing.T) {
	f := newDeletionFixture(t)
	extractor := NewMeasurementExtractor(f.db)

	values, err := extractor.ExtractMeasurements(f.tenant, "tls_version")
	if err != nil {
		t.Fatalf("ExtractMeasurements: %v", err)
	}
	if len(values) != 1 {
		t.Fatalf("live inventory produced %d values, want 1", len(values))
	}

	if _, err := f.db.Exec(
		`UPDATE network_assets SET deleted_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		f.tenant, f.assetID); err != nil {
		t.Fatalf("soft-delete asset: %v", err)
	}
	values, err = extractor.ExtractMeasurements(f.tenant, "tls_version")
	if err != nil {
		t.Fatalf("ExtractMeasurements after asset delete: %v", err)
	}
	if len(values) != 0 {
		t.Fatalf("deleted asset still produced %d measurement values, want 0", len(values))
	}

	// Restore the asset, delete the configuration instead: the other predicate.
	if _, err := f.db.Exec(
		`UPDATE network_assets SET deleted_at = NULL WHERE tenant_id = $1 AND id = $2`,
		f.tenant, f.assetID); err != nil {
		t.Fatalf("restore asset: %v", err)
	}
	if _, err := f.db.Exec(
		`UPDATE crypto_implementations_partitioned SET deleted_at = NOW() WHERE id = $1`, f.implID); err != nil {
		t.Fatalf("soft-delete crypto implementation: %v", err)
	}
	values, err = extractor.ExtractMeasurements(f.tenant, "tls_version")
	if err != nil {
		t.Fatalf("ExtractMeasurements after implementation delete: %v", err)
	}
	if len(values) != 0 {
		t.Fatalf("deleted crypto implementation still produced %d measurement values, want 0", len(values))
	}
}
