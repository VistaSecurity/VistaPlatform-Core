package services

// Database-integration tests for B-08, whose two halves are separate bugs that
// compounded each other.
//
// (a) Only PublishFramework enqueued an ADR-0014 reconcile. CreateControl,
//     UpdateControl, DeleteControl and all three measurement mutations changed an
//     already-published framework's evaluable content and enqueued nothing, so
//     tightening a threshold produced no new findings for inventory that did not
//     independently change — with no re-publish action on the catalog page and no
//     warning that the edit had done nothing.
//
// (b) loadControlAssessments marked a control PASS as soon as it had ANY
//     control_measurements row and the tenant had any inventory. So the new
//     control also scored as a free pass: adding a Critical control to live Best
//     Practices RAISED every tenant's score for a check nothing had ever run.
//
// Skips unless TEST_DATABASE_URL is set (shared/testdb); `make test-integration-db`.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// authoringFixture is a platform framework the tests can author against, plus a
// recording enqueuer so "did this mutation ask for a reconcile?" is observable.
type authoringFixture struct {
	db          *sqlx.DB
	tenant      uuid.UUID
	frameworkID uuid.UUID
	svc         *PlatformFrameworkService
	jobs        *[]ReconcileJob
	typeID      uuid.UUID
}

func newAuthoringFixture(t *testing.T, status string) *authoringFixture {
	t.Helper()
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	roleID, userID := uuid.New(), uuid.New()
	suffix := roleID.String()[:8]
	if _, err := db.Exec(`INSERT INTO platform_roles (id, name, display_name) VALUES ($1, $2, $3)`,
		roleID, "auth-role-"+suffix, "Authoring Role"); err != nil {
		t.Fatalf("seed platform role: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_roles WHERE id = $1`, roleID) })
	if _, err := db.Exec(`
		INSERT INTO platform_users (id, email, password_hash, first_name, last_name, role_id)
		VALUES ($1, $2, 'x', 'Auth', 'User', $3)`,
		userID, "auth-"+suffix+"@example.test", roleID); err != nil {
		t.Fatalf("seed platform user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_users WHERE id = $1`, userID) })

	frameworkID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, created_by)
		VALUES ($1, $2, 'Authoring Framework', '1.0', 'integration fixture', 'IT Org', $3, $4)`,
		frameworkID, "auth-fw-"+suffix, status, userID); err != nil {
		t.Fatalf("seed framework: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, frameworkID) })

	// A fixture-local measurement type that constrains both allowed_rule_types and
	// valid_operators, so the tests can prove those jsonb columns actually arrive
	// populated: an empty list means "no restriction" to the validator, which is
	// indistinguishable from a successful read unless the restriction bites.
	const mtCode = "authoring_fixture_days"
	if _, err := db.Exec(`
		INSERT INTO measurement_types (code, name, description, data_type, extraction_query, units,
		                               valid_range, allowed_rule_types, enum_values, valid_operators, predicate_schema, category)
		VALUES ($1, 'Authoring fixture (days)', 'integration fixture', 'integer', 'SELECT 1', 'days',
		        '{}'::jsonb, '["threshold"]'::jsonb, '[]'::jsonb, '[">=", "<=", ">", "<", "=="]'::jsonb, '{}'::jsonb, 'certificate')
		ON CONFLICT (code) DO UPDATE SET
		  valid_range = EXCLUDED.valid_range,
		  allowed_rule_types = EXCLUDED.allowed_rule_types,
		  enum_values = EXCLUDED.enum_values,
		  valid_operators = EXCLUDED.valid_operators,
		  predicate_schema = EXCLUDED.predicate_schema,
		  extraction_query = EXCLUDED.extraction_query`, mtCode); err != nil {
		t.Fatalf("seed measurement type: %v", err)
	}
	var typeID uuid.UUID
	if err := db.Get(&typeID, `SELECT id FROM measurement_types WHERE code = $1`, mtCode); err != nil {
		t.Fatalf("read measurement type: %v", err)
	}

	// Activated for the tenant. Findings are read through licensedFindingScopeSQL,
	// so without this every finding is invisible to the read paths and the tests
	// would be asserting against an empty set that looks like a clean pass.
	if _, err := db.Exec(`
		INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
		VALUES ($1, $2, 'active')`, tenant, frameworkID); err != nil {
		t.Fatalf("seed license: %v", err)
	}

	jobs := &[]ReconcileJob{}
	enq := NewReconcileEnqueuer(nil, db)
	enq.sink = func(j ReconcileJob) { *jobs = append(*jobs, j) }

	svc := NewPlatformFrameworkService(db)
	svc.SetReconcileEnqueuer(enq)

	return &authoringFixture{db: db, tenant: tenant, frameworkID: frameworkID, svc: svc, jobs: jobs, typeID: typeID}
}

// scopedJobs returns the reconcile jobs enqueued for THIS fixture's framework.
// The fan-out publishes one message per tenant in the database, so counting
// messages is meaningless; what matters is that the framework was scoped in at
// all, which is what a missing enqueue makes false.
func (f *authoringFixture) scopedJobs() []ReconcileJob {
	var out []ReconcileJob
	for _, j := range *f.jobs {
		if j.FrameworkID == f.frameworkID.String() {
			out = append(out, j)
		}
	}
	return out
}

func (f *authoringFixture) reset() { *f.jobs = nil }

func (f *authoringFixture) newControl(t *testing.T, code, severity string) uuid.UUID {
	t.Helper()
	ctrl, err := f.svc.CreateControl(f.frameworkID, &models.PlatformFrameworkControlInput{
		ControlID:        code,
		Title:            "Control " + code,
		Description:      "integration fixture control",
		BaselineSeverity: severity,
		CryptoRelevant:   true,
	})
	if err != nil {
		t.Fatalf("CreateControl(%s): %v", code, err)
	}
	return ctrl.ID
}

// seedMeasurementRow adds a measurement rule through the service, the way the
// platform-admin measurement-rule modal does.
func (f *authoringFixture) seedMeasurementRow(t *testing.T, controlID uuid.UUID) uuid.UUID {
	t.Helper()
	m, err := f.svc.AddControlMeasurement(controlID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "threshold",
		Predicate:         map[string]interface{}{"operator": ">=", "value": float64(0)},
		Weight:            1,
	})
	if err != nil {
		t.Fatalf("AddControlMeasurement: %v", err)
	}
	return m.ID
}

// touchMeasurement bumps a measurement's updated_at the way a predicate edit
// does (the update_control_measurements_updated_at trigger maintains it).
func (f *authoringFixture) touchMeasurement(t *testing.T, measurementID uuid.UUID) {
	t.Helper()
	if _, err := f.db.Exec(`
		UPDATE control_measurements SET predicate = '{"operator": ">=", "value": 90}'::jsonb
		WHERE id = $1`, measurementID); err != nil {
		t.Fatalf("tighten measurement predicate: %v", err)
	}
}

// TestIntegration_ControlMutations_EnqueueReconcile is B-08(a): EVERY mutation
// that changes a published framework's evaluable content must fan a reconcile
// out, not just PublishFramework.
func TestIntegration_ControlMutations_EnqueueReconcile(t *testing.T) {
	f := newAuthoringFixture(t, "published")

	// CreateControl
	f.reset()
	controlID := f.newControl(t, "AUTH-1", "Critical")
	if len(f.scopedJobs()) == 0 {
		t.Fatal("CreateControl on a PUBLISHED framework enqueued no reconcile — " +
			"the new control will never be evaluated for any tenant")
	}

	// UpdateControl
	f.reset()
	if _, err := f.svc.UpdateControl(controlID, &models.PlatformFrameworkControlInput{
		ControlID:        "AUTH-1",
		Title:            "Control AUTH-1 (retitled)",
		Description:      "integration fixture control",
		BaselineSeverity: "High",
		CryptoRelevant:   true,
	}); err != nil {
		t.Fatalf("UpdateControl: %v", err)
	}
	if len(f.scopedJobs()) == 0 {
		t.Fatal("UpdateControl enqueued no reconcile")
	}

	// AddControlMeasurement
	f.reset()
	measurementID := f.seedMeasurementRow(t, controlID)
	if len(f.scopedJobs()) == 0 {
		t.Fatal("AddControlMeasurement enqueued no reconcile — the new rule will never be evaluated")
	}

	// UpdateControlMeasurement
	f.reset()
	if _, err := f.svc.UpdateControlMeasurement(measurementID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "threshold",
		Predicate:         map[string]interface{}{"operator": ">=", "value": float64(90)},
		Weight:            1,
	}); err != nil {
		t.Fatalf("UpdateControlMeasurement: %v", err)
	}
	if len(f.scopedJobs()) == 0 {
		t.Fatal("UpdateControlMeasurement enqueued no reconcile — tightening a threshold would produce no new findings")
	}

	// DeleteControlMeasurement — resolves the framework BEFORE the row is gone,
	// which is the ordering a naive "enqueue after the write" would get wrong.
	f.reset()
	if err := f.svc.DeleteControlMeasurement(measurementID); err != nil {
		t.Fatalf("DeleteControlMeasurement: %v", err)
	}
	if len(f.scopedJobs()) == 0 {
		t.Fatal("DeleteControlMeasurement enqueued no reconcile — the framework link must be " +
			"resolved before the DELETE, not after")
	}

	// DeleteControl — same ordering requirement.
	f.reset()
	if err := f.svc.DeleteControl(controlID); err != nil {
		t.Fatalf("DeleteControl: %v", err)
	}
	if len(f.scopedJobs()) == 0 {
		t.Fatal("DeleteControl enqueued no reconcile — its findings will never be inactivated")
	}
}

// TestIntegration_ControlMutations_DraftFrameworkDoesNotFanOut pins the other
// polarity. A draft framework is not evaluable — EvaluateTenantFrameworksScoped
// short-circuits on it — so authoring one must not put a message per tenant on
// the queue for every keystroke-sized edit. PublishFramework does that fan-out
// once, when the content actually becomes live.
func TestIntegration_ControlMutations_DraftFrameworkDoesNotFanOut(t *testing.T) {
	f := newAuthoringFixture(t, "draft")

	controlID := f.newControl(t, "DRAFT-1", "High")
	measurementID := f.seedMeasurementRow(t, controlID)
	if err := f.svc.DeleteControlMeasurement(measurementID); err != nil {
		t.Fatalf("DeleteControlMeasurement: %v", err)
	}
	if got := len(f.scopedJobs()); got != 0 {
		t.Fatalf("authoring a DRAFT framework enqueued %d reconcile jobs, want 0", got)
	}
}

// --- B-08(b): a configured measurement is not an evaluation ------------------

// evaluatedAtRollup stamps the tenant's rollup for the framework, standing in for
// "the reconcile has folded this framework for this tenant at time t".
func evaluatedAtRollup(t *testing.T, db *sqlx.DB, tenant, frameworkID uuid.UUID, at time.Time) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO tenant_framework_scores (tenant_id, platform_framework_id, score, controls_total, computed_at)
		VALUES ($1, $2, NULL, 0, $3)
		ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET computed_at = EXCLUDED.computed_at`,
		tenant, frameworkID, at); err != nil {
		t.Fatalf("stamp rollup: %v", err)
	}
}

// TestIntegration_NewControl_IsNotAssessedUntilEvaluated is the headline B-08(b)
// regression. A control added to a live framework AFTER the tenant's last
// evaluation must report NOT_ASSESSED, not a free PASS — and must therefore not
// move the tenant's score at all.
func TestIntegration_NewControl_IsNotAssessedUntilEvaluated(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	ctx := context.Background()

	// An established control, evaluated, and violated: the tenant's real posture.
	existing := f.newControl(t, "EST-1", "Low")
	f.seedMeasurementRow(t, existing)
	seedTenantInventory(t, f.db, f.tenant)
	if _, err := f.db.Exec(`
		INSERT INTO compliance_findings
			(id, tenant_id, control_id, asset_id, asset_type, severity, summary, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, 'certificate', 'Low', 'expires soon', 'ACTIVE', 'NEW')`,
		uuid.New(), f.tenant, existing, uuid.New()); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	evaluatedAtRollup(t, f.db, f.tenant, f.frameworkID, time.Now())

	// Now a platform admin adds a Critical control to the live framework.
	// Its created_at is after the rollup's computed_at, so nothing has run it.
	added := f.newControl(t, "NEW-1", "Critical")
	f.seedMeasurementRow(t, added)

	assessments, err := loadControlAssessments(ctx, f.db.DB, f.tenant,
		[]uuid.UUID{existing, added}, "platform")
	if err != nil {
		t.Fatalf("loadControlAssessments: %v", err)
	}
	if got := assessments[existing]; got.Status != statusFail {
		t.Fatalf("established violated control = %+v, want FAIL", got)
	}
	if got := assessments[added]; got.Status != statusNotAssessed || got.Reason != reasonNotEvaluated {
		t.Fatalf("newly added control = %+v, want NOT_ASSESSED/%s — a configured measurement "+
			"is not an evaluation, and counting it as a pass RAISES the score for a check nothing ran",
			got, reasonNotEvaluated)
	}

	// The arithmetic that the tenant actually sees. Before the fix the added
	// Critical control scored as a pass (weight 4) beside the failing Low control
	// (weight 1), which pushed the framework from 0 to 4*100/5 = 80. It must
	// stay 0: nothing about the tenant's posture improved.
	b := frameworkScore([]controlOutcome{
		{BaselineSeverity: "Low", Status: assessments[existing].Status},
		{BaselineSeverity: "Critical", Status: assessments[added].Status},
	})
	if b.Score == nil || *b.Score != 0 {
		t.Fatalf("framework score = %v, want 0 — adding an unevaluated Critical control "+
			"must not raise the score", b.Score)
	}
	if b.Passing != 0 || b.Failing != 1 || b.NotAssessed != 1 || b.Total != 2 {
		t.Fatalf("breakdown = {total:%d passing:%d failing:%d notAssessed:%d}, want {2 0 1 1}",
			b.Total, b.Passing, b.Failing, b.NotAssessed)
	}
}

// TestIntegration_ThresholdChange_IsNotAssessedUntilReEvaluated covers the other
// authoring move: the control is old and passing, but its RULE changed, so the
// stored pass is a claim about the previous predicate.
func TestIntegration_ThresholdChange_IsNotAssessedUntilReEvaluated(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	ctx := context.Background()
	seedTenantInventory(t, f.db, f.tenant)

	controlID := f.newControl(t, "THR-1", "High")
	measurementID := f.seedMeasurementRow(t, controlID)

	evaluatedAtRollup(t, f.db, f.tenant, f.frameworkID, time.Now())
	assessments, err := loadControlAssessments(ctx, f.db.DB, f.tenant, []uuid.UUID{controlID}, "platform")
	if err != nil {
		t.Fatalf("loadControlAssessments: %v", err)
	}
	if got := assessments[controlID]; got.Status != statusPass {
		t.Fatalf("evaluated, unviolated control = %+v, want PASS", got)
	}

	// Tighten the threshold. The measurement's updated_at moves past the rollup.
	f.touchMeasurement(t, measurementID)

	assessments, err = loadControlAssessments(ctx, f.db.DB, f.tenant, []uuid.UUID{controlID}, "platform")
	if err != nil {
		t.Fatalf("loadControlAssessments: %v", err)
	}
	if got := assessments[controlID]; got.Status != statusNotAssessed || got.Reason != reasonNotEvaluated {
		t.Fatalf("control with a changed threshold = %+v, want NOT_ASSESSED/%s — "+
			"the stored pass is a claim about the OLD predicate", got, reasonNotEvaluated)
	}

	// And the reconcile's own fold sees it as assessed straight away, rather than
	// reporting the control it just checked as unevaluated for one extra pass.
	assessments, err = loadControlAssessmentsAt(ctx, f.db.DB, f.tenant, []uuid.UUID{controlID}, "platform", time.Now())
	if err != nil {
		t.Fatalf("loadControlAssessmentsAt: %v", err)
	}
	if got := assessments[controlID]; got.Status != statusPass {
		t.Fatalf("in-flight evaluation reports %+v, want PASS — evaluatedAt must count as "+
			"an evaluation, or the rollup lags one pass behind every rule change", got)
	}
}

// TestIntegration_ControlMetadataEdit_StaysAssessed is the guard on the OTHER
// polarity, and the reason the freshness check keys on created_at rather than
// platform_framework_controls.updated_at.
//
// seed.sql re-runs on every helm upgrade and its `ON CONFLICT ... DO UPDATE SET
// ..., updated_at = NOW()` bumps every seeded control. Keying on updated_at would
// therefore blank every framework's score to "—" after every install, for edits
// that changed only a title. Titles, descriptions and baseline_severity are not
// evaluable content: severity is the control's WEIGHT, never its verdict.
func TestIntegration_ControlMetadataEdit_StaysAssessed(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	ctx := context.Background()
	seedTenantInventory(t, f.db, f.tenant)

	controlID := f.newControl(t, "META-1", "High")
	f.seedMeasurementRow(t, controlID)
	evaluatedAtRollup(t, f.db, f.tenant, f.frameworkID, time.Now())

	// Exactly what the seed's ON CONFLICT branch does.
	if _, err := f.db.Exec(`
		UPDATE platform_framework_controls
		SET title = 'Re-seeded title', description = 'Re-seeded description', updated_at = NOW()
		WHERE id = $1`, controlID); err != nil {
		t.Fatalf("re-seed control metadata: %v", err)
	}

	assessments, err := loadControlAssessments(ctx, f.db.DB, f.tenant, []uuid.UUID{controlID}, "platform")
	if err != nil {
		t.Fatalf("loadControlAssessments: %v", err)
	}
	if got := assessments[controlID]; got.Status != statusPass {
		t.Fatalf("control whose TITLE was re-seeded = %+v, want PASS — a metadata edit is not "+
			"a rule change, and treating it as one blanks every framework's score on every upgrade", got)
	}
}

// TestIntegration_NoRollupRow_FailsOpen pins the deliberate fail-open direction.
// "Never folded" is a different claim from "folded before this control existed",
// and treating a missing rollup as staleness would move every control of every
// framework to NOT_ASSESSED on any install whose rollups have not been written.
func TestIntegration_NoRollupRow_FailsOpen(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	ctx := context.Background()
	seedTenantInventory(t, f.db, f.tenant)

	controlID := f.newControl(t, "OPEN-1", "High")
	f.seedMeasurementRow(t, controlID)
	// Deliberately no tenant_framework_scores row.

	assessments, err := loadControlAssessments(ctx, f.db.DB, f.tenant, []uuid.UUID{controlID}, "platform")
	if err != nil {
		t.Fatalf("loadControlAssessments: %v", err)
	}
	if got := assessments[controlID]; got.Status != statusPass {
		t.Fatalf("control on a tenant with no rollup row = %+v, want PASS (fail open)", got)
	}
}

// TestIntegration_FrameworkIDResolvers pins the lookups the mutation paths use to
// decide WHICH framework to reconcile. Both are read before their DELETE, so a
// wrong join here means either the wrong framework is reconciled or none is.
func TestIntegration_FrameworkIDResolvers(t *testing.T) {
	f := newAuthoringFixture(t, "published")

	controlID := f.newControl(t, "RES-1", "High")
	measurementID := f.seedMeasurementRow(t, controlID)

	got, err := f.svc.frameworkIDForControl(controlID)
	if err != nil {
		t.Fatalf("frameworkIDForControl: %v", err)
	}
	if got != f.frameworkID {
		t.Fatalf("frameworkIDForControl = %s, want %s", got, f.frameworkID)
	}

	got, err = f.svc.frameworkIDForMeasurement(measurementID)
	if err != nil {
		t.Fatalf("frameworkIDForMeasurement: %v", err)
	}
	if got != f.frameworkID {
		t.Fatalf("frameworkIDForMeasurement = %s, want %s", got, f.frameworkID)
	}

	// After the row is gone the link is unresolvable, which is exactly why both
	// delete paths resolve first.
	if err := f.svc.DeleteControlMeasurement(measurementID); err != nil {
		t.Fatalf("DeleteControlMeasurement: %v", err)
	}
	if _, err := f.svc.frameworkIDForMeasurement(measurementID); err == nil {
		t.Fatal("frameworkIDForMeasurement resolved a deleted measurement — " +
			"the delete paths' resolve-before-delete ordering would be pointless")
	}
}

// --- the measurement_types read ---------------------------------------------

// TestIntegration_MeasurementTypeRead_PopulatesJSONBFields is the regression for
// the defect that made AddControlMeasurement and UpdateControlMeasurement — the
// platform-admin "add / edit a measurement rule" endpoints behind admin-ui's
// measurement-rules modal — impossible to call successfully.
//
// models.MeasurementType declared valid_range / allowed_rule_types / enum_values /
// valid_operators / predicate_schema as plain maps and slices, but the columns
// are jsonb and database/sql scans jsonb into neither, with or without a value.
// So the SELECT at the top of both methods always failed and platform frameworks
// were only measurable through seed.sql.
//
// Asserting that the call now succeeds is NOT enough: a read that silently
// yielded empty lists would also succeed, because an empty allowed_rule_types
// means "no restriction" to the validator. So each half is pinned by the
// restriction biting — the fixture type allows only `threshold`, and lists
// operators that exclude `!=`.
func TestIntegration_MeasurementTypeRead_PopulatesJSONBFields(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	controlID := f.newControl(t, "MTR-1", "High")

	m, err := f.svc.AddControlMeasurement(controlID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "threshold",
		Predicate:         map[string]interface{}{"operator": ">=", "value": float64(30)},
		Weight:            1,
	})
	if err != nil {
		t.Fatalf("AddControlMeasurement: %v", err)
	}
	if m.Predicate["operator"] != ">=" {
		t.Fatalf("predicate did not round trip: %v", m.Predicate)
	}

	// allowed_rule_types = ["threshold"] must reject anything else. If the jsonb
	// column scanned to an empty slice the validator would fall through to its
	// data-type defaults, which allow `range` for an integer.
	if _, err := f.svc.AddControlMeasurement(controlID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "range",
		Predicate:         map[string]interface{}{"min": float64(1), "max": float64(2)},
		Weight:            1,
	}); err == nil {
		t.Fatal("a `range` rule was accepted for a measurement type whose allowed_rule_types is " +
			"[\"threshold\"] — allowed_rule_types arrived empty, so the read is still not populating it")
	}

	// valid_operators excludes "!=", and the default operator list allows it, so
	// this only fails if the column arrived populated.
	if _, err := f.svc.AddControlMeasurement(controlID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "threshold",
		Predicate:         map[string]interface{}{"operator": "!=", "value": float64(30)},
		Weight:            1,
	}); err == nil {
		t.Fatal("operator `!=` was accepted for a measurement type that does not list it — " +
			"valid_operators arrived empty")
	}

	// UpdateControlMeasurement runs the same read.
	if _, err := f.svc.UpdateControlMeasurement(m.ID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "threshold",
		Predicate:         map[string]interface{}{"operator": "<=", "value": float64(7)},
		Weight:            2,
	}); err != nil {
		t.Fatalf("UpdateControlMeasurement: %v", err)
	}
}

// TestIntegration_MeasurementTypeRead_ToleratesNullColumns pins the other
// polarity, which is the shape EVERY seeded measurement type actually has:
// scripts/database/seed.sql never sets extraction_query, and leaves units,
// valid_range, enum_values and valid_operators NULL on most rows. NULL scans
// into a Go string no better than jsonb does, so a fix that only re-typed the
// jsonb fields would still fail on all 18 real rows while passing against a
// fully-populated fixture.
func TestIntegration_MeasurementTypeRead_ToleratesNullColumns(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	controlID := f.newControl(t, "MTR-2", "High")

	// Mirrors seed.sql's `cert_algorithm`: enum, no extraction_query, no units,
	// no valid_range, no valid_operators, no predicate_schema.
	const code = "authoring_fixture_nulls"
	var typeID uuid.UUID
	if err := f.db.Get(&typeID, `
		INSERT INTO measurement_types (code, name, description, data_type, allowed_rule_types, enum_values, category)
		VALUES ($1, 'Authoring fixture (nulls)', NULL, 'enum', '["pattern","presence"]'::jsonb,
		        '["RSA","ECDSA"]'::jsonb, NULL)
		ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, code); err != nil {
		t.Fatalf("seed null-column measurement type: %v", err)
	}
	t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM measurement_types WHERE id = $1`, typeID) })

	if _, err := f.svc.AddControlMeasurement(controlID, &models.ControlMeasurementInput{
		MeasurementTypeID: typeID,
		RuleType:          "pattern",
		Predicate:         map[string]interface{}{"pattern": "^RSA$"},
		Weight:            1,
	}); err != nil {
		t.Fatalf("AddControlMeasurement against a measurement type with NULL columns: %v", err)
	}
}

// TestIntegration_ControlMeasurement_SeverityOverrideIsOptional pins the second
// half of the same "cannot succeed at all" defect, which only became visible once
// the measurement_types read stopped failing first.
//
// severity_override is nullable under a CHECK admitting only the four severity
// labels. The input field is optional and the admin-ui rule builder leaves it
// blank by default, so the common case wrote ” — which the CHECK rejects — and
// the RETURNING clause then scanned a NULL back into a plain string.
func TestIntegration_ControlMeasurement_SeverityOverrideIsOptional(t *testing.T) {
	f := newAuthoringFixture(t, "published")
	controlID := f.newControl(t, "SEV-1", "High")

	blank, err := f.svc.AddControlMeasurement(controlID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "threshold",
		Predicate:         map[string]interface{}{"operator": ">=", "value": float64(30)},
		Weight:            1,
	})
	if err != nil {
		t.Fatalf("AddControlMeasurement without a severity override: %v", err)
	}
	if blank.SeverityOverride != "" {
		t.Fatalf("SeverityOverride = %q, want \"\" — an absent override must read back as absent", blank.SeverityOverride)
	}

	// An explicit override still round trips, in both directions.
	set, err := f.svc.AddControlMeasurement(controlID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "threshold",
		Predicate:         map[string]interface{}{"operator": ">=", "value": float64(60)},
		SeverityOverride:  "Critical",
		Weight:            1,
	})
	if err != nil {
		t.Fatalf("AddControlMeasurement with a severity override: %v", err)
	}
	if set.SeverityOverride != "Critical" {
		t.Fatalf("SeverityOverride = %q, want Critical", set.SeverityOverride)
	}

	// Clearing an override on update must null it, not write ''.
	cleared, err := f.svc.UpdateControlMeasurement(set.ID, &models.ControlMeasurementInput{
		MeasurementTypeID: f.typeID,
		RuleType:          "threshold",
		Predicate:         map[string]interface{}{"operator": ">=", "value": float64(60)},
		Weight:            1,
	})
	if err != nil {
		t.Fatalf("UpdateControlMeasurement clearing the severity override: %v", err)
	}
	if cleared.SeverityOverride != "" {
		t.Fatalf("SeverityOverride = %q after clearing, want empty", cleared.SeverityOverride)
	}
}

// TestIntegration_ListMeasurementTypes_ReadsEverySeededRow covers the read the
// admin-ui modal makes first: it populates the rule builder's measurement-type
// picker, so if it fails there is nothing to author a rule against. It goes
// through the same column list, against the real seeded catalog rather than a
// fixture row.
func TestIntegration_ListMeasurementTypes_ReadsEverySeededRow(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")

	var types []models.MeasurementType
	if err := db.Select(&types, `
		SELECT `+models.MeasurementTypeColumns+`
		FROM measurement_types
		ORDER BY category, code`); err != nil {
		t.Fatalf("list measurement types: %v", err)
	}
	if len(types) == 0 {
		t.Fatal("no measurement types in the database — seed.sql did not run, so this proves nothing")
	}

	var withRuleTypes int
	for _, mt := range types {
		if len(mt.AllowedRuleTypes) > 0 {
			withRuleTypes++
		}
	}
	if withRuleTypes == 0 {
		t.Fatal("every measurement type came back with an empty allowed_rule_types — " +
			"seed.sql sets it on all of them, so the jsonb read is dropping the value")
	}
}
