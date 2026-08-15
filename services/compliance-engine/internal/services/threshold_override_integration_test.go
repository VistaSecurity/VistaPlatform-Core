package services

// Database-integration tests for the `threshold_overrides` premium feature.
//
// The defect these pin: the authoring side (services/compliance-engine/ee/thresholds)
// validated entitlement, validated the framework licence, and wrote
// `tenant_measurement_overrides` rows — and nothing ever read them at evaluation
// time. The paying tenant's customised predicate was stored and ignored, which is
// indistinguishable from the feature working until you check the evaluation result.
//
// The fixture is end-to-end on purpose: a real certificate, a real measurement type,
// a real control measurement, evaluated through RuleEvaluator.EvaluateControl. A
// narrower test on the loader would have passed against a loader that nobody called.
//
// They skip unless TEST_DATABASE_URL is set (see shared/testdb): CI runs them in the
// nightly backend job; locally use `make test-integration-db`.

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// thresholdFixture is a platform control whose single measurement requires a
// certificate to have at least 30 days of life left, plus a certificate with 60
// days left — passing under the platform predicate.
type thresholdFixture struct {
	db            *sqlx.DB
	tenant        uuid.UUID
	controlID     uuid.UUID
	measurementID uuid.UUID
	userID        uuid.UUID
	evaluator     *RuleEvaluator
}

func newThresholdFixture(t *testing.T) *thresholdFixture {
	t.Helper()
	f := newEvalFixture(t) // published framework + two controls + active licence
	db := f.db

	// measurement_types is global and may already carry this code from seed.sql
	// (the nightly job seeds; the local ephemeral Postgres does not). Reuse the
	// existing row rather than mutating it.
	if _, err := db.Exec(`
		INSERT INTO measurement_types (code, name, data_type, category)
		VALUES ('cert_expiration_days', 'Certificate Expiration Days', 'integer', 'certificate')
		ON CONFLICT (code) DO NOTHING`); err != nil {
		t.Fatalf("seed measurement type: %v", err)
	}
	var measurementTypeID uuid.UUID
	if err := db.Get(&measurementTypeID, `SELECT id FROM measurement_types WHERE code = 'cert_expiration_days'`); err != nil {
		t.Fatalf("load measurement type: %v", err)
	}

	// newEvalFixture gives every control a default always-passing measurement so
	// its controls count as ASSESSED. This fixture is about ONE
	// measurement's predicate, so drop the default rather than score against a
	// second measurement nobody here is reasoning about.
	if _, err := db.Exec(`DELETE FROM control_measurements WHERE control_id = $1`, f.critical); err != nil {
		t.Fatalf("clear default control measurements: %v", err)
	}

	// Platform predicate: at least 30 days of remaining life.
	measurementID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO control_measurements (id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight)
		VALUES ($1, $2, 'platform', $3, 'threshold', '{"operator": ">=", "value": 30}'::jsonb, 'High', 1)`,
		measurementID, f.critical, measurementTypeID); err != nil {
		t.Fatalf("seed control measurement: %v", err)
	}

	// A certificate with ~60 days left: comfortably inside the platform threshold.
	if _, err := db.Exec(`
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name, fingerprint_sha256,
		                          not_before, not_after, is_ca_certificate)
		VALUES ($1, $2, 'CN=it.example.test', 'CN=IT Issuer', 'it.example.test', md5(random()::text) || md5(random()::text),
		        NOW() - INTERVAL '30 days', NOW() + INTERVAL '60 days', false)`,
		uuid.New(), f.tenant); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	// tenant_measurement_overrides.created_by FKs to users.
	userID := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		userID, f.tenant, "it-"+userID.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	return &thresholdFixture{
		db:            db,
		tenant:        f.tenant,
		controlID:     f.critical,
		measurementID: measurementID,
		userID:        userID,
		evaluator:     NewRuleEvaluator(db, NewMeasurementExtractor(db)),
	}
}

// addOverride writes the tenant's customised predicate exactly as the Enterprise
// authoring service does.
func (f *thresholdFixture) addOverride(t *testing.T, tenantID uuid.UUID, predicate map[string]any, severity *string) {
	t.Helper()
	raw, err := json.Marshal(predicate)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO tenant_measurement_overrides
			(id, tenant_id, control_measurement_id, predicate_override, severity_override, rationale, created_by)
		VALUES ($1, $2, $3, $4, $5, 'integration fixture', $6)`,
		uuid.New(), tenantID, f.measurementID, raw, severity, f.userID); err != nil {
		t.Fatalf("seed override: %v", err)
	}
}

// TestIntegration_ThresholdOverride_AppliedAtEvaluation is the regression test for
// the no-op premium feature: a stricter tenant predicate must actually change the
// evaluation outcome.
func TestIntegration_ThresholdOverride_AppliedAtEvaluation(t *testing.T) {
	f := newThresholdFixture(t)

	// Baseline: the platform predicate (>= 30 days) passes for a 60-day cert.
	before, err := f.evaluator.EvaluateControl(f.tenant, f.controlID, "platform")
	if err != nil {
		t.Fatalf("EvaluateControl (baseline): %v", err)
	}
	if before.Status != "pass" || len(before.Findings) != 0 {
		t.Fatalf("baseline: status=%q findings=%d, want pass/0 — fixture is wrong, not the code",
			before.Status, len(before.Findings))
	}

	// The tenant pays for threshold_overrides and tightens it to 90 days.
	f.addOverride(t, f.tenant, map[string]any{"operator": ">=", "value": 90}, nil)

	after, err := f.evaluator.EvaluateControl(f.tenant, f.controlID, "platform")
	if err != nil {
		t.Fatalf("EvaluateControl (overridden): %v", err)
	}
	if len(after.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 — the tenant's 90-day predicate was not applied, "+
			"so the premium threshold_overrides feature had no effect",
			len(after.Findings))
	}
	if after.Status != "fail" {
		t.Fatalf("status = %q, want fail (severity_override High)", after.Status)
	}
	if after.Score == nil {
		t.Fatal("score = nil, want 0 — the control WAS assessed, it just failed")
	}
	if *after.Score != 0 {
		t.Fatalf("score = %d, want 0 (the only measurement now violates)", *after.Score)
	}
}

// TestIntegration_ThresholdOverride_SeverityOverrideApplied pins the second field
// the override row carries: it can also re-rate the violation's severity.
func TestIntegration_ThresholdOverride_SeverityOverrideApplied(t *testing.T) {
	f := newThresholdFixture(t)
	low := "Low"
	f.addOverride(t, f.tenant, map[string]any{"operator": ">=", "value": 90}, &low)

	res, err := f.evaluator.EvaluateControl(f.tenant, f.controlID, "platform")
	if err != nil {
		t.Fatalf("EvaluateControl: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if res.Findings[0].Severity != "Low" {
		t.Fatalf("finding severity = %q, want Low (the override re-rates it from High)", res.Findings[0].Severity)
	}
	// A violated control FAILS whatever the severity. This expectation
	// has now moved twice — "warn" under the live path's own mapping, then
	// "pass" once it delegated to statusForWorstSeverity — and both were wrong
	// for the same reason: severity was deciding the verdict. It is the WEIGHT.
	// The severity re-rating asserted above is what this test is really about,
	// and it still re-rates: the finding is Low, so the control now contributes
	// weight 1 rather than 3 to the framework score.
	if res.Status != "fail" {
		t.Fatalf("status = %q, want fail — the measurement was violated; severity only sets the weight", res.Status)
	}
}

// TestIntegration_ThresholdOverride_IsTenantScoped proves the override is a
// per-tenant customisation and not a global edit of the platform framework:
// another tenant subscribed to the same framework must still be evaluated
// against the platform predicate.
func TestIntegration_ThresholdOverride_IsTenantScoped(t *testing.T) {
	f := newThresholdFixture(t)

	other := testdb.NewTenant(t, f.db.DB)
	if _, err := f.db.Exec(`
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name, fingerprint_sha256,
		                          not_before, not_after, is_ca_certificate)
		VALUES ($1, $2, 'CN=other.example.test', 'CN=IT Issuer', 'other.example.test', md5(random()::text) || md5(random()::text),
		        NOW() - INTERVAL '30 days', NOW() + INTERVAL '60 days', false)`,
		uuid.New(), other); err != nil {
		t.Fatalf("seed other-tenant certificate: %v", err)
	}

	// Only the first tenant overrides.
	f.addOverride(t, f.tenant, map[string]any{"operator": ">=", "value": 90}, nil)

	mine, err := f.evaluator.EvaluateControl(f.tenant, f.controlID, "platform")
	if err != nil {
		t.Fatalf("EvaluateControl (overriding tenant): %v", err)
	}
	theirs, err := f.evaluator.EvaluateControl(other, f.controlID, "platform")
	if err != nil {
		t.Fatalf("EvaluateControl (other tenant): %v", err)
	}
	if len(mine.Findings) != 1 {
		t.Fatalf("overriding tenant: findings = %d, want 1", len(mine.Findings))
	}
	if len(theirs.Findings) != 0 {
		t.Fatalf("other tenant: findings = %d, want 0 — one tenant's override leaked into another's evaluation",
			len(theirs.Findings))
	}
}

// TestIntegration_ThresholdOverride_EmptyPredicateIgnored pins the defensive case.
// `predicate_override` is NOT NULL, so a malformed authoring call can land `{}`,
// and every rule evaluator branch returns "passed" when it can't read its
// predicate. Silently disabling a control is the worst possible reading of an
// empty override, so the platform predicate stands.
func TestIntegration_ThresholdOverride_EmptyPredicateIgnored(t *testing.T) {
	f := newThresholdFixture(t)
	f.addOverride(t, f.tenant, map[string]any{}, nil)

	res, err := f.evaluator.EvaluateControl(f.tenant, f.controlID, "platform")
	if err != nil {
		t.Fatalf("EvaluateControl: %v", err)
	}
	// Platform predicate (>= 30) still applies, and the 60-day cert satisfies it.
	if res.Status != "pass" || len(res.Findings) != 0 {
		t.Fatalf("status=%q findings=%d, want pass/0 — an empty override must not replace the platform predicate",
			res.Status, len(res.Findings))
	}
}
