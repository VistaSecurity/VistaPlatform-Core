package services

// Database-integration tests for the READ GATE on materialized findings
// (licensedFindingScopeSQL).
//
// The engine persists findings for EVERY published framework, activated or not
// (ADR-0015) so unactivated frameworks can show a preview score. ADR-0015 pairs
// that with "drill-down is the reward for activation, enforced at the read
// layer" — and that half was never built. On a live tenant with ONE activated
// framework the product showed four on Findings → By Framework, a Dashboard
// "5 Critical" sourced entirely from an unactivated framework, and a Posture
// page whose Top Exposures panel disagreed with the control grid beside it.
//
// These tests pin the gate on every tenant-facing reader. They deliberately
// assert BOTH directions: the unactivated framework's findings are hidden, and
// the activated one's are still returned — a gate that hides everything would
// "pass" a one-sided test while breaking the product completely.
//
// They skip unless TEST_DATABASE_URL is set (see shared/testdb); locally use
// `make test-integration-db`.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// licenseScopeFixture is two published platform frameworks, one control each,
// with an ACTIVE finding on both — but only one framework licensed to the tenant.
type licenseScopeFixture struct {
	svc               *FindingsService
	eval              *EvaluationService
	db                *sqlx.DB
	tenant            uuid.UUID
	licensedFwID      uuid.UUID
	licensedControl   uuid.UUID
	licensedFinding   uuid.UUID
	unlicensedFwID    uuid.UUID
	unlicensedControl uuid.UUID
	unlicensedFinding uuid.UUID
	assetID           uuid.UUID
}

// seedPlatformFrameworkAuthor mints the platform_roles → platform_users chain
// that platform_frameworks.created_by requires. The integration database is
// schema-only (no seed), so no admin exists to borrow.
func seedPlatformFrameworkAuthor(t *testing.T, db *sqlx.DB) (userID uuid.UUID, suffix string) {
	t.Helper()
	roleID, userID := uuid.New(), uuid.New()
	suffix = roleID.String()[:8]
	if _, err := db.Exec(`INSERT INTO platform_roles (id, name, display_name) VALUES ($1, $2, $3)`,
		roleID, "lic-role-"+suffix, "Lic Role"); err != nil {
		t.Fatalf("seed platform role: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_roles WHERE id = $1`, roleID) })
	if _, err := db.Exec(`
		INSERT INTO platform_users (id, email, password_hash, first_name, last_name, role_id)
		VALUES ($1, $2, 'x', 'Lic', 'User', $3)`,
		userID, "lic-"+suffix+"@example.test", roleID); err != nil {
		t.Fatalf("seed platform user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_users WHERE id = $1`, userID) })
	return userID, suffix
}

// seedPublishedFramework inserts a published platform framework, optionally
// activating it for the tenant, and returns its id plus a control minter.
//
// Every findings test needs this now: since licensedFindingScopeSQL gates the
// tenant-facing readers, a finding hung off a bare random control id is
// invisible by design — it belongs to no framework at all.
func seedPublishedFramework(t *testing.T, db *sqlx.DB, tenant uuid.UUID, code string, activate bool) (uuid.UUID, func(severity string) uuid.UUID) {
	t.Helper()
	userID, suffix := seedPlatformFrameworkAuthor(t, db)
	frameworkID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO platform_frameworks (id, code, name, version, description, organization, status, created_by)
		VALUES ($1, $2, 'Lic Scope Framework', '1.0', 'integration fixture', 'IT Org', 'published', $3)`,
		frameworkID, code+"-"+suffix, userID); err != nil {
		t.Fatalf("seed framework %s: %v", code, err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_frameworks WHERE id = $1`, frameworkID) })

	if activate {
		if _, err := db.Exec(`
			INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
			VALUES ($1, $2, 'active')`, tenant, frameworkID); err != nil {
			t.Fatalf("seed license for %s: %v", code, err)
		}
	}

	n := 0
	newControl := func(severity string) uuid.UUID {
		n++
		id := uuid.New()
		controlCode := fmt.Sprintf("C-%s-%d", suffix, n)
		if _, err := db.Exec(`
			INSERT INTO platform_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant)
			VALUES ($1, $2, $3, $4, 'integration fixture control', $5, true)`,
			id, frameworkID, controlCode, "Control "+controlCode, severity); err != nil {
			t.Fatalf("seed control %s: %v", controlCode, err)
		}
		return id
	}
	return frameworkID, newControl
}

func newLicenseScopeFixture(t *testing.T) *licenseScopeFixture {
	t.Helper()
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	licensedFwID, newLicensedControl := seedPublishedFramework(t, db, tenant, "lic-yes", true)
	unlicensedFwID, newUnlicensedControl := seedPublishedFramework(t, db, tenant, "lic-no", false)

	f := &licenseScopeFixture{
		svc: &FindingsService{db: db}, eval: NewEvaluationService(db), db: db, tenant: tenant,
		licensedFwID: licensedFwID, licensedControl: newLicensedControl("Critical"),
		unlicensedFwID: unlicensedFwID, unlicensedControl: newUnlicensedControl("Critical"),
		assetID: uuid.New(),
	}

	// One ACTIVE finding under each framework — the state the engine really
	// produces, since it materializes for every published framework.
	f.licensedFinding = f.writeFinding(t, f.licensedControl)
	f.unlicensedFinding = f.writeFinding(t, f.unlicensedControl)
	return f
}

func (f *licenseScopeFixture) writeFinding(t *testing.T, controlID uuid.UUID) uuid.UUID {
	t.Helper()
	findingID := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO compliance_findings (id, tenant_id, control_id, asset_id, asset_type, severity, summary, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, 'network_asset', 'Critical', 'lic scope fixture', 'ACTIVE', 'NEW')`,
		findingID, f.tenant, controlID, f.assetID); err != nil {
		t.Fatalf("seed finding for control %s: %v", controlID, err)
	}
	return findingID
}

// TestIntegration_Findings_ListExcludesUnactivatedFrameworks is the headline
// case: the Findings page must show only frameworks the tenant activated.
func TestIntegration_Findings_ListExcludesUnactivatedFrameworks(t *testing.T) {
	f := newLicenseScopeFixture(t)

	findings, total, err := f.svc.ListFindings(f.tenant, FindingListFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 1 || len(findings) != 1 {
		t.Fatalf("ListFindings returned %d findings (total %d), want exactly 1 — the unactivated framework's finding must not be listed", len(findings), total)
	}
	if findings[0].ControlID != f.licensedControl {
		t.Errorf("ListFindings returned the control of an unactivated framework: got %s, want %s", findings[0].ControlID, f.licensedControl)
	}
}

// The Dashboard's severity tiles read these counts. An unactivated framework's
// Criticals landing here is what made the Dashboard read "5 Critical" for a
// tenant whose only activated framework had none.
func TestIntegration_Findings_StatisticsExcludeUnactivatedFrameworks(t *testing.T) {
	f := newLicenseScopeFixture(t)

	stats, err := f.svc.GetFindingStatistics(f.tenant)
	if err != nil {
		t.Fatalf("GetFindingStatistics: %v", err)
	}
	if stats.SeverityCounts.Critical != 1 {
		t.Errorf("Critical count = %d, want 1 (only the activated framework's finding)", stats.SeverityCounts.Critical)
	}
	if stats.ActiveFindings != 1 {
		t.Errorf("ActiveFindings = %d, want 1", stats.ActiveFindings)
	}
	if stats.NewFindings != 1 {
		t.Errorf("NewFindings = %d, want 1", stats.NewFindings)
	}
}

// Feeds Findings → By Control AND the Posture page's Top Exposures panel, which
// is why an ungated version made Posture contradict itself on one screen.
func TestIntegration_Findings_ByControlExcludesUnactivatedFrameworks(t *testing.T) {
	f := newLicenseScopeFixture(t)

	groups, err := f.svc.GetFindingsByControl(f.tenant, 50)
	if err != nil {
		t.Fatalf("GetFindingsByControl: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("GetFindingsByControl returned %d groups, want 1", len(groups))
	}
	if groups[0].FrameworkID != f.licensedFwID {
		t.Errorf("group framework = %s, want the activated framework %s", groups[0].FrameworkID, f.licensedFwID)
	}
}

func TestIntegration_Findings_ByAssetExcludesUnactivatedFrameworks(t *testing.T) {
	f := newLicenseScopeFixture(t)

	findings, err := f.svc.GetFindingsByAsset(f.tenant, f.assetID)
	if err != nil {
		t.Fatalf("GetFindingsByAsset: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("GetFindingsByAsset returned %d findings, want 1", len(findings))
	}
	if findings[0].ControlID != f.licensedControl {
		t.Errorf("returned the control of an unactivated framework: %s", findings[0].ControlID)
	}
}

func TestIntegration_Findings_DirectLookupRequiresActivatedFramework(t *testing.T) {
	f := newLicenseScopeFixture(t)

	if _, err := f.svc.GetFinding(f.tenant, f.licensedFinding); err != nil {
		t.Fatalf("GetFinding licensed: %v", err)
	}
	if _, err := f.svc.GetFinding(f.tenant, f.unlicensedFinding); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("GetFinding unlicensed: got %v, want ErrFindingNotFound", err)
	}
}

func TestIntegration_Findings_DirectMutationsRequireActivatedFramework(t *testing.T) {
	f := newLicenseScopeFixture(t)
	actor := uuid.New()
	assignee := uuid.New()

	if err := f.svc.AssignFindingOwner(f.tenant, f.unlicensedFinding, assignee, actor, nil); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("AssignFindingOwner unlicensed: got %v, want ErrFindingNotFound", err)
	}
	if err := f.svc.UpdateWorkflowStatus(f.tenant, f.unlicensedFinding, actor, "RESOLVED", nil, nil); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("UpdateWorkflowStatus unlicensed: got %v, want ErrFindingNotFound", err)
	}

	var status string
	if err := f.db.Get(&status, `SELECT workflow_status FROM compliance_findings WHERE id = $1`, f.unlicensedFinding); err != nil {
		t.Fatalf("read workflow status: %v", err)
	}
	if status != "NEW" {
		t.Fatalf("unlicensed finding was mutated: workflow_status = %q, want NEW", status)
	}
}

func TestIntegration_Findings_EvidenceAndHistoryRequireActivatedFramework(t *testing.T) {
	f := newLicenseScopeFixture(t)

	if _, _, err := f.svc.GetEvidenceID(f.tenant, f.unlicensedFinding); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("GetEvidenceID unlicensed: got %v, want ErrFindingNotFound", err)
	}
	if _, err := f.svc.GetFindingHistory(f.tenant, f.unlicensedFinding); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("GetFindingHistory unlicensed: got %v, want ErrFindingNotFound", err)
	}
}

func TestIntegration_Findings_ControlDetailsExcludeUnactivatedFrameworkFindings(t *testing.T) {
	f := newLicenseScopeFixture(t)

	licensed, err := f.eval.GetControlDetails(f.tenant, f.licensedControl, nil, models.ScenarioFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("GetControlDetails licensed: %v", err)
	}
	if len(licensed.Findings) != 1 {
		t.Fatalf("licensed control details returned %d findings, want 1", len(licensed.Findings))
	}

	unlicensed, err := f.eval.GetControlDetails(f.tenant, f.unlicensedControl, nil, models.ScenarioFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("GetControlDetails unlicensed: %v", err)
	}
	if len(unlicensed.Findings) != 0 {
		t.Fatalf("unlicensed control details returned %d findings, want 0", len(unlicensed.Findings))
	}
	total, err := f.eval.GetControlDetailsTotalCount(f.tenant, f.unlicensedControl, models.ScenarioFilters{})
	if err != nil {
		t.Fatalf("GetControlDetailsTotalCount unlicensed: %v", err)
	}
	if total != 0 {
		t.Fatalf("unlicensed control detail total = %d, want 0", total)
	}
}

// A lapsed subscription must read like no subscription. The gate reuses the same
// active-status + not-expired predicate the alerting jobs use, so a cancelled or
// expired activation stops surfacing findings without any other bookkeeping.
func TestIntegration_Findings_LapsedSubscriptionHidesFindings(t *testing.T) {
	f := newLicenseScopeFixture(t)

	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"cancelled", `UPDATE tenant_framework_licenses SET subscription_status = 'cancelled' WHERE tenant_id = $1`},
		{"expired", `UPDATE tenant_framework_licenses SET subscription_status = 'active', subscription_expires_at = NOW() - INTERVAL '1 day' WHERE tenant_id = $1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.db.Exec(tc.sql, f.tenant); err != nil {
				t.Fatalf("update license: %v", err)
			}
			_, total, err := f.svc.ListFindings(f.tenant, FindingListFilters{}, 1, 50)
			if err != nil {
				t.Fatalf("ListFindings: %v", err)
			}
			if total != 0 {
				t.Errorf("ListFindings returned %d findings under a %s subscription, want 0", total, tc.name)
			}
		})
	}

	// Restore, and prove the gate is not simply hiding everything — the same
	// query must return the finding again once the subscription is active.
	if _, err := f.db.Exec(`
		UPDATE tenant_framework_licenses SET subscription_status = 'active', subscription_expires_at = NULL WHERE tenant_id = $1`,
		f.tenant); err != nil {
		t.Fatalf("restore license: %v", err)
	}
	_, total, err := f.svc.ListFindings(f.tenant, FindingListFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 1 {
		t.Errorf("ListFindings returned %d findings after restoring the subscription, want 1", total)
	}
}

// Custom policies (tenant_frameworks) are authored by the tenant and carry no
// license row at all — gating on tenant_framework_licenses alone would hide
// every Enterprise custom-policy finding, which is the obvious way to get this
// fix wrong.
func TestIntegration_Findings_TenantCustomPolicyFindingsStayVisible(t *testing.T) {
	f := newLicenseScopeFixture(t)

	tenantFwID, tenantControlID := uuid.New(), uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO tenant_frameworks (id, tenant_id, name, version, description)
		VALUES ($1, $2, 'Custom Policy', '1.0', 'integration fixture')`,
		tenantFwID, f.tenant); err != nil {
		t.Fatalf("seed tenant framework: %v", err)
	}
	t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM tenant_frameworks WHERE id = $1`, tenantFwID) })

	if _, err := f.db.Exec(`
		INSERT INTO tenant_framework_controls (id, framework_id, control_id, title, description, baseline_severity, crypto_relevant)
		VALUES ($1, $2, 'TC-1', 'Custom control', 'integration fixture control', 'Critical', true)`,
		tenantControlID, tenantFwID); err != nil {
		t.Fatalf("seed tenant control: %v", err)
	}
	f.writeFinding(t, tenantControlID)

	findings, total, err := f.svc.ListFindings(f.tenant, FindingListFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 {
		t.Fatalf("ListFindings returned %d findings, want 2 (licensed platform + custom policy)", total)
	}
	seen := map[uuid.UUID]bool{}
	for _, x := range findings {
		seen[x.ControlID] = true
	}
	if !seen[tenantControlID] {
		t.Error("a tenant custom-policy finding was hidden — custom policies need no license")
	}
	if !seen[f.licensedControl] {
		t.Error("the licensed platform framework's finding went missing")
	}
	if seen[f.unlicensedControl] {
		t.Error("the unactivated framework's finding is still listed")
	}
}

// Guard against the gate quietly changing what a non-finding filter means: an
// explicit framework filter still narrows within the visible set.
func TestIntegration_Findings_FrameworkFilterStillApplies(t *testing.T) {
	f := newLicenseScopeFixture(t)

	_, total, err := f.svc.ListFindings(f.tenant, FindingListFilters{FrameworkID: &f.licensedFwID}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 1 {
		t.Errorf("filtering to the activated framework returned %d, want 1", total)
	}

	// Filtering to an unactivated framework yields nothing — the gate wins.
	_, total, err = f.svc.ListFindings(f.tenant, FindingListFilters{FrameworkID: &f.unlicensedFwID}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 0 {
		t.Errorf("filtering to an unactivated framework returned %d, want 0", total)
	}
}
