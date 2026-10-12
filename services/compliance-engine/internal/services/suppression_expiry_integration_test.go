package services

// A time-boxed suppression has to end. suppressed_until was stored for a long
// time and read by nothing, so "suppress for 30 days" was permanent: the
// finding stayed SUPPRESSED, the control stayed green, and nothing reopened it.
//
// These drive the real FindingsService against Postgres (skip without
// TEST_DATABASE_URL; `make test-integration-db`).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

func (f *licenseScopeFixture) workflow(t *testing.T, findingID uuid.UUID) (status string, until *time.Time) {
	t.Helper()
	if err := f.db.QueryRow(`SELECT workflow_status, suppressed_until FROM findings WHERE id = $1`, findingID).
		Scan(&status, &until); err != nil {
		t.Fatalf("read workflow status: %v", err)
	}
	return status, until
}

// openCount counts the tenant's findings on a control that openFindingPredicate
// calls open.
func (f *licenseScopeFixture) openCount(t *testing.T, controlID uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM findings f
		WHERE f.tenant_id = $1 AND f.control_id = $2 AND `+openFindingPredicate("f"),
		f.tenant, controlID).Scan(&n); err != nil {
		t.Fatalf("count open findings: %v", err)
	}
	return n
}

func TestIntegration_ExpiredSuppression_ReopensAndTheControlCountsItAgain(t *testing.T) {
	f := newLicenseScopeFixture(t)
	f.svc.bypassDB = f.db
	user := seedRefsUser(t, f.db, f.tenant)
	reason := "accepted risk until the vendor patch lands"

	// NEW -> NOTIFIED -> SUPPRESSED(30 days). The prior status the sweep must
	// restore is NOTIFIED, not the NEW default.
	if err := f.svc.UpdateWorkflowStatus(f.tenant, f.licensedFinding, user, "NOTIFIED", nil, nil); err != nil {
		t.Fatalf("notify: %v", err)
	}
	until := time.Now().Add(30 * 24 * time.Hour)
	if err := f.svc.UpdateWorkflowStatus(f.tenant, f.licensedFinding, user, "SUPPRESSED", &reason, &until); err != nil {
		t.Fatalf("suppress: %v", err)
	}

	details := func() int {
		d, err := f.eval.GetControlDetails(f.tenant, f.licensedControl, nil, models.ScenarioFilters{}, 1, 10)
		if err != nil {
			t.Fatalf("GetControlDetails: %v", err)
		}
		return d.EvidenceSummary.FailingFindingsCount
	}

	// While the suppression is in force nothing counts it, and a sweep leaves it be.
	if got := f.openCount(t, f.licensedControl); got != 0 {
		t.Fatalf("suppressed finding counted as open (%d)", got)
	}
	if got, err := f.svc.ExpireSuppressions(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("sweep before the deadline reopened %d (err %v), want 0", len(got), err)
	}
	if status, _ := f.workflow(t, f.licensedFinding); status != "SUPPRESSED" {
		t.Fatalf("status = %s before the deadline, want SUPPRESSED", status)
	}
	if got := details(); got != 0 {
		t.Fatalf("control counts a suppressed finding (%d)", got)
	}

	// The deadline passes. The predicate sees it at once, before any sweep.
	if _, err := f.db.Exec(`UPDATE findings SET suppressed_until = NOW() - interval '1 minute' WHERE id = $1`, f.licensedFinding); err != nil {
		t.Fatal(err)
	}
	if got := f.openCount(t, f.licensedControl); got != 1 {
		t.Fatalf("expired suppression still hidden from openFindingPredicate (%d open)", got)
	}

	// The sweep restores the prior status, clears the deadline, and reports the
	// tenant so the caller can reconcile it.
	expired, err := f.svc.ExpireSuppressions(context.Background())
	if err != nil {
		t.Fatalf("ExpireSuppressions: %v", err)
	}
	if len(expired) != 1 || expired[0].FindingID != f.licensedFinding || expired[0].TenantID != f.tenant || expired[0].RestoredStatus != "NOTIFIED" {
		t.Fatalf("sweep result = %+v, want the one finding restored to NOTIFIED", expired)
	}
	status, gotUntil := f.workflow(t, f.licensedFinding)
	if status != "NOTIFIED" || gotUntil != nil {
		t.Fatalf("after sweep: status=%s until=%v, want NOTIFIED / nil", status, gotUntil)
	}
	var hist int
	if err := f.db.QueryRow(`SELECT count(*) FROM compliance_finding_history
		WHERE finding_id = $1 AND new_value = 'NOTIFIED' AND old_value = 'SUPPRESSED'`, f.licensedFinding).Scan(&hist); err != nil || hist != 1 {
		t.Fatalf("history rows for the reopening = %d (err %v), want 1", hist, err)
	}
	if got := details(); got != 1 {
		t.Fatalf("control counts %d failing findings after expiry, want 1", got)
	}

	// Idempotent.
	if again, err := f.svc.ExpireSuppressions(context.Background()); err != nil || len(again) != 0 {
		t.Fatalf("second sweep reopened %d (err %v), want 0", len(again), err)
	}
}

// A suppression with no deadline is indefinite on purpose and must survive.
func TestIntegration_OpenEndedSuppression_IsNotSwept(t *testing.T) {
	f := newLicenseScopeFixture(t)
	f.svc.bypassDB = f.db
	reason := "will never fix: decommissioned next quarter"
	if err := f.svc.UpdateWorkflowStatus(f.tenant, f.licensedFinding, seedRefsUser(t, f.db, f.tenant), "SUPPRESSED", &reason, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := f.svc.ExpireSuppressions(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("swept an open-ended suppression: %v (err %v)", got, err)
	}
	if got := f.openCount(t, f.licensedControl); got != 0 {
		t.Fatalf("open-ended suppression counted as open")
	}
}

func TestIntegration_AssignFindingOwner_RequiresATenantUser(t *testing.T) {
	f := newLicenseScopeFixture(t)
	member := uuid.New()
	if _, err := f.db.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		member, f.tenant, "m-"+member.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	err := f.svc.AssignFindingOwner(f.tenant, f.licensedFinding, uuid.New(), member, nil)
	if ie, ok := AsInputError(err); !ok || !ie.Missing || ie.Field != "assigned_to" {
		t.Fatalf("assigning a stranger = %v, want a Missing InputError on assigned_to", err)
	}
	if err := f.svc.AssignFindingOwner(f.tenant, f.licensedFinding, member, member, nil); err != nil {
		t.Fatalf("assigning a tenant user: %v", err)
	}
	if err := f.svc.AssignFindingOwner(f.tenant, uuid.New(), member, member, nil); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("unknown finding = %v, want ErrFindingNotFound", err)
	}
}
