package jobs

// ControlNoncompliantScanJob's raise-on-change guard.
//
// scanTenant used to call Raise for EVERY noncompliant control on EVERY pass,
// unconditionally — the query that finds noncompliant controls matches the
// same row on every interval until its findings clear, and nothing compared
// that against the alert already open for it. The alert engine dedupes a
// same-severity re-raise into a silent TOUCH, so this never duplicated an
// alert, but it still moved `updated_at`/`last_event_at` on every pass and (on
// a tenant with hundreds of noncompliant controls) issued hundreds of pointless
// UPDATEs an hour. FindingsAlertScanJob in this same package already guards
// this with `severityWorse` (see its "Raise-on-change" doc comment); this test
// pins the identical guard now applied here.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ControlNoncompliantScan_RaiseOnChange(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	author := h.newPlatformAuthor(t)

	frameworkID := uuid.New()
	h.exec(t, `INSERT INTO platform_frameworks (id, code, name, version, organization, created_by)
	           VALUES ($1,$2,'Raise On Change FW','1.0','Vista Platform Test',$3)`,
		frameworkID, "roc-"+uuid.NewString()[:8], author)
	h.exec(t, `INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
	           VALUES ($1,$2,'active')`, tenant, frameworkID)

	controlID := uuid.New()
	h.exec(t, `INSERT INTO platform_framework_controls (id, framework_id, control_id, title, baseline_severity)
	           VALUES ($1,$2,$3,'Control','Low')`, controlID, frameworkID, "ROC-1")
	h.exec(t, `INSERT INTO findings
	             (tenant_id, producer, kind, control_id, subject_id, subject_type,
	              severity, summary, detection_state, workflow_status)
	           VALUES ($1,'compliance','control_noncompliant',$2,$3,'asset',
	                   'low','weak cipher negotiated','ACTIVE','NEW')`,
		tenant, controlID, uuid.New())

	job := NewControlNoncompliantScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()

	if got := h.alertCount(t, tenant, "control_noncompliant"); got != 1 {
		t.Fatalf("got %d control_noncompliant alerts, want 1", got)
	}
	alertID, severity, _ := h.alertRow(t, tenant, "control_noncompliant")
	if severity != "low" {
		t.Fatalf("severity = %q, want low (the control's baseline_severity)", severity)
	}
	opened := h.alertEventCount(t, alertID)
	if opened != 1 {
		t.Fatalf("a newly opened alert has %d events, want 1 (opened)", opened)
	}

	// A second pass with nothing changed must write nothing: no new alert, no
	// new event, and — the raise-on-change rule — no touch either. This is the
	// assertion that fails without the fix: the control still matches the
	// noncompliant-controls query every pass, so scanTenant called Raise again,
	// and the engine's dedupe-into-touch moved these timestamps even though
	// nothing about the control changed.
	updatedAt, lastEventAt := h.alertTouchedAt(t, alertID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "control_noncompliant"); got != 1 {
		t.Fatalf("a re-scan duplicated the alert: got %d, want 1", got)
	}
	if got := h.alertEventCount(t, alertID); got != opened {
		t.Fatalf("an unchanged re-scan appended %d event(s)", got-opened)
	}
	gotUpdated, gotLastEvent := h.alertTouchedAt(t, alertID)
	if !gotUpdated.Equal(updatedAt) || !gotLastEvent.Equal(lastEventAt) {
		t.Fatalf("an unchanged re-scan touched the alert (updated_at %v -> %v, last_event_at %v -> %v) — "+
			"the job re-raised a control whose noncompliance had not changed",
			updatedAt, gotUpdated, lastEventAt, gotLastEvent)
	}

	// The control's baseline severity is raised (an admin edit in the Catalog):
	// the same alert escalates, and the escalation DOES append an event.
	h.exec(t, `UPDATE platform_framework_controls SET baseline_severity = 'Critical' WHERE id = $1`, controlID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "control_noncompliant"); got != 1 {
		t.Fatalf("escalation opened a second alert: got %d, want 1", got)
	}
	_, severity, _ = h.alertRow(t, tenant, "control_noncompliant")
	if severity != "critical" {
		t.Fatalf("severity after escalation = %q, want critical", severity)
	}
	if got := h.alertEventCount(t, alertID); got != opened+1 {
		t.Fatalf("escalation appended %d event(s), want 1", got-opened)
	}
}
