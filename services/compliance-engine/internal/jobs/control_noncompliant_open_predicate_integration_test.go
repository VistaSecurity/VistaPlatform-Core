package jobs

// The control_noncompliant detector against the registry's ONE definition of an
// open finding (sharedfindings.OpenSQL — `detection_state:ACTIVE and
// workflow_status not in (RESOLVED, SUPPRESSED)`, ADR-0005 D3).
//
// The detector used to write its own near-miss of that predicate:
// `detection_state = 'ACTIVE' AND workflow_status <> 'SUPPRESSED'`. It agrees
// with the definition on three of the four workflow values and disagrees on the
// one that matters. A person who worked every finding on a control and marked
// them RESOLVED therefore kept the alert: Remediation → Alerts still said the
// control was noncompliant, with nothing open behind it, and the only way to
// clear it was to SUPPRESS findings they had genuinely fixed.
//
// All four states are asserted, because a predicate is pinned by the values it
// must EXCLUDE as much as by the one it must keep — a read narrowed to nothing
// would pass a one-sided test while breaking the detector completely.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ControlNoncompliantScan_UsesTheOpenFindingPredicate(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	author := h.newPlatformAuthor(t)

	frameworkID := uuid.New()
	h.exec(t, `INSERT INTO platform_frameworks (id, code, name, version, created_by)
	           VALUES ($1,$2,'Open Predicate FW','1.0',$3)`, frameworkID, "opf-"+uuid.NewString()[:8], author)
	h.exec(t, `INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
	           VALUES ($1,$2,'active')`, tenant, frameworkID)

	// One control per state, each with a single finding. Only the NEW one is
	// open; the other three are each a different way of being closed.
	controls := map[string]uuid.UUID{}
	for i, state := range []string{"NEW", "RESOLVED", "SUPPRESSED", "INACTIVE"} {
		id := uuid.New()
		controls[state] = id
		h.exec(t, `INSERT INTO platform_framework_controls (id, framework_id, control_id, title, baseline_severity)
		           VALUES ($1,$2,$3,'Control','High')`, id, frameworkID, fmt.Sprintf("OPF-%d", i+1))
		detection, workflow := "ACTIVE", state
		if state == "INACTIVE" {
			detection, workflow = "INACTIVE", "NEW"
		}
		h.exec(t, `INSERT INTO findings
		             (tenant_id, producer, kind, control_id, subject_id, subject_type,
		              severity, summary, detection_state, workflow_status)
		           VALUES ($1,'compliance','control_noncompliant',$2,$3,'asset',
		                   'high','weak cipher negotiated',$4,$5)`,
			tenant, id, uuid.New(), detection, workflow)
	}

	job := NewControlNoncompliantScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()

	if got := h.alertCount(t, tenant, "control_noncompliant"); got != 1 {
		t.Fatalf("got %d control_noncompliant alerts, want 1 — only the control with an OPEN finding may alert", got)
	}
	var subject uuid.UUID
	if err := h.owner.QueryRow(`SELECT subject_id FROM alerts
	    WHERE tenant_id = $1 AND alert_type = 'control_noncompliant' AND status <> 'resolved'`, tenant).
		Scan(&subject); err != nil {
		t.Fatalf("read the alert subject: %v", err)
	}
	if subject != controls["NEW"] {
		t.Fatalf("the alert is about control %s, want the one with the open finding (%s)", subject, controls["NEW"])
	}

	// A person now works the last open finding and marks it RESOLVED: nothing on
	// the control is open any more, so the alert has to clear itself.
	h.exec(t, `UPDATE findings SET workflow_status = 'RESOLVED' WHERE tenant_id = $1 AND control_id = $2`,
		tenant, controls["NEW"])
	job.ScanAll()
	if got := h.alertCount(t, tenant, "control_noncompliant"); got != 0 {
		t.Fatalf("every finding on the control is RESOLVED but %d alert(s) are still open", got)
	}
}
