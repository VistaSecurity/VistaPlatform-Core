package jobs

// De-escalation, and the drift_detected detector, against a real Postgres.
//
// The bug these close: Raise only ever moved severity UP. A same-or-lower raise
// was deduped into a silent touch, so an alert that opened critical stayed
// critical for as long as anything remained open — a package downgraded from
// CVSS 9.8 to 5.1 by a partial fix kept a critical badge, and the Alerts page,
// which people triage top-down by severity, kept it at the top. "Only ever
// worse" is not conservative; it is a wrong number displayed with confidence.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedDriftFinding writes one drift finding the way the drift producer writes
// it: the severity is the registry's fixed grade for the kind, the summary is
// the rendered title_template, and the baseline window travels in the evidence.
func (h *jobHarness) seedDriftFinding(t *testing.T, tenantID, subjectID uuid.UUID,
	kind, subjectType, label, severity string, score int) {
	t.Helper()
	h.exec(t, `INSERT INTO findings
	             (tenant_id, producer, kind, subject_id, subject_type, subject_label,
	              severity, score, summary, evidence, source_kind, detection_state, workflow_status)
	           VALUES ($1,'drift',$2,$3,$4,$5,$6,$7,$8,$9::jsonb,'measured','ACTIVE','NEW')`,
		tenantID, kind, subjectID, subjectType, label, severity, score,
		label+" changed since its baseline",
		`{"window_days": 14, "window_start": "2026-08-01T00:00:00Z"}`)
}

// alertSeverityEvents returns the severity_changed details on one alert, oldest
// first. De-escalation without a trail would be a number that silently moved.
func (h *jobHarness) alertSeverityEvents(t *testing.T, alertID uuid.UUID) []string {
	t.Helper()
	rows, err := h.owner.Query(`
		SELECT COALESCE(details::text, '') FROM alert_events
		WHERE alert_id = $1 AND event_type = 'severity_changed'
		ORDER BY created_at, id`, alertID)
	if err != nil {
		t.Fatalf("read severity events: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatalf("scan severity event: %v", err)
		}
		out = append(out, d)
	}
	return out
}

// engineDeescalate calls the engine method directly, for the edges no job
// reaches (a higher severity, a subject with no open alert, a severity outside
// the enum).
func (h *jobHarness) engineDeescalate(t *testing.T, tenantID uuid.UUID, alertType string,
	subjectID uuid.UUID, severity string) (services.DeescalateOutcome, error) {
	t.Helper()
	sid := subjectID
	return h.engine.Deescalate(context.Background(), events.AlertRaiseEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertType:   alertType,
		Source:      "compliance-engine",
		SubjectType: "software_install",
		SubjectID:   &sid,
		Severity:    severity,
		Title:       "t",
		Message:     "m",
		Timestamp:   time.Now(),
	}, map[string]interface{}{"observed": "test"})
}

// --- drift_detected -----------------------------------------------------------

// TestIntegration_DriftAlertScan_OpensAtTheFindingSeverityAndResolves is the new
// type end to end: one alert per subject, graded by the worst open drift
// finding, resolving when the findings stop being detected.
func TestIntegration_DriftAlertScan_OpensAtTheFindingSeverityAndResolves(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	asset := uuid.New()
	// Two findings on ONE subject: a low-graded port-profile change and a
	// medium-graded new protocol. One alert, at the worse of the two.
	h.seedDriftFinding(t, tenant, asset, "port_profile_changed", "asset", "web-01", "low", 20)
	h.seedDriftFinding(t, tenant, asset, "unexpected_protocol", "asset", "web-01", "medium", 40)
	// A different subject keeps its own alert.
	cert := uuid.New()
	h.seedDriftFinding(t, tenant, cert, "new_issuer", "certificate", "*.example.com", "medium", 30)

	job := NewDriftAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()

	if got := h.alertCount(t, tenant, "drift_detected"); got != 2 {
		t.Fatalf("got %d drift_detected alerts, want 2 (one per subject)", got)
	}
	var severity, title, message string
	if err := h.owner.QueryRow(`SELECT severity, title, message FROM alerts
	    WHERE tenant_id = $1 AND alert_type = 'drift_detected' AND subject_id = $2`, tenant, asset).
		Scan(&severity, &title, &message); err != nil {
		t.Fatalf("read the asset's alert: %v", err)
	}
	if severity != "medium" {
		t.Fatalf("an asset with a low and a medium drift finding opened at %q, want medium (the worst sets the rung)", severity)
	}
	if !strings.Contains(title, "web-01") {
		t.Errorf("title = %q, does not name the subject", title)
	}
	if !strings.Contains(message, "2 drift findings") {
		t.Errorf("message = %q, does not say both findings are open", message)
	}

	// Everything clears → the alert auto-resolves.
	h.exec(t, `UPDATE findings SET detection_state = 'INACTIVE'
	           WHERE tenant_id = $1 AND subject_id = $2`, tenant, asset)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "drift_detected"); got != 1 {
		t.Fatalf("after the asset's drift findings cleared, %d alerts remain open, want 1", got)
	}
}

// TestIntegration_DriftAlertScan_DisabledTypeRaisesNothing pins the tenant
// toggle on the new type — switching "Drift detected" off in Settings → Alert
// Rules has to stop the detector, not merely the notification.
func TestIntegration_DriftAlertScan_DisabledTypeRaisesNothing(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	h.exec(t, `INSERT INTO tenant_alert_settings (tenant_id, alert_type, enabled) VALUES ($1,'drift_detected',false)`, tenant)
	h.seedDriftFinding(t, tenant, uuid.New(), "new_class_in_segment", "asset", "printer-3", "medium", 30)

	job := NewDriftAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "drift_detected"); got != 0 {
		t.Fatalf("a disabled alert type still raised: got %d, want 0", got)
	}
}

// --- de-escalation ------------------------------------------------------------

// TestIntegration_FindingsAlertScan_LowersSeverityWhenTheFindingIsRescored is
// the headline transition: an alert opened critical, the finding is re-scored
// medium, and the alert has to follow it DOWN — with the move on the record and
// the row still open, because the condition has not gone away.
//
// Mutation: delete the de-escalation arm of scanTenant's switch and this fails
// on the severity that did not move.
func TestIntegration_FindingsAlertScan_LowersSeverityWhenTheFindingIsRescored(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	install := uuid.New()
	h.seedVulnFinding(t, tenant, install, "openssl 1.1.1k", "critical", 98, "CVE-2026-2222")

	job := NewVulnerabilityAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	alertID, severity, _ := h.alertRow(t, tenant, "known_vulnerability")
	if severity != "critical" {
		t.Fatalf("opened at %q, want critical", severity)
	}
	opened := h.alertEventCount(t, alertID)

	// A partial fix: the worst advisory that still matches is CVSS 5.1.
	h.exec(t, `UPDATE findings SET severity = 'medium', score = 51,
	             evidence = jsonb_set(evidence, '{cves,0,cvss_score}', '5.1')
	           WHERE tenant_id = $1 AND subject_id = $2`, tenant, install)
	job.ScanAll()

	if got := h.alertCount(t, tenant, "known_vulnerability"); got != 1 {
		t.Fatalf("de-escalation changed the number of open alerts: got %d, want 1 — "+
			"an alert row is never deleted and never re-opened by a severity move", got)
	}
	gotID, severity, _ := h.alertRow(t, tenant, "known_vulnerability")
	if gotID != alertID {
		t.Fatalf("de-escalation opened a NEW alert %s (was %s)", gotID, alertID)
	}
	if severity != "medium" {
		t.Fatalf("a finding re-scored to CVSS 5.1 left the alert at %q, want medium — "+
			"the alert is still displaying the worst grade it ever reached", severity)
	}
	// The message is re-stamped too: a medium badge beside "CVSS 9.8" in the
	// body is the same stale number in a different place.
	var message string
	if err := h.owner.QueryRow(`SELECT message FROM alerts WHERE id = $1`, alertID).Scan(&message); err != nil {
		t.Fatalf("read message: %v", err)
	}
	if strings.Contains(message, "9.8") {
		t.Errorf("message still quotes the old score: %q", message)
	}

	// The move is on the record, and says which way it went.
	if got := h.alertEventCount(t, alertID); got != opened+1 {
		t.Fatalf("de-escalation appended %d events, want exactly 1", got-opened)
	}
	sevEvents := h.alertSeverityEvents(t, alertID)
	if len(sevEvents) != 1 {
		t.Fatalf("got %d severity_changed events, want 1", len(sevEvents))
	}
	for _, want := range []string{`"from": "critical"`, `"to": "medium"`, `"direction": "lowered"`} {
		if !strings.Contains(sevEvents[0], want) {
			t.Errorf("severity_changed details %s does not contain %s", sevEvents[0], want)
		}
	}

	// A THIRD pass with nothing changed writes nothing at all — de-escalation
	// must not become a per-pass rewrite of its own.
	updatedAt, lastEventAt := h.alertTouchedAt(t, alertID)
	job.ScanAll()
	gotUpdated, gotLastEvent := h.alertTouchedAt(t, alertID)
	if !gotUpdated.Equal(updatedAt) || !gotLastEvent.Equal(lastEventAt) {
		t.Fatalf("a pass after de-escalation touched the alert again (updated_at %v -> %v)", updatedAt, gotUpdated)
	}
	if got := len(h.alertSeverityEvents(t, alertID)); got != 1 {
		t.Fatalf("an unchanged pass appended another severity_changed event (%d total)", got)
	}
}

// TestIntegration_FindingsAlertScan_WorstRemainingFindingSetsTheNewSeverity is
// the other way a subject improves: nothing is re-scored, but the worst of
// several findings is resolved and a milder one is left. The alert follows the
// worst finding that is STILL open, and stays open because one is.
func TestIntegration_FindingsAlertScan_WorstRemainingFindingSetsTheNewSeverity(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	asset := uuid.New()
	// 900 days past OS end-of-life (critical) and hardware support ending in 30
	// days (inside the 90-day rung, so medium). One alert, opened critical.
	h.seedEOLFinding(t, tenant, asset, "os_end_of_life", "asset", "db-prod-01", "critical", 90, -900)
	h.seedEOLFinding(t, tenant, asset, "hardware_end_of_support", "asset", "db-prod-01", "low", 20, 30)

	job := NewEndOfLifeAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	alertID, severity, _ := h.alertRow(t, tenant, "end_of_life")
	if severity != "critical" {
		t.Fatalf("opened at %q, want critical", severity)
	}

	// The OS is upgraded. The hardware deadline remains.
	h.exec(t, `UPDATE findings SET detection_state = 'INACTIVE'
	           WHERE tenant_id = $1 AND subject_id = $2 AND kind = 'os_end_of_life'`, tenant, asset)
	job.ScanAll()

	status, _ := h.alertStatus(t, alertID)
	if status == "resolved" {
		t.Fatal("resolving the worst finding resolved the ALERT — a milder finding is still open on this subject")
	}
	_, severity, _ = h.alertRow(t, tenant, "end_of_life")
	if severity != "medium" {
		t.Fatalf("after the critical finding cleared the alert reads %q, want medium — the hardware deadline is "+
			"30 days out, which is inside the 90-day rung", severity)
	}
	if got := len(h.alertSeverityEvents(t, alertID)); got != 1 {
		t.Fatalf("got %d severity_changed events, want 1", got)
	}
}

// TestIntegration_FindingsAlertScan_AStillOpenFindingLeavesTheAlertAlone is the
// negative control for both directions. Without it a de-escalation that fired
// on every pass, or one that mistook "unchanged" for "improved", would pass the
// two tests above.
func TestIntegration_FindingsAlertScan_AStillOpenFindingLeavesTheAlertAlone(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	install := uuid.New()
	h.seedVulnFinding(t, tenant, install, "nginx 1.14", "high", 75, "CVE-2026-3333")

	job := NewVulnerabilityAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	alertID, severity, _ := h.alertRow(t, tenant, "known_vulnerability")
	if severity != "high" {
		t.Fatalf("opened at %q, want high", severity)
	}
	updatedAt, lastEventAt := h.alertTouchedAt(t, alertID)
	events := h.alertEventCount(t, alertID)

	// Re-scored INSIDE the same rung (7.5 → 7.9 is still High): nothing moved,
	// so nothing may be written.
	h.exec(t, `UPDATE findings SET score = 79 WHERE tenant_id = $1 AND subject_id = $2`, tenant, install)
	job.ScanAll()

	_, severity, _ = h.alertRow(t, tenant, "known_vulnerability")
	if severity != "high" {
		t.Fatalf("severity moved to %q on a re-score within the same rung", severity)
	}
	gotUpdated, gotLastEvent := h.alertTouchedAt(t, alertID)
	if !gotUpdated.Equal(updatedAt) || !gotLastEvent.Equal(lastEventAt) {
		t.Fatalf("an unchanged rung touched the alert (updated_at %v -> %v)", updatedAt, gotUpdated)
	}
	if got := h.alertEventCount(t, alertID); got != events {
		t.Fatalf("an unchanged rung appended %d event(s)", got-events)
	}
	if got := len(h.alertSeverityEvents(t, alertID)); got != 0 {
		t.Fatalf("an unchanged rung recorded %d severity change(s)", got)
	}
}

// TestIntegration_AlertEngineDeescalate_RefusesToRaiseOrInvent pins the engine
// method's own edges, which no job exercises: it never opens an alert, never
// raises one, and never accepts a severity outside the ladder.
func TestIntegration_AlertEngineDeescalate_RefusesToRaiseOrInvent(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	install := uuid.New()
	h.seedVulnFinding(t, tenant, install, "openssl 1.1.1k", "medium", 55, "CVE-2026-4444")
	job := NewVulnerabilityAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	alertID, severity, _ := h.alertRow(t, tenant, "known_vulnerability")
	if severity != "medium" {
		t.Fatalf("opened at %q, want medium", severity)
	}

	// A HIGHER severity is not a de-escalation: it must be ignored, not applied.
	// Escalation has its own path (Raise), which notifies; letting this method
	// raise would be a silent page-less escalation.
	if _, err := h.engineDeescalate(t, tenant, "known_vulnerability", install, "critical"); err != nil {
		t.Fatalf("Deescalate(critical): %v", err)
	}
	_, severity, _ = h.alertRow(t, tenant, "known_vulnerability")
	if severity != "medium" {
		t.Fatalf("Deescalate raised the alert to %q", severity)
	}
	if got := len(h.alertSeverityEvents(t, alertID)); got != 0 {
		t.Fatalf("an ignored de-escalation still recorded %d event(s)", got)
	}

	// No open alert for this subject: nothing is opened.
	other := uuid.New()
	if _, err := h.engineDeescalate(t, tenant, "known_vulnerability", other, "low"); err != nil {
		t.Fatalf("Deescalate(no alert): %v", err)
	}
	var n int
	if err := h.owner.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id = $1 AND subject_id = $2`,
		tenant, other).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("Deescalate opened %d alert(s) for a subject that had none", n)
	}

	// A severity outside the ladder is refused rather than written.
	if _, err := h.engineDeescalate(t, tenant, "known_vulnerability", install, "catastrophic"); err == nil {
		t.Fatal("Deescalate accepted a severity outside the enum")
	}
	_, severity, _ = h.alertRow(t, tenant, "known_vulnerability")
	if severity != "medium" {
		t.Fatalf("a refused de-escalation still changed the severity to %q", severity)
	}
}

// TestIntegration_FindingsAlertScan_LoweringKeepsAcknowledgementAndSnooze pins
// the thing a person would notice first if it broke: de-escalation must not
// reset the lifecycle state they chose.
//
// Acknowledging says "I have seen this"; snoozing says "stop telling me until
// <date>". Neither claim stops being true because the condition got milder, and
// an UPDATE that touched `status` or `snoozed_until` would silently undo both —
// an acknowledged alert would reappear in the Active tab, and a snoozed one
// would start notifying again on the next escalation. There is no user-visible
// error either way; the alert simply moves back into a queue somebody had
// already dealt with.
func TestIntegration_FindingsAlertScan_LoweringKeepsAcknowledgementAndSnooze(t *testing.T) {
	h := newJobHarness(t)

	for _, tc := range []struct {
		name       string
		status     string
		snoozeDays int
	}{
		{"acknowledged", "acknowledged", 0},
		{"snoozed", "snoozed", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant := testdb.NewTenant(t, h.owner)
			install := uuid.New()
			h.seedVulnFinding(t, tenant, install, "openssl 1.1.1k", "critical", 98, "CVE-2026-5555")

			job := NewVulnerabilityAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
			job.ScanAll()
			alertID, severity, _ := h.alertRow(t, tenant, "known_vulnerability")
			if severity != "critical" {
				t.Fatalf("opened at %q, want critical", severity)
			}

			// The user acts on the alert.
			if tc.snoozeDays > 0 {
				h.exec(t, `UPDATE alerts SET status = $1, snoozed_until = NOW() + ($2 || ' days')::interval
				           WHERE id = $3`, tc.status, tc.snoozeDays, alertID)
			} else {
				h.exec(t, `UPDATE alerts SET status = $1 WHERE id = $2`, tc.status, alertID)
			}
			var snoozedBefore sql.NullTime
			if err := h.owner.QueryRow(`SELECT snoozed_until FROM alerts WHERE id = $1`, alertID).
				Scan(&snoozedBefore); err != nil {
				t.Fatalf("read snoozed_until: %v", err)
			}

			// A partial fix drops the worst CVSS into the medium rung.
			h.exec(t, `UPDATE findings SET severity = 'medium', score = 51,
			             evidence = jsonb_set(evidence, '{cves,0,cvss_score}', '5.1')
			           WHERE tenant_id = $1 AND subject_id = $2`, tenant, install)
			job.ScanAll()

			gotStatus, resolution := h.alertStatus(t, alertID)
			if gotStatus != tc.status {
				t.Fatalf("lowering the severity moved the alert from %q to %q — the lifecycle state the user "+
					"chose is not a consequence of how bad the condition is", tc.status, gotStatus)
			}
			if resolution.Valid && resolution.String != "" {
				t.Errorf("lowering the severity stamped a resolution (%q) on an alert that is still open", resolution.String)
			}
			var snoozedAfter sql.NullTime
			if err := h.owner.QueryRow(`SELECT snoozed_until FROM alerts WHERE id = $1`, alertID).
				Scan(&snoozedAfter); err != nil {
				t.Fatalf("read snoozed_until: %v", err)
			}
			if snoozedBefore.Valid != snoozedAfter.Valid ||
				(snoozedBefore.Valid && !snoozedBefore.Time.Equal(snoozedAfter.Time)) {
				t.Errorf("lowering the severity changed snoozed_until (%v -> %v) — the snooze window would end early",
					snoozedBefore, snoozedAfter)
			}
			// And the lowering did happen, so this is not passing by doing nothing.
			var severityAfter string
			if err := h.owner.QueryRow(`SELECT severity FROM alerts WHERE id = $1`, alertID).
				Scan(&severityAfter); err != nil {
				t.Fatalf("read severity: %v", err)
			}
			if severityAfter != "medium" {
				t.Fatalf("severity = %q, want medium — the de-escalation this test guards did not happen", severityAfter)
			}
		})
	}
}
