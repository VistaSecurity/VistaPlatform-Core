package jobs

// The findings-driven alert detectors, against a real Postgres.
//
// The unit tests next door prove the ladders; these prove the SQL and the
// lifecycle — that the open-findings predicate matches rows shaped the way the
// producers actually write them, that one subject yields one alert, that a
// worsening finding escalates it, that a cleared finding resolves it, and that
// a pass in which nothing changed writes nothing.
//
// Wired exactly as cmd/main.go wires the job: the tenant-scoped handle is the
// non-owner `crypto_app` role (RLS enforced, as in production) and the
// cross-tenant handle is the owner connection standing in for the BYPASSRLS
// pool. An owner-only test would prove nothing about the RLS-scoped reads.

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// alertRow reads the single non-resolved alert of a type, read on the owner
// handle so the assertion itself is never the thing RLS hides.
func (h *jobHarness) alertRow(t *testing.T, tenantID uuid.UUID, alertType string) (id uuid.UUID, severity, title string) {
	t.Helper()
	if err := h.owner.QueryRow(`
		SELECT id, severity, title FROM alerts
		WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved'
	`, tenantID, alertType).Scan(&id, &severity, &title); err != nil {
		t.Fatalf("read %s alert: %v", alertType, err)
	}
	return id, severity, title
}

// alertEventCount counts the append-only evidence rows on one alert. It is how
// "a pass with no change publishes nothing" is observable: a re-raise the
// engine dedupes into a touch appends no event, and an escalation appends one.
func (h *jobHarness) alertEventCount(t *testing.T, alertID uuid.UUID) int {
	t.Helper()
	var n int
	if err := h.owner.QueryRow(`SELECT COUNT(*) FROM alert_events WHERE alert_id = $1`, alertID).Scan(&n); err != nil {
		t.Fatalf("count alert events: %v", err)
	}
	return n
}

// alertTouchedAt reads the timestamps a re-raise would move. The raise-on-change
// rule is only observable here: the alert engine dedupes a same-severity raise
// into a silent TOUCH that appends no event but does move these, so a job that
// re-raised every pass would show up as an `updated_at` that keeps advancing on
// an alert where nothing happened.
func (h *jobHarness) alertTouchedAt(t *testing.T, alertID uuid.UUID) (updatedAt, lastEventAt time.Time) {
	t.Helper()
	var lastEvent sql.NullTime
	if err := h.owner.QueryRow(`SELECT updated_at, last_event_at FROM alerts WHERE id = $1`, alertID).
		Scan(&updatedAt, &lastEvent); err != nil {
		t.Fatalf("read alert timestamps: %v", err)
	}
	return updatedAt, lastEvent.Time
}

func (h *jobHarness) alertStatus(t *testing.T, alertID uuid.UUID) (status string, resolution sql.NullString) {
	t.Helper()
	if err := h.owner.QueryRow(`SELECT status, resolution FROM alerts WHERE id = $1`, alertID).Scan(&status, &resolution); err != nil {
		t.Fatalf("read alert status: %v", err)
	}
	return status, resolution
}

// seedVulnFinding writes one known_vulnerability finding the way the
// vulnerability producer writes it: subject is the software INSTALL, score is
// the worst CVSS times ten, and the CVE list travels in the evidence.
func (h *jobHarness) seedVulnFinding(t *testing.T, tenantID, installID uuid.UUID, label, severity string, score int, cve string) {
	t.Helper()
	h.exec(t, `INSERT INTO findings
	             (tenant_id, producer, kind, subject_id, subject_type, subject_label,
	              severity, score, summary, evidence, source_kind, detection_state, workflow_status)
	           VALUES ($1,'vulnerability','known_vulnerability',$2,'software_install',$3,
	                   $4,$5,$6,$7::jsonb,'imported','ACTIVE','NEW')`,
		tenantID, installID, label, severity, score,
		label+" is affected by "+cve,
		fmt.Sprintf(`{"cve_count": 1, "cves": [{"cve_id": %q, "cvss_score": %.1f}], "worst_cvss_scored": true}`,
			cve, float64(score)/10))
}

// seedEOLFinding writes one end-of-life finding the way the eol producer writes
// it: the day count in the evidence is what the alert ladder reads.
func (h *jobHarness) seedEOLFinding(t *testing.T, tenantID, subjectID uuid.UUID, kind, subjectType, label, severity string, score, daysRemaining int) {
	t.Helper()
	h.exec(t, `INSERT INTO findings
	             (tenant_id, producer, kind, subject_id, subject_type, subject_label,
	              severity, score, summary, evidence, source_kind, detection_state, workflow_status)
	           VALUES ($1,'eol',$2,$3,$4,$5,$6,$7,$8,$9::jsonb,'imported','ACTIVE','NEW')`,
		tenantID, kind, subjectID, subjectType, label, severity, score,
		label+" is end of life",
		fmt.Sprintf(`{"days_remaining": %d, "eol_date": "2024-04-30", "catalogue_product": "ubuntu"}`, daysRemaining))
}

// --- known_vulnerability -----------------------------------------------------

func TestIntegration_VulnerabilityAlertScan_OpensEscalatesAndResolves(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	quiet := testdb.NewTenant(t, h.owner)

	// Negative control: CVSS 3.0 is a real finding below the alert floor, and a
	// CVE the feed never scored (score 0) is a real finding nobody graded.
	// Neither opens an alert; neither is thereby reported as harmless.
	h.seedVulnFinding(t, quiet, uuid.New(), "zlib 1.2.11", "low", 30, "CVE-2026-0003")
	h.seedVulnFinding(t, quiet, uuid.New(), "libfoo 0.1", "info", 0, "CVE-2026-0000")

	installID := uuid.New()
	h.seedVulnFinding(t, tenant, installID, "openssl 1.1.1k", "medium", 55, "CVE-2026-1111")

	job := NewVulnerabilityAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()

	if got := h.alertCount(t, quiet, "known_vulnerability"); got != 0 {
		t.Fatalf("a low/unscored advisory raised an alert: got %d, want 0", got)
	}
	if got := h.alertCount(t, tenant, "known_vulnerability"); got != 1 {
		t.Fatalf("a CVSS 5.5 advisory did not raise an alert: got %d, want 1", got)
	}
	alertID, severity, title := h.alertRow(t, tenant, "known_vulnerability")
	if severity != "medium" {
		t.Fatalf("CVSS 5.5 opened at severity %q, want medium", severity)
	}
	if !strings.Contains(title, "openssl 1.1.1k") {
		t.Errorf("title %q does not name the install", title)
	}
	opened := h.alertEventCount(t, alertID)
	if opened != 1 {
		t.Fatalf("an alert that just opened has %d events, want 1 (opened)", opened)
	}

	// A second pass with nothing changed must write nothing: no new alert, no
	// new event, and — the raise-on-change rule — no touch either.
	updatedAt, lastEventAt := h.alertTouchedAt(t, alertID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "known_vulnerability"); got != 1 {
		t.Fatalf("a re-scan duplicated the alert: got %d, want 1", got)
	}
	if got := h.alertEventCount(t, alertID); got != opened {
		t.Fatalf("an unchanged re-scan appended %d event(s)", got-opened)
	}
	gotUpdated, gotLastEvent := h.alertTouchedAt(t, alertID)
	if !gotUpdated.Equal(updatedAt) || !gotLastEvent.Equal(lastEventAt) {
		t.Fatalf("an unchanged re-scan touched the alert (updated_at %v -> %v, last_event_at %v -> %v) — "+
			"the job re-raised a rung that had not moved",
			updatedAt, gotUpdated, lastEventAt, gotLastEvent)
	}

	// The worst CVSS rises: the same alert escalates, and says so.
	h.exec(t, `UPDATE findings SET severity = 'critical', score = 95,
	             evidence = jsonb_set(evidence, '{cves,0,cvss_score}', '9.5')
	           WHERE tenant_id = $1 AND subject_id = $2`, tenant, installID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "known_vulnerability"); got != 1 {
		t.Fatalf("escalation opened a second alert: got %d, want 1", got)
	}
	_, severity, _ = h.alertRow(t, tenant, "known_vulnerability")
	if severity != "critical" {
		t.Fatalf("CVSS 9.5 did not escalate the alert: severity %q, want critical", severity)
	}
	if got := h.alertEventCount(t, alertID); got != opened+1 {
		t.Fatalf("escalation appended %d events, want 1", got-opened)
	}

	// The finding stops being detected (the package was upgraded) → the alert
	// auto-resolves. INACTIVE is what the shared writer's Resolve/Sweep sets.
	h.exec(t, `UPDATE findings SET detection_state = 'INACTIVE' WHERE tenant_id = $1 AND subject_id = $2`, tenant, installID)
	job.ScanAll()
	status, resolution := h.alertStatus(t, alertID)
	if status != "resolved" {
		t.Fatalf("a cleared finding left the alert at status %q, want resolved", status)
	}
	if !resolution.Valid || resolution.String != "auto" {
		t.Fatalf("resolution = %v, want auto", resolution)
	}
}

// TestIntegration_VulnerabilityAlertScan_IgnoresSuppressedAndResolvedFindings
// pins the OPEN half of the predicate. `finding:(detection_state:ACTIVE and
// workflow_status not in (RESOLVED, SUPPRESSED))` is the registry's ONE
// definition of open, and this detector compiles it from
// shared/findings.OpenSQL rather than spelling it again — a detector that
// checked only detection_state would keep paging about a finding a person had
// already signed off.
func TestIntegration_VulnerabilityAlertScan_IgnoresSuppressedAndResolvedFindings(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	suppressed := uuid.New()
	resolved := uuid.New()
	inactive := uuid.New()
	open := uuid.New()
	h.seedVulnFinding(t, tenant, suppressed, "pkg-a 1.0", "critical", 95, "CVE-2026-4444")
	h.seedVulnFinding(t, tenant, resolved, "pkg-b 1.0", "critical", 95, "CVE-2026-5555")
	h.seedVulnFinding(t, tenant, inactive, "pkg-c 1.0", "critical", 95, "CVE-2026-6666")
	// One genuinely open finding, so the tenant is IN the scan. Without it the
	// tenant listing — which compiles the same predicate — would skip the
	// tenant entirely and this would pass even with the per-tenant read
	// widened to detection_state alone. Verified by mutation: widen that read
	// and this test goes red on a count of 3 instead of 1.
	h.seedVulnFinding(t, tenant, open, "pkg-d 1.0", "critical", 95, "CVE-2026-7777")
	h.exec(t, `UPDATE findings SET workflow_status = 'SUPPRESSED' WHERE tenant_id = $1 AND subject_id = $2`, tenant, suppressed)
	h.exec(t, `UPDATE findings SET workflow_status = 'RESOLVED' WHERE tenant_id = $1 AND subject_id = $2`, tenant, resolved)
	h.exec(t, `UPDATE findings SET detection_state = 'INACTIVE' WHERE tenant_id = $1 AND subject_id = $2`, tenant, inactive)

	job := NewVulnerabilityAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "known_vulnerability"); got != 1 {
		t.Fatalf("got %d alerts, want 1 — only the open finding may alert (suppressed, human-resolved and inactive ones must not)", got)
	}
	var subject uuid.UUID
	if err := h.owner.QueryRow(`SELECT subject_id FROM alerts
	    WHERE tenant_id = $1 AND alert_type = 'known_vulnerability' AND status <> 'resolved'`, tenant).Scan(&subject); err != nil {
		t.Fatalf("read the alert subject: %v", err)
	}
	if subject != open {
		t.Fatalf("the alert is about subject %s, want the open finding's subject %s", subject, open)
	}
}

// --- end_of_life -------------------------------------------------------------

// TestIntegration_EndOfLifeAlertScan_OneAlertPerSubjectAtTheWorstRung is the
// "one alert per subject" rule against real rows: an asset whose OPERATING
// SYSTEM has been dead for years and whose HARDWARE support ends in a month is
// one piece of work, not two, and the alert is graded by the worse of them.
func TestIntegration_EndOfLifeAlertScan_OneAlertPerSubjectAtTheWorstRung(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	asset := uuid.New()
	h.seedEOLFinding(t, tenant, asset, "hardware_end_of_support", "asset", "db-prod-01", "low", 20, 30)
	h.seedEOLFinding(t, tenant, asset, "os_end_of_life", "asset", "db-prod-01", "critical", 90, -900)
	// A different subject on the same tenant keeps its own alert.
	install := uuid.New()
	h.seedEOLFinding(t, tenant, install, "software_end_of_life", "software_install", "nginx 1.14", "medium", 50, -10)
	// And a subject outside every rung opens nothing.
	future := uuid.New()
	h.seedEOLFinding(t, tenant, future, "hardware_end_of_support", "asset", "new-switch", "low", 20, 900)

	job := NewEndOfLifeAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()

	if got := h.alertCount(t, tenant, "end_of_life"); got != 2 {
		t.Fatalf("got %d end_of_life alerts, want 2 (one per subject that crosses a rung)", got)
	}
	var severity, title string
	if err := h.owner.QueryRow(`SELECT severity, title FROM alerts
	    WHERE tenant_id = $1 AND alert_type = 'end_of_life' AND subject_id = $2`, tenant, asset).
		Scan(&severity, &title); err != nil {
		t.Fatalf("read the asset's alert: %v", err)
	}
	if severity != "critical" {
		t.Fatalf("an asset 900 days past OS end-of-life opened at %q, want critical (the worst finding sets the rung)", severity)
	}
	if !strings.Contains(title, "Past end of life") {
		t.Errorf("title = %q, want the past-end-of-life wording", title)
	}
	var installSeverity string
	if err := h.owner.QueryRow(`SELECT severity FROM alerts
	    WHERE tenant_id = $1 AND alert_type = 'end_of_life' AND subject_id = $2`, tenant, install).
		Scan(&installSeverity); err != nil {
		t.Fatalf("read the install's alert: %v", err)
	}
	if installSeverity != "high" {
		t.Fatalf("a package 10 days past end-of-life opened at %q, want high", installSeverity)
	}

	// The whole subject clears → its alert resolves; the other is untouched.
	h.exec(t, `UPDATE findings SET detection_state = 'INACTIVE' WHERE tenant_id = $1 AND subject_id = $2`, tenant, asset)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "end_of_life"); got != 1 {
		t.Fatalf("after the asset's findings cleared, %d alerts remain open, want 1", got)
	}
}

// TestIntegration_EndOfLifeAlertScan_DisabledTypeRaisesNothing pins the tenant
// toggle on the new type: switching "End of life" off in Settings → Alert Rules
// has to actually stop the detector, not merely the notification.
func TestIntegration_EndOfLifeAlertScan_DisabledTypeRaisesNothing(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	h.exec(t, `INSERT INTO tenant_alert_settings (tenant_id, alert_type, enabled) VALUES ($1,'end_of_life',false)`, tenant)
	h.seedEOLFinding(t, tenant, uuid.New(), "os_end_of_life", "asset", "old-box", "critical", 90, -900)

	job := NewEndOfLifeAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "end_of_life"); got != 0 {
		t.Fatalf("a disabled alert type still raised: got %d, want 0", got)
	}
}

// TestIntegration_FindingsAlertScan_StartRunsAPass proves the scheduler half:
// Start() actually runs a scan rather than only arming a ticker. Without it
// nothing here would notice a job that is constructed, registered and never
// fires — the failure shape this repository keeps re-finding.
func TestIntegration_FindingsAlertScan_StartRunsAPass(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	h.seedVulnFinding(t, tenant, uuid.New(), "openssl 1.1.1k", "critical", 95, "CVE-2026-9999")

	job := NewVulnerabilityAlertScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.initialDelay = 10 * time.Millisecond
	job.Start()
	defer job.Stop()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if h.alertCount(t, tenant, "known_vulnerability") == 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("Start() never ran a pass — the alert was never raised")
}

// seedScoredFramework creates an activated, scored framework with a given code.
//
// The VERSION is unique per call, deliberately:
// unique_platform_framework_code_version means the seeded Core
// `inventory-hygiene` 1.0 (present whenever seed.sql has been applied, as it is
// in the nightly job) would collide with a test creating the same pair — and so
// would two tests in this file. The routing this exercises keys on the CODE
// alone, so the version is free to vary.
func (h *jobHarness) seedScoredFramework(t *testing.T, tenantID, author uuid.UUID, code, name string, score int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	// `organization` is set deliberately. The column is nullable, but
	// models.PlatformFramework scans it into a plain string, so a NULL row is
	// unscannable — and these tests share a database with every other package's,
	// where a row shaped like that breaks a NEIGHBOUR's test rather than this
	// one. (The production write paths all set it; see the PR notes.)
	h.exec(t, `INSERT INTO platform_frameworks (id, code, name, version, organization, created_by)
	           VALUES ($1,$2,$3,$4,'Vista Platform Test',$5)`, id, code, name, "t-"+uuid.NewString()[:8], author)
	h.exec(t, `INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
	           VALUES ($1,$2,'active')`, tenantID, id)
	h.exec(t, `INSERT INTO tenant_framework_scores (tenant_id, platform_framework_id, score)
	           VALUES ($1,$2,$3)`, tenantID, id, score)
	h.exec(t, `INSERT INTO alert_framework_score_snapshots (tenant_id, platform_framework_id, score, captured_at)
	           VALUES ($1,$2,90, NOW() - INTERVAL '25 hours')`, tenantID, id)
	return id
}

// --- hygiene_score_drop ------------------------------------------------------

// TestIntegration_HygieneScoreDropScan_SplitsByFrameworkCode pins the routing:
// the Inventory Hygiene framework's drop is `hygiene_score_drop` and every
// other framework's is `compliance_score_drop`. One detector, two types, and a
// single drop never opens two alerts.
func TestIntegration_HygieneScoreDropScan_SplitsByFrameworkCode(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	author := h.newPlatformAuthor(t)

	hygieneID := h.seedScoredFramework(t, tenant, author, "inventory-hygiene", "Inventory Hygiene", 90)
	otherID := h.seedScoredFramework(t, tenant, author, "srf-"+uuid.NewString()[:8], "Some Regulated FW", 90)

	job := NewComplianceScoreDropScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)

	// Only hygiene drops.
	h.exec(t, `UPDATE tenant_framework_scores SET score = 55 WHERE tenant_id = $1 AND platform_framework_id = $2`, tenant, hygieneID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "hygiene_score_drop"); got != 1 {
		t.Fatalf("the Inventory Hygiene drop did not raise hygiene_score_drop: got %d, want 1", got)
	}
	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 0 {
		t.Fatalf("the hygiene drop ALSO raised compliance_score_drop: got %d, want 0", got)
	}
	_, _, title := h.alertRow(t, tenant, "hygiene_score_drop")
	if !strings.Contains(title, "Hygiene score dropped") {
		t.Errorf("title = %q, want the hygiene wording", title)
	}

	// Now the other framework drops too: two alerts, one of each type.
	h.exec(t, `UPDATE tenant_framework_scores SET score = 40 WHERE tenant_id = $1 AND platform_framework_id = $2`, tenant, otherID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 1 {
		t.Fatalf("the regulated framework's drop did not raise compliance_score_drop: got %d, want 1", got)
	}
	if got := h.alertCount(t, tenant, "hygiene_score_drop"); got != 1 {
		t.Fatalf("hygiene_score_drop duplicated: got %d, want 1", got)
	}

	// Hygiene recovers → only the hygiene alert resolves.
	h.exec(t, `UPDATE tenant_framework_scores SET score = 88 WHERE tenant_id = $1 AND platform_framework_id = $2`, tenant, hygieneID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "hygiene_score_drop"); got != 0 {
		t.Fatalf("a recovered hygiene score left the alert open: got %d, want 0", got)
	}
	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 1 {
		t.Fatalf("the hygiene recovery resolved the compliance alert too: got %d, want 1", got)
	}
}

// TestIntegration_HygieneScoreDropScan_TypesAreGatedIndependently: silencing
// hygiene noise must not silence a compliance score collapse.
func TestIntegration_HygieneScoreDropScan_TypesAreGatedIndependently(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	author := h.newPlatformAuthor(t)

	// Both frameworks are already 40 points down against their 24h reference.
	h.seedScoredFramework(t, tenant, author, "inventory-hygiene", "Inventory Hygiene", 50)
	h.seedScoredFramework(t, tenant, author, "srf-"+uuid.NewString()[:8], "Some Regulated FW", 50)
	h.exec(t, `INSERT INTO tenant_alert_settings (tenant_id, alert_type, enabled)
	           VALUES ($1,'hygiene_score_drop',false)`, tenant)

	job := NewComplianceScoreDropScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()

	if got := h.alertCount(t, tenant, "hygiene_score_drop"); got != 0 {
		t.Fatalf("a disabled hygiene_score_drop still raised: got %d, want 0", got)
	}
	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 1 {
		t.Fatalf("disabling hygiene_score_drop silenced compliance_score_drop too: got %d, want 1", got)
	}
}

// TestIntegration_ScoreDropScan_DisablingATypeDoesNotResolveItsOpenAlerts is
// the OTHER half of "gated independently", and it is the half the split nearly
// lost.
//
// Before this job served two types, a disabled type returned from scanTenant
// before the sweep and its open alerts simply stayed open. Serving two types
// means the function no longer returns early, so the sweep runs — and it swept
// the DISABLED type's alerts closed, under the observation "framework no longer
// active or scored", which is not what happened: the framework is still
// activated and still scored, the tenant just stopped wanting to be told.
//
// A tenant silencing score-drop noise for a week would have come back to find
// the alerts they already had gone from Remediation → Alerts, closed with a
// false reason in the timeline, and re-enabling the type would not bring them
// back — the score has to fall another ten points first.
//
// Both directions are asserted: the disabled type's alert survives, and the
// still-enabled type keeps working (a sweep skipped entirely would pass a
// one-sided test while breaking auto-resolve for everybody).
func TestIntegration_ScoreDropScan_DisablingATypeDoesNotResolveItsOpenAlerts(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	author := h.newPlatformAuthor(t)

	hygieneID := h.seedScoredFramework(t, tenant, author, "inventory-hygiene", "Inventory Hygiene", 50)
	h.seedScoredFramework(t, tenant, author, "srf-"+uuid.NewString()[:8], "Some Regulated FW", 50)

	job := NewComplianceScoreDropScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 1 {
		t.Fatalf("setup: compliance_score_drop = %d, want 1", got)
	}
	if got := h.alertCount(t, tenant, "hygiene_score_drop"); got != 1 {
		t.Fatalf("setup: hygiene_score_drop = %d, want 1", got)
	}

	// The tenant silences compliance_score_drop only.
	h.exec(t, `INSERT INTO tenant_alert_settings (tenant_id, alert_type, enabled)
	           VALUES ($1,'compliance_score_drop',false)`, tenant)
	job.ScanAll()

	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 1 {
		t.Fatalf("silencing compliance_score_drop auto-resolved the alert it already had: got %d open, want 1", got)
	}
	if got := h.alertCount(t, tenant, "hygiene_score_drop"); got != 1 {
		t.Fatalf("silencing compliance_score_drop also closed hygiene_score_drop: got %d, want 1", got)
	}

	// And the sweep is SKIPPED for the disabled type, not switched off: the
	// still-enabled type's alert must still resolve when its framework stops
	// being active — which is the sweep's own branch, not the recovery branch
	// above it. Without this the guard could be "satisfied" by a sweep that
	// resolved nothing at all.
	h.exec(t, `UPDATE tenant_framework_licenses SET subscription_status = 'cancelled'
	           WHERE tenant_id = $1 AND platform_framework_id = $2`, tenant, hygieneID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "hygiene_score_drop"); got != 0 {
		t.Fatalf("deactivating the framework left its hygiene_score_drop alert open: got %d, want 0", got)
	}
	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 1 {
		t.Fatalf("the sweep took the disabled type's alert with it: got %d, want 1", got)
	}
}

// --- wiring ------------------------------------------------------------------

// TestFindingsAlertJobsAreRegisteredInMain is the other half of the wiring
// proof. A job that is constructed correctly, tested thoroughly and never
// started in cmd/main.go is the exact failure this repository has paid for more
// than once — a fix that compiles, passes its tests, and does nothing in
// production. Delete either registration line and this fails.
//
// Not an integration test (it needs no database) but it lives here because it
// is the companion assertion to StartRunsAPass above: one proves Start() runs a
// pass, this proves something calls Start().
func TestFindingsAlertJobsAreRegisteredInMain(t *testing.T) {
	path := filepath.Join("..", "..", "cmd", "main.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	main := string(b)
	for _, want := range []string{
		"jobs.NewVulnerabilityAlertScanJob(",
		"vulnerabilityAlertJob.Start()",
		"jobs.NewEndOfLifeAlertScanJob(",
		"endOfLifeAlertJob.Start()",
		"jobs.NewDriftAlertScanJob(",
		"driftAlertJob.Start()",
		"jobs.NewComplianceScoreDropScanJob(",
		"scoreDropJob.Start()",
	} {
		if !strings.Contains(main, want) {
			t.Errorf("cmd/main.go no longer contains %q — the detector is built but never runs", want)
		}
	}
}
