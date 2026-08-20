package jobs

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// These tests answer one question per detector: does the predicate match data
// shaped the way the platform actually writes it? Each seeds the exact
// condition the alert is supposed to detect, runs the real job, and asserts an
// `alerts` row appears — and each has a negative control asserting the job stays
// silent when the condition is absent, so a test that would pass without the
// fixture cannot masquerade as proof.
//
// The job under test is wired exactly as cmd/main.go wires it: the tenant-scoped
// handle is the non-owner `crypto_app` role (RLS enforced, as in production) and
// the cross-tenant handle is the owner connection standing in for the BYPASSRLS
// pool. An owner-only test would prove nothing about the RLS-scoped reads.

type jobHarness struct {
	owner  *sql.DB
	app    *sqlx.DB
	bypass *sqlx.DB
	engine *services.AlertEngineService
	catlg  *services.AlertCatalogService
}

func newJobHarness(t *testing.T) *jobHarness {
	t.Helper()
	owner := testdb.Connect(t)
	appRaw := testdb.ConnectAsAppRole(t, owner)
	app := sqlx.NewDb(appRaw, "postgres")
	bypass := sqlx.NewDb(owner, "postgres")
	return &jobHarness{
		owner:  owner,
		app:    app,
		bypass: bypass,
		engine: services.NewAlertEngineService(app, bypass, nil, nil),
		catlg:  services.NewAlertCatalogService(app),
	}
}

// alertCount counts non-resolved alerts of a type for a tenant, read on the
// owner handle so the assertion itself is never the thing RLS hides.
func (h *jobHarness) alertCount(t *testing.T, tenantID uuid.UUID, alertType string) int {
	t.Helper()
	var n int
	if err := h.owner.QueryRow(
		`SELECT COUNT(*) FROM alerts WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved'`,
		tenantID, alertType).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

// newPlatformAuthor seeds a platform user to satisfy platform_frameworks.created_by.
func (h *jobHarness) newPlatformAuthor(t *testing.T) uuid.UUID {
	t.Helper()
	roleID, userID := uuid.New(), uuid.New()
	suffix := uuid.NewString()[:8]
	h.exec(t, `INSERT INTO platform_roles (id, name, display_name) VALUES ($1,$2,'Predicate Audit Role')`,
		roleID, "par-"+suffix)
	h.exec(t, `INSERT INTO platform_users (id, email, password_hash, first_name, last_name, role_id)
	           VALUES ($1,$2,'x','Predicate','Audit',$3)`, userID, "pa-"+suffix+"@example.test", roleID)
	t.Cleanup(func() {
		_, _ = h.owner.Exec(`DELETE FROM platform_users WHERE id = $1`, userID)
		_, _ = h.owner.Exec(`DELETE FROM platform_roles WHERE id = $1`, roleID)
	})
	return userID
}

// hexFingerprint returns a 64-char hex string satisfying certificates'
// valid_fingerprint_sha256 CHECK.
func hexFingerprint() string {
	a, b := uuid.NewString(), uuid.NewString()
	strip := func(s string) string {
		out := make([]byte, 0, 32)
		for i := 0; i < len(s); i++ {
			if s[i] != '-' {
				out = append(out, s[i])
			}
		}
		return string(out)
	}
	return strip(a) + strip(b)
}

func (h *jobHarness) exec(t *testing.T, q string, args ...interface{}) {
	t.Helper()
	if _, err := h.owner.Exec(q, args...); err != nil {
		t.Fatalf("seed failed (%s): %v", q, err)
	}
}

// --- certificate_expiring (CertLadderScanJob) -------------------------------

func TestIntegration_CertLadderScan_FiresOnExpiringCertificate(t *testing.T) {
	h := newJobHarness(t)
	quiet := testdb.NewTenant(t, h.owner)
	firing := testdb.NewTenant(t, h.owner)

	// Negative control: a certificate comfortably outside every rung.
	h.exec(t, `INSERT INTO certificates (tenant_id, subject_dn, issuer_dn, fingerprint_sha256, common_name, not_after)
	           VALUES ($1,'CN=quiet','CN=ca',$2,'quiet.example', NOW() + INTERVAL '400 days')`,
		quiet, hexFingerprint())
	// Condition: inside the 60-day product baseline rung.
	h.exec(t, `INSERT INTO certificates (tenant_id, subject_dn, issuer_dn, fingerprint_sha256, common_name, not_after)
	           VALUES ($1,'CN=firing','CN=ca',$2,'firing.example', NOW() + INTERVAL '10 days')`,
		firing, hexFingerprint())

	job := NewCertLadderScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()

	if got := h.alertCount(t, firing, "certificate_expiring"); got != 1 {
		t.Fatalf("expiring certificate did not raise an alert: got %d, want 1", got)
	}
	if got := h.alertCount(t, quiet, "certificate_expiring"); got != 0 {
		t.Fatalf("certificate outside every rung raised an alert: got %d, want 0", got)
	}
}

// --- sensor_offline / discovery_agent_offline (HeartbeatOfflineScanJob) -----

func TestIntegration_SensorOfflineScan_FiresOnStaleHeartbeat(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	// Fresh heartbeat — negative control.
	h.exec(t, `INSERT INTO sensors (tenant_id, name, platform, version, profile, status, last_heartbeat)
	           VALUES ($1,'fresh','linux','1.0','standard','active', NOW())`, tenant)
	job := NewSensorOfflineScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "sensor_offline"); got != 0 {
		t.Fatalf("sensor with a fresh heartbeat alerted: got %d, want 0", got)
	}

	// Stale heartbeat past the 15-minute dwell.
	h.exec(t, `INSERT INTO sensors (tenant_id, name, platform, version, profile, status, last_heartbeat)
	           VALUES ($1,'stale','linux','1.0','standard','active', NOW() - INTERVAL '2 hours')`, tenant)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "sensor_offline"); got != 1 {
		t.Fatalf("offline sensor did not raise an alert: got %d, want 1", got)
	}
}

func TestIntegration_DiscoveryAgentOfflineScan_FiresOnStaleHeartbeat(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	h.exec(t, `INSERT INTO device_agents (tenant_id, registration_key, name, platform, version, status, last_heartbeat)
	           VALUES ($1,$2,'fresh-agent','linux','1.0','active', NOW())`, tenant, uuid.NewString())
	job := NewDiscoveryAgentOfflineScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "discovery_agent_offline"); got != 0 {
		t.Fatalf("agent with a fresh heartbeat alerted: got %d, want 0", got)
	}

	h.exec(t, `INSERT INTO device_agents (tenant_id, registration_key, name, platform, version, status, last_heartbeat)
	           VALUES ($1,$2,'stale-agent','linux','1.0','active', NOW() - INTERVAL '2 hours')`, tenant, uuid.NewString())
	job.ScanAll()
	if got := h.alertCount(t, tenant, "discovery_agent_offline"); got != 1 {
		t.Fatalf("offline discovery agent did not raise an alert: got %d, want 1", got)
	}
}

// --- discovery_job_failed ----------------------------------------------------

func TestIntegration_DiscoveryJobFailedScan_FiresOnFailedJob(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	// Negative control: a completed job is not a failure.
	h.exec(t, `INSERT INTO discovery_jobs (tenant_id, execution_mode, status, completed_at)
	           VALUES ($1,'passive','completed', NOW() - INTERVAL '3 hours')`, tenant)
	job := NewDiscoveryJobFailedScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "discovery_job_failed"); got != 0 {
		t.Fatalf("completed discovery job alerted: got %d, want 0", got)
	}

	// The status string is exactly what DiscoveryService.UpdateJobStatus writes.
	h.exec(t, `INSERT INTO discovery_jobs (tenant_id, execution_mode, status, completed_at, error_message)
	           VALUES ($1,'active','failed', NOW(), 'probe timed out')`, tenant)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "discovery_job_failed"); got != 1 {
		t.Fatalf("failed discovery job did not raise an alert: got %d, want 1", got)
	}
}

// --- control_noncompliant ----------------------------------------------------

func TestIntegration_ControlNoncompliantScan_FiresOnActiveFinding(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	frameworkID := uuid.New()
	controlID := uuid.New()
	author := h.newPlatformAuthor(t)
	h.exec(t, `INSERT INTO platform_frameworks (id, code, name, version, created_by)
	           VALUES ($1,$2,'Predicate Audit FW','1.0',$3)`, frameworkID, "paf-"+uuid.NewString()[:8], author)
	h.exec(t, `INSERT INTO platform_framework_controls (id, framework_id, control_id, title, baseline_severity)
	           VALUES ($1,$2,'PAF-1','No weak TLS','High')`, controlID, frameworkID)
	h.exec(t, `INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
	           VALUES ($1,$2,'active')`, tenant, frameworkID)

	job := NewControlNoncompliantScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "control_noncompliant"); got != 0 {
		t.Fatalf("activated framework with no findings alerted: got %d, want 0", got)
	}

	// detection_state / workflow_status use the uppercase vocabulary the
	// reconciler writes; severity uses the 'Med'-style control vocabulary.
	h.exec(t, `INSERT INTO compliance_findings (tenant_id, control_id, asset_id, severity, summary, detection_state, workflow_status)
	           VALUES ($1,$2,$3,'High','weak cipher negotiated','ACTIVE','NEW')`, tenant, controlID, uuid.New())
	job.ScanAll()
	if got := h.alertCount(t, tenant, "control_noncompliant"); got != 1 {
		t.Fatalf("active finding on a licensed control did not raise an alert: got %d, want 1", got)
	}

	var severity string
	if err := h.owner.QueryRow(
		`SELECT severity FROM alerts WHERE tenant_id = $1 AND alert_type = 'control_noncompliant'`,
		tenant).Scan(&severity); err != nil {
		t.Fatalf("read alert severity: %v", err)
	}
	if severity != "high" {
		t.Fatalf("control baseline_severity 'High' did not map to alert severity 'high': got %q", severity)
	}
}

// --- compliance_score_drop ---------------------------------------------------

func TestIntegration_ComplianceScoreDropScan_FiresOnDrop(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	frameworkID := uuid.New()
	author := h.newPlatformAuthor(t)
	h.exec(t, `INSERT INTO platform_frameworks (id, code, name, version, created_by)
	           VALUES ($1,$2,'Score Drop FW','1.0',$3)`, frameworkID, "sdf-"+uuid.NewString()[:8], author)
	h.exec(t, `INSERT INTO tenant_framework_licenses (tenant_id, platform_framework_id, subscription_status)
	           VALUES ($1,$2,'active')`, tenant, frameworkID)
	h.exec(t, `INSERT INTO tenant_framework_scores (tenant_id, platform_framework_id, score)
	           VALUES ($1,$2,90)`, tenant, frameworkID)

	job := NewComplianceScoreDropScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)

	// No 24h-old reference yet — the job must stay silent rather than guess.
	job.ScanAll()
	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 0 {
		t.Fatalf("score drop alerted with no reference snapshot: got %d, want 0", got)
	}

	// Plant a reference older than the lookback, then drop the live score.
	h.exec(t, `INSERT INTO alert_framework_score_snapshots (tenant_id, platform_framework_id, score, captured_at)
	           VALUES ($1,$2,90, NOW() - INTERVAL '25 hours')`, tenant, frameworkID)
	h.exec(t, `UPDATE tenant_framework_scores SET score = 55 WHERE tenant_id = $1`, tenant)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "compliance_score_drop"); got != 1 {
		t.Fatalf("35-point score drop did not raise an alert: got %d, want 1", got)
	}
}

// --- asset_limit_approaching -------------------------------------------------

// newTierWithAssetCap creates a tier whose ENFORCED asset cap is `cap`, set the
// way the platform actually sets it: a tier_entitlements row against the
// max_assets billable item. `staleColumnValue` is written to the legacy
// subscription_tiers.max_assets column, which nothing enforces — pass a
// deliberately different number so a reader that still trusts it is caught.
func (h *jobHarness) newTierWithAssetCap(t *testing.T, tenant uuid.UUID, cap, staleColumnValue int) {
	t.Helper()
	tierID := uuid.New()
	h.exec(t, `INSERT INTO subscription_tiers (id, name, display_name, max_assets)
	           VALUES ($1,$2,'Predicate Audit Tier', $3)`, tierID, "pat-"+uuid.NewString()[:8], staleColumnValue)
	h.exec(t, `INSERT INTO tier_entitlements (tier_id, item_id, included_value)
	           SELECT $1, id, jsonb_build_object('quantity', $2::int) FROM billable_items WHERE key = 'max_assets'`,
		tierID, cap)
	h.exec(t, `UPDATE tenants SET subscription_tier_id = $1 WHERE id = $2`, tierID, tenant)
}

func TestIntegration_AssetLimitScan_FiresNearPlanLimit(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	// B-15: enforced cap 10, stale tier column 50. The alert must measure
	// against 10. Before the fix it read the column, so a tenant was warned at
	// the wrong usage — or, with a NULL column, classified unlimited and never
	// warned at all before the hard 402.
	h.newTierWithAssetCap(t, tenant, 10, 50)

	job := NewAssetLimitScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)

	// 3/10 = 30% — below the 80% warn rung.
	for i := 0; i < 3; i++ {
		h.exec(t, `INSERT INTO network_assets_partitioned (tenant_id, asset_type) VALUES ($1,'server')`, tenant)
	}
	job.ScanAll()
	if got := h.alertCount(t, tenant, "asset_limit_approaching"); got != 0 {
		t.Fatalf("asset usage at 30%% alerted: got %d, want 0", got)
	}

	// 9/10 = 90% — over the warn rung, under the high rung.
	// Against the stale column (50) this is 18% and would NOT alert.
	for i := 0; i < 6; i++ {
		h.exec(t, `INSERT INTO network_assets_partitioned (tenant_id, asset_type) VALUES ($1,'server')`, tenant)
	}
	job.ScanAll()
	if got := h.alertCount(t, tenant, "asset_limit_approaching"); got != 1 {
		t.Fatalf("asset usage at 90%% did not raise an alert: got %d, want 1", got)
	}
}

// TestIntegration_AssetLimitScan_IgnoresTheStaleTierColumn is the same
// disagreement pointed the other way: the legacy column says the tenant is at
// 90% of 10, the enforced cap is 1000. Reading the column would raise a
// false alarm telling a tenant to upgrade a plan they are nowhere near
// exhausting.
func TestIntegration_AssetLimitScan_IgnoresTheStaleTierColumn(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	h.newTierWithAssetCap(t, tenant, 1000, 10)

	for i := 0; i < 9; i++ {
		h.exec(t, `INSERT INTO network_assets_partitioned (tenant_id, asset_type) VALUES ($1,'server')`, tenant)
	}
	NewAssetLimitScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour).ScanAll()

	if got := h.alertCount(t, tenant, "asset_limit_approaching"); got != 0 {
		t.Fatalf("9 assets against an ENFORCED cap of 1000 alerted (it read the stale "+
			"max_assets column of 10): got %d, want 0", got)
	}
}

// TestIntegration_AssetLimitScan_HonoursAPerTenantOverride pins the negotiated
// case: a tenant-specific entitlement raises the cap above the tier's, and the
// warning has to follow it. Per-tenant overrides were invisible to this job.
func TestIntegration_AssetLimitScan_HonoursAPerTenantOverride(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)
	h.newTierWithAssetCap(t, tenant, 10, 10)

	// 9/10 = 90% on the tier — would alert.
	for i := 0; i < 9; i++ {
		h.exec(t, `INSERT INTO network_assets_partitioned (tenant_id, asset_type) VALUES ($1,'server')`, tenant)
	}
	// ...but this tenant negotiated 1000.
	h.exec(t, `INSERT INTO tenant_entitlements (tenant_id, item_id, override_value, effective_from)
	           SELECT $1, id, '{"quantity": 1000}'::jsonb, now() - interval '1 day'
	           FROM billable_items WHERE key = 'max_assets'`, tenant)

	NewAssetLimitScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour).ScanAll()

	if got := h.alertCount(t, tenant, "asset_limit_approaching"); got != 0 {
		t.Fatalf("a negotiated per-tenant cap of 1000 was ignored: got %d alerts, want 0", got)
	}
}

// --- service_down (platform track, sentinel tenant) --------------------------

func TestIntegration_ServiceDownScan_FiresOnRecentDownEvent(t *testing.T) {
	h := newJobHarness(t)
	sentinel := services.PlatformAlertTenantID
	serviceName := "predicate-audit-" + uuid.NewString()[:8]
	subject := serviceSubjectID(serviceName)
	t.Cleanup(func() {
		_, _ = h.owner.Exec(`DELETE FROM alerts WHERE tenant_id = $1 AND subject_id = $2`, sentinel, subject)
		_, _ = h.owner.Exec(`DELETE FROM service_health_events WHERE service_name = $1`, serviceName)
	})

	job := NewServiceDownScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)

	// Negative control: a stale down event is "no current signal", not an outage.
	h.exec(t, `INSERT INTO service_health_events (service_name, event_type, status, "timestamp")
	           VALUES ($1,'incident','down', NOW() - INTERVAL '3 hours')`, serviceName)
	job.Scan()
	if n := h.subjectAlertCount(t, sentinel, "service_down", subject); n != 0 {
		t.Fatalf("stale down event alerted: got %d, want 0", n)
	}

	// The status string is exactly what MetricsAggregator.storeHealthEvent writes.
	h.exec(t, `INSERT INTO service_health_events (service_name, event_type, status, "timestamp")
	           VALUES ($1,'incident','down', NOW())`, serviceName)
	job.Scan()
	if n := h.subjectAlertCount(t, sentinel, "service_down", subject); n != 1 {
		t.Fatalf("fresh down event did not raise an alert: got %d, want 1", n)
	}
}

// --- tenant_health_degraded (platform track, sentinel tenant) ----------------

func TestIntegration_TenantHealthDegradedScan_FiresBelowThreshold(t *testing.T) {
	h := newJobHarness(t)
	sentinel := services.PlatformAlertTenantID
	healthy := testdb.NewTenant(t, h.owner)
	degraded := testdb.NewTenant(t, h.owner)
	// B-12: a tenant whose peers were all unreachable stores overall_score 0
	// with health_status 'unknown'. That is "no data", not "score 0" — it must
	// NOT alert, or a mesh hiccup reports every tenant as critically degraded.
	unknown := testdb.NewTenant(t, h.owner)
	t.Cleanup(func() {
		_, _ = h.owner.Exec(`DELETE FROM alerts WHERE tenant_id = $1 AND subject_id = ANY($2)`,
			sentinel, "{"+healthy.String()+","+degraded.String()+","+unknown.String()+"}")
	})

	h.exec(t, `INSERT INTO tenant_health (tenant_id, overall_score, health_status) VALUES ($1, 92.0, 'healthy')`, healthy)
	h.exec(t, `INSERT INTO tenant_health (tenant_id, overall_score, health_status) VALUES ($1, 35.0, 'critical')`, degraded)
	h.exec(t, `INSERT INTO tenant_health (tenant_id, overall_score, health_status) VALUES ($1, 0.0, 'unknown')`, unknown)

	job := NewTenantHealthDegradedScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.Scan()

	if n := h.subjectAlertCount(t, sentinel, "tenant_health_degraded", degraded); n != 1 {
		t.Fatalf("degraded tenant did not raise an alert: got %d, want 1", n)
	}
	if n := h.subjectAlertCount(t, sentinel, "tenant_health_degraded", healthy); n != 0 {
		t.Fatalf("healthy tenant raised an alert: got %d, want 0", n)
	}
	if n := h.subjectAlertCount(t, sentinel, "tenant_health_degraded", unknown); n != 0 {
		t.Fatalf("unmeasured (health_status='unknown') tenant raised an alert: got %d, want 0", n)
	}
}

func (h *jobHarness) subjectAlertCount(t *testing.T, tenantID uuid.UUID, alertType string, subject uuid.UUID) int {
	t.Helper()
	var n int
	if err := h.owner.QueryRow(
		`SELECT COUNT(*) FROM alerts WHERE tenant_id = $1 AND alert_type = $2 AND subject_id = $3 AND status <> 'resolved'`,
		tenantID, alertType, subject).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

var _ = context.Background
