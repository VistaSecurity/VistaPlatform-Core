package services

// Database-integration tests for the two alert-engine defects.
//
// B-34 — two producers ignored the tenant's alert-catalog enable/disable toggle.
// Eight of the ten live tenant-track types gated on IsTypeEnabled inside their own
// scan job and Raise had no backstop, so the two producers that are not scan jobs
// bypassed it: handleCertificateExpiring (inventory-service's fixed 30/14/7/0-day
// lifecycle events) and audit-service's failed_login_burst, which arrives over
// alerts.raise and has no reference to tenant_alert_settings at all. Turning
// "Failed login burst" off did nothing whatsoever.
//
// B-48 — snoozing an alert did not suppress its escalation notification. Raise
// treated any non-resolved alert as escalatable and called publishAlertNotification
// unconditionally, so a user who snoozed a cert-expiry alert for a week still got
// paged every time a tighter rung was crossed inside the window — while the row
// still read 'snoozed'. Snooze's own contract says it "pauses escalation/
// re-notification until `until`".
//
// Both need a real database: the gate and the snooze check are decided from
// tenant_alert_settings and the locked alerts row.
//
// Skips unless TEST_DATABASE_URL is set (shared/testdb); `make test-integration-db`.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// alertFixture is a tenant plus an alert engine whose notification fan-out lands
// on a counting stub. natsClient is nil so every notification takes the HTTP
// fallback, which is what makes "did this notify?" observable.
type alertFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID
	engine *AlertEngineService
	stub   *notifyStub
}

func newAlertFixture(t *testing.T) *alertFixture {
	t.Helper()
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	const secret = "internal-auth-test-secret"
	t.Setenv("INTERNAL_AUTH_SECRET", secret)
	t.Setenv("USE_MTLS", "false")
	stub := newNotifyStub(t, secret)
	t.Setenv("NOTIFICATION_SERVICE_URL", stub.server.URL)

	engine := NewAlertEngineService(db, db, nil, nil)
	engine.SetAlertCatalog(NewAlertCatalogService(db))

	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM alerts WHERE tenant_id = $1`, tenant) })
	return &alertFixture{db: db, tenant: tenant, engine: engine, stub: stub}
}

func (f *alertFixture) disable(t *testing.T, alertType string) {
	t.Helper()
	if _, err := f.db.Exec(`
		INSERT INTO tenant_alert_settings (tenant_id, alert_type, enabled)
		VALUES ($1, $2, false)
		ON CONFLICT (tenant_id, alert_type) DO UPDATE SET enabled = false`,
		f.tenant, alertType); err != nil {
		t.Fatalf("disable %s: %v", alertType, err)
	}
}

func (f *alertFixture) alertCount(t *testing.T, alertType string) int {
	t.Helper()
	var n int
	if err := f.db.Get(&n, `SELECT COUNT(*) FROM alerts WHERE tenant_id = $1 AND alert_type = $2`,
		f.tenant, alertType); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

func certRaise(tenant uuid.UUID, subject uuid.UUID, severity string) events.AlertRaiseEvent {
	return events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenant,
		AlertType:    "certificate_expiring",
		Source:       "inventory-service",
		SubjectType:  "certificate",
		SubjectID:    &subject,
		SubjectLabel: "svc.example.test",
		Severity:     severity,
		Title:        "Certificate expiring: svc.example.test",
		Message:      "Certificate svc.example.test expires soon",
		Timestamp:    time.Now(),
	}
}

// --- B-34 -------------------------------------------------------------------

// TestIntegration_Raise_HonoursDisabledAlertType is the certificate half: the
// inventory-service lifecycle bridge raises unconditionally, so a tenant who
// switched the type off still got the fixed-tier escalations.
func TestIntegration_Raise_HonoursDisabledAlertType(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	subject := uuid.New()

	// Enabled (registry default): the raise lands and notifies.
	outcome, err := f.engine.Raise(ctx, certRaise(f.tenant, subject, "medium"))
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if outcome != RaiseOpened {
		t.Fatalf("outcome = %q, want %q while the type is enabled", outcome, RaiseOpened)
	}
	if f.stub.hits != 1 {
		t.Fatalf("notifications = %d, want 1 on open", f.stub.hits)
	}

	// The tenant switches "Certificate expiring" off, and the certificate crosses
	// a tighter rung. Nothing more should happen.
	f.disable(t, "certificate_expiring")
	before := f.stub.hits
	outcome, err = f.engine.Raise(ctx, certRaise(f.tenant, uuid.New(), "critical"))
	if err != nil {
		t.Fatalf("Raise while disabled: %v", err)
	}
	if outcome != RaiseSuppressed {
		t.Fatalf("outcome = %q, want %q — the tenant disabled this type", outcome, RaiseSuppressed)
	}
	if f.alertCount(t, "certificate_expiring") != 1 {
		t.Fatalf("a disabled alert type opened a second alert row")
	}
	if f.stub.hits != before {
		t.Fatalf("notifications = %d, want %d — a disabled type must not page the tenant",
			f.stub.hits, before)
	}
}

// TestIntegration_Raise_HonoursDisabledAlertTypeFromNATS is the audit-service
// half. failed_login_burst reaches this engine over alerts.raise, and
// audit-service gates only on the hardcoded rule.Enabled of its in-memory
// defaults — it has no reference to tenant_alert_settings at all — so the engine
// is the only place the tenant's toggle can be honoured for it.
func TestIntegration_Raise_HonoursDisabledAlertTypeFromNATS(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	f.disable(t, "failed_login_burst")

	user := uuid.New()
	outcome, err := f.engine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     f.tenant,
		AlertType:    "failed_login_burst",
		Source:       "audit",
		SubjectType:  "user",
		SubjectID:    &user,
		SubjectLabel: user.String(),
		Severity:     "high",
		Title:        "Multiple Failed Login Attempts",
		Message:      "5 failed logins in 5 minutes",
		Timestamp:    time.Now(),
	})
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if outcome != RaiseSuppressed {
		t.Fatalf("outcome = %q, want %q — turning off \"Failed login burst\" did nothing at all",
			outcome, RaiseSuppressed)
	}
	if f.alertCount(t, "failed_login_burst") != 0 {
		t.Fatal("a disabled alert type still opened an alert")
	}
	if f.stub.hits != 0 {
		t.Fatalf("notifications = %d, want 0", f.stub.hits)
	}
}

// TestIntegration_RaisePolicyRung_BypassesDisabledAlertType is the §8.3 polarity,
// and the reason the gate is not simply applied to every caller of Raise: "a
// tenant may disable a catalog type entirely ... but rungs contributed by an
// activated framework still open/escalate the alert. You can control noise; you
// can't fake posture."
func TestIntegration_RaisePolicyRung_BypassesDisabledAlertType(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	f.disable(t, "certificate_expiring")

	outcome, err := f.engine.RaisePolicyRung(ctx, certRaise(f.tenant, uuid.New(), "high"))
	if err != nil {
		t.Fatalf("RaisePolicyRung: %v", err)
	}
	if outcome != RaiseOpened {
		t.Fatalf("outcome = %q, want %q — a rung from an ACTIVATED framework must still open "+
			"the alert even with the catalog type disabled", outcome, RaiseOpened)
	}
	if f.alertCount(t, "certificate_expiring") != 1 {
		t.Fatal("policy rung did not open an alert")
	}
}

// TestIntegration_Raise_UnknownAndPlatformTypesFailOpen pins the other direction
// of the gate: it must never silence something it cannot resolve. A type with no
// registry entry, and a platform-track type (not in the tenant catalog at all,
// raised against a sentinel tenant), both go through untouched.
func TestIntegration_Raise_UnknownAndPlatformTypesFailOpen(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()

	// A setting row that should not apply to a type outside the tenant catalog.
	f.disable(t, "service_down")

	subject := uuid.New()
	outcome, err := f.engine.Raise(ctx, events.AlertRaiseEvent{
		EventID: uuid.New(), TenantID: f.tenant, AlertType: "service_down",
		Source: "monitoring", SubjectType: "service", SubjectID: &subject,
		SubjectLabel: "inventory-service", Severity: "high",
		Title: "Service down", Message: "no heartbeat", Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("Raise(service_down): %v", err)
	}
	if outcome == RaiseSuppressed {
		t.Fatal("a platform-track alert was suppressed by a tenant setting — platform alerts " +
			"are not in the tenant catalog and raise against a sentinel tenant")
	}

	subject2 := uuid.New()
	outcome, err = f.engine.Raise(ctx, events.AlertRaiseEvent{
		EventID: uuid.New(), TenantID: f.tenant, AlertType: "not_in_the_registry",
		Source: "somewhere", SubjectType: "thing", SubjectID: &subject2,
		SubjectLabel: "x", Severity: "high",
		Title: "Unregistered", Message: "x", Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("Raise(unregistered): %v", err)
	}
	if outcome == RaiseSuppressed {
		t.Fatal("an alert type with no registry entry was suppressed — the gate must fail open " +
			"on anything it cannot resolve")
	}
}

// --- B-48 -------------------------------------------------------------------

// TestIntegration_Raise_SnoozedAlertEscalatesWithoutNotifying is the B-48
// regression. The severity still climbs and the event chain still records it —
// posture is not faked — but the tenant is not paged inside a window they chose.
func TestIntegration_Raise_SnoozedAlertEscalatesWithoutNotifying(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	subject := uuid.New()

	if _, err := f.engine.Raise(ctx, certRaise(f.tenant, subject, "medium")); err != nil {
		t.Fatalf("open: %v", err)
	}
	if f.stub.hits != 1 {
		t.Fatalf("notifications = %d, want 1 on open", f.stub.hits)
	}

	var alertID uuid.UUID
	if err := f.db.Get(&alertID,
		`SELECT id FROM alerts WHERE tenant_id = $1 AND subject_id = $2`, f.tenant, subject); err != nil {
		t.Fatalf("read alert: %v", err)
	}
	if _, err := f.engine.Snooze(ctx, f.tenant, alertID, uuid.New(),
		time.Now().Add(7*24*time.Hour), "renewal scheduled"); err != nil {
		t.Fatalf("Snooze: %v", err)
	}
	before := f.stub.hits

	// A tighter rung is crossed inside the snooze window.
	outcome, err := f.engine.Raise(ctx, certRaise(f.tenant, subject, "critical"))
	if err != nil {
		t.Fatalf("escalating raise: %v", err)
	}
	if outcome != RaiseEscalated {
		t.Fatalf("outcome = %q, want %q — a snooze must not stop the alert from escalating",
			outcome, RaiseEscalated)
	}
	if f.stub.hits != before {
		t.Fatalf("notifications = %d, want %d — snoozing is documented to pause "+
			"escalation/re-notification, and a snoozed row paging the user is the whole defect",
			f.stub.hits, before)
	}

	var severity, status string
	if err := f.db.QueryRow(`SELECT severity, status FROM alerts WHERE id = $1`, alertID).
		Scan(&severity, &status); err != nil {
		t.Fatalf("re-read alert: %v", err)
	}
	if severity != "critical" {
		t.Fatalf("severity = %q, want critical — the escalation itself must still happen", severity)
	}
	if status != "snoozed" {
		t.Fatalf("status = %q, want snoozed", status)
	}
}

// TestIntegration_Raise_AcknowledgedAlertStillNotifies pins that the suppression
// keys on 'snoozed' specifically. Acknowledging says "I have seen this", not
// "stop telling me when it gets worse" — escalating an acknowledged alert is
// intended, and a blanket "any non-active status" check would silence it.
func TestIntegration_Raise_AcknowledgedAlertStillNotifies(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	subject := uuid.New()

	if _, err := f.engine.Raise(ctx, certRaise(f.tenant, subject, "medium")); err != nil {
		t.Fatalf("open: %v", err)
	}
	var alertID uuid.UUID
	if err := f.db.Get(&alertID,
		`SELECT id FROM alerts WHERE tenant_id = $1 AND subject_id = $2`, f.tenant, subject); err != nil {
		t.Fatalf("read alert: %v", err)
	}
	if _, err := f.engine.Acknowledge(ctx, f.tenant, alertID, uuid.New()); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	before := f.stub.hits

	if _, err := f.engine.Raise(ctx, certRaise(f.tenant, subject, "critical")); err != nil {
		t.Fatalf("escalating raise: %v", err)
	}
	if f.stub.hits != before+1 {
		t.Fatalf("notifications = %d, want %d — an ACKNOWLEDGED alert must still page on escalation",
			f.stub.hits, before+1)
	}
}

// TestIntegration_Raise_ExpiredSnoozeStillNotifies pins the bound on the silence.
// Nothing sweeps a snoozed row back to 'active' when its window lapses, so
// trusting the status column alone would turn a one-hour snooze into a permanent
// one.
func TestIntegration_Raise_ExpiredSnoozeStillNotifies(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	subject := uuid.New()

	if _, err := f.engine.Raise(ctx, certRaise(f.tenant, subject, "medium")); err != nil {
		t.Fatalf("open: %v", err)
	}
	var alertID uuid.UUID
	if err := f.db.Get(&alertID,
		`SELECT id FROM alerts WHERE tenant_id = $1 AND subject_id = $2`, f.tenant, subject); err != nil {
		t.Fatalf("read alert: %v", err)
	}
	// Snooze, then let the window lapse. Snooze() refuses a past `until`, so the
	// expiry is applied directly — which is also exactly the state a real alert
	// sits in once its window passes.
	if _, err := f.engine.Snooze(ctx, f.tenant, alertID, uuid.New(),
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatalf("Snooze: %v", err)
	}
	if _, err := f.db.Exec(
		`UPDATE alerts SET snoozed_until = NOW() - INTERVAL '1 minute' WHERE id = $1`, alertID); err != nil {
		t.Fatalf("expire snooze: %v", err)
	}
	before := f.stub.hits

	if _, err := f.engine.Raise(ctx, certRaise(f.tenant, subject, "critical")); err != nil {
		t.Fatalf("escalating raise: %v", err)
	}
	if f.stub.hits != before+1 {
		t.Fatalf("notifications = %d, want %d — an EXPIRED snooze must not keep suppressing; "+
			"nothing moves the row back to 'active' on its own", f.stub.hits, before+1)
	}
}
