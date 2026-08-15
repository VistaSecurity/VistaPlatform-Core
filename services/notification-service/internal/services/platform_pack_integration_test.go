package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The platform track's failure mode was total silence out of the box:
// scripts/database/seed.sql created no platform_notification_channels and no
// platform_notification_rules, so service_down — a live, critical, correctly
// detected platform alert — reached zero channels on every fresh install.
//
// These tests exercise the SEEDED pack itself (they create no channels or
// rules of their own), so they fail if the seed block is removed, weakened, or
// its severity coverage develops a hole.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

// countPlatformInApp counts operator-bell rows carrying the given message.
// platform_in_app_notifications is a global table with no tenant column, so a
// unique message is the only way to isolate one test's deliveries from another's.
func countPlatformInApp(t *testing.T, db *sql.DB, message string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_in_app_notifications WHERE message = $1`,
		message).Scan(&n); err != nil {
		t.Fatalf("count platform_in_app_notifications: %v", err)
	}
	return n
}

// platformHistoryChannels returns cardinality(channels_used) for the newest
// platform (tenant_id IS NULL) notification_history row with this message.
func platformHistoryChannels(t *testing.T, db *sql.DB, message string) int {
	t.Helper()
	var n int
	err := db.QueryRow(`
		SELECT cardinality(channels_used) FROM notification_history
		WHERE tenant_id IS NULL AND message = $1
		ORDER BY created_at DESC LIMIT 1`, message).Scan(&n)
	if err != nil {
		t.Fatalf("read platform notification_history: %v", err)
	}
	return n
}

// TestIntegration_PlatformPack_RoutesServiceDown is the core claim: with only
// what seed.sql creates, a service_down-shaped platform notification reaches a
// real channel. Mutation check for this test: delete the seeded
// 'Default platform critical alerts' rule and it fails on zero deliveries.
func TestIntegration_PlatformPack_RoutesServiceDown(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	svc := itNotificationService(t, db)
	ctx := context.Background()

	msg := "Service auth-service is failing health checks. (" + uuid.NewString() + ")"

	// Exactly the shape the alert engine publishes for service_down: platform
	// track (no tenant), source monitoring, fixed critical severity.
	if err := svc.SendNotification(ctx, &models.SendNotificationRequest{
		TenantID:    nil,
		AlertSource: "monitoring",
		AlertType:   "service_down",
		Severity:    "critical",
		Message:     msg,
	}); err != nil {
		// SendNotification tolerates individual channel failures (the seeded
		// email channel has no SMTP config in a test database), so an error
		// here means routing itself broke.
		t.Fatalf("SendNotification: %v", err)
	}

	if n := countPlatformInApp(t, db, msg); n != 1 {
		t.Fatalf("seeded platform pack delivered service_down to the operator bell %d times, want 1 "+
			"(zero means the platform track is silent out of the box — the bug this seed exists to fix)", n)
	}
	if n := platformHistoryChannels(t, db, msg); n < 1 {
		t.Errorf("notification_history records %d channels used for a delivered alert, want at least 1", n)
	}
}

// TestIntegration_PlatformPack_LowSeverityDoesNotPageAdmins is the other
// polarity: the pack must discriminate, not match everything. An info-severity
// platform notification lands in the bell but must NOT be routed to the email
// channel — otherwise "critical+high goes to email" is not a real filter and
// the first test above would pass even for a catch-all rule.
func TestIntegration_PlatformPack_LowSeverityDoesNotPageAdmins(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	svc := itNotificationService(t, db)

	emailID := seededPlatformChannelID(t, db, "Platform admin email")
	inAppID := seededPlatformChannelID(t, db, "Platform in-app")

	rules, err := svc.ruleEngine.GetPlatformRulesForAlert("monitoring", "metric_threshold", "info")
	if err != nil {
		t.Fatalf("GetPlatformRulesForAlert: %v", err)
	}
	matched := map[uuid.UUID]bool{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		for _, ch := range r.ChannelIDs {
			matched[ch] = true
		}
	}
	if matched[emailID] {
		t.Errorf("info-severity platform notification routed to the admin email channel; " +
			"the critical+high severity filter is not discriminating")
	}
	if !matched[inAppID] {
		t.Errorf("info-severity platform notification reached no in-app channel — the activity-feed rule is broken")
	}
}

// TestIntegration_PlatformPack_CoversEverySeverityBand pins the hole the tenant
// pack once had. NormalizeSeverity collapses every producer severity onto five
// values and its default branch degrades anything unrecognized to 'info', so a
// band left unrouted is a silent drop, not a gap in coverage anyone would see.
func TestIntegration_PlatformPack_CoversEverySeverityBand(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	svc := itNotificationService(t, db)

	// Every value NormalizeSeverity can return, plus a producer severity it
	// does not recognize (which must degrade into a covered band).
	for _, raw := range []string{"critical", "high", "medium", "low", "info", "", "WEIRD-SEVERITY"} {
		norm := NormalizeSeverity(raw)
		rules, err := svc.ruleEngine.GetPlatformRulesForAlert("monitoring", "service_down", norm)
		if err != nil {
			t.Fatalf("GetPlatformRulesForAlert(%q): %v", norm, err)
		}
		channels := 0
		for _, r := range rules {
			if r.Enabled {
				channels += len(r.ChannelIDs)
			}
		}
		if channels == 0 {
			t.Errorf("severity %q (normalized from %q) is routed to NO channel — "+
				"every notification landing in that band is dropped silently", norm, raw)
		}
	}
}

// TestIntegration_PlatformPack_DoesNotServeTenantAlerts proves the platform
// pack is scoped to the platform track: a tenant with no rules of its own is
// still silent, even though platform rules with alert_source 'all' exist.
func TestIntegration_PlatformPack_DoesNotServeTenantAlerts(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	ctx := context.Background()

	msg := "tenant-scoped alert " + uuid.NewString()
	if err := svc.SendNotification(ctx, &models.SendNotificationRequest{
		TenantID:    &tenantID,
		AlertSource: "monitoring",
		AlertType:   "service_down",
		Severity:    "critical",
		Message:     msg,
	}); err != nil {
		t.Fatalf("SendNotification: %v", err)
	}

	if n := countPlatformInApp(t, db, msg); n != 0 {
		t.Errorf("a tenant-scoped alert reached the PLATFORM operator bell %d time(s); "+
			"platform rules must not serve tenant notifications", n)
	}
}

// TestIntegration_PlatformPack_EmailChannelStoresNoAddress pins the design
// property that makes seeding an email channel possible at all: the channel
// names a ROLE, resolved against platform_users at send time. A seeded literal
// address would be wrong on every install and would have to be edited before
// the pack worked — i.e. it would not be a working default.
func TestIntegration_PlatformPack_EmailChannelStoresNoAddress(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	var cfg string
	if err := db.QueryRow(`
		SELECT config::text FROM platform_notification_channels
		WHERE channel_name = 'Platform admin email'`).Scan(&cfg); err != nil {
		t.Fatalf("read seeded email channel: %v", err)
	}

	var role sql.NullString
	if err := db.QueryRow(`
		SELECT config->>'recipient_role' FROM platform_notification_channels
		WHERE channel_name = 'Platform admin email'`).Scan(&role); err != nil {
		t.Fatalf("read recipient_role: %v", err)
	}
	if !role.Valid || role.String == "" {
		t.Fatalf("seeded platform email channel has no recipient_role (config=%s); "+
			"it cannot resolve any recipient before an operator edits it", cfg)
	}

	// The role must actually exist and hold at least one active operator on a
	// freshly seeded install, or the channel resolves to nobody.
	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM platform_users pu
		JOIN platform_roles pr ON pr.id = pu.role_id
		WHERE pr.name = $1 AND pu.is_active = true AND pu.deleted_at IS NULL
		  AND pu.email IS NOT NULL AND pu.email <> ''`, role.String).Scan(&n); err != nil {
		t.Fatalf("resolve platform role recipients: %v", err)
	}
	if n == 0 {
		t.Errorf("recipient_role %q resolves to zero active platform users on a seeded install; "+
			"the seeded email channel would fail with 'no valid recipients found'", role.String)
	}
}

// TestIntegration_MonitoringThresholds_AreSeededAndEvaluable checks the seeded
// thresholds against the evaluator's actual constraints. Every one of these
// assertions corresponds to a way a threshold row can exist and still be
// permanently inert — which is indistinguishable from a healthy platform.
func TestIntegration_MonitoringThresholds_AreSeededAndEvaluable(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	rows, err := db.Query(`
		SELECT threshold_name, metric_type, service_name, warning_threshold,
		       critical_threshold, comparison_operator, enabled
		FROM monitoring_alert_thresholds`)
	if err != nil {
		t.Fatalf("query thresholds: %v", err)
	}
	defer func() { _ = rows.Close() }()

	// Metric types the evaluator can actually read from a snapshot.
	// cpu_usage / memory_usage hit an explicit `return nil`.
	evaluable := map[string]bool{"response_time": true, "error_rate": true, "throughput": true}

	count := 0
	for rows.Next() {
		var name, metricType, operator string
		var serviceName sql.NullString
		var warning, critical sql.NullFloat64
		var enabled bool
		if err := rows.Scan(&name, &metricType, &serviceName, &warning, &critical, &operator, &enabled); err != nil {
			t.Fatalf("scan threshold: %v", err)
		}
		count++

		if !serviceName.Valid || serviceName.String == "" {
			t.Errorf("threshold %q has no service_name; GetServiceMetrics filters service_name = $1 "+
				"exactly, so it can never match a snapshot", name)
		}
		if !evaluable[metricType] {
			t.Errorf("threshold %q uses metric_type %q, which the evaluator does not read from snapshots", name, metricType)
		}
		if !warning.Valid && !critical.Valid {
			t.Errorf("threshold %q sets neither warning nor critical; nothing can breach", name)
		}
		if warning.Valid && critical.Valid && operator == "gt" && warning.Float64 >= critical.Float64 {
			t.Errorf("threshold %q: warning %.1f >= critical %.1f under 'gt'; the warning rung is unreachable",
				name, warning.Float64, critical.Float64)
		}
		if !enabled {
			t.Errorf("threshold %q is seeded disabled; the evaluator only reads enabled rows", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate thresholds: %v", err)
	}
	if count == 0 {
		t.Fatal("monitoring_alert_thresholds is empty — metric_threshold is a live alert type " +
			"whose detector has nothing to evaluate, so it cannot fire on a fresh install")
	}
}

// TestIntegration_PlatformSeed_PreservesOperatorConfiguration re-applies the
// seed over an operator-customized pack, which is what every helm upgrade does.
// Re-seeding must add nothing and change nothing.
func TestIntegration_PlatformSeed_PreservesOperatorConfiguration(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	const customName = "Operator-renamed critical alerts"
	origRuleName := "Default platform critical alerts"

	var ruleID uuid.UUID
	if err := db.QueryRow(`SELECT id FROM platform_notification_rules WHERE rule_name = $1`,
		origRuleName).Scan(&ruleID); err != nil {
		t.Fatalf("find seeded rule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`UPDATE platform_notification_rules SET rule_name = $1, enabled = true WHERE id = $2`,
			origRuleName, ruleID)
	})

	// Operator renames the rule and turns it off — a configuration decision the
	// seed must never override.
	if _, err := db.Exec(`UPDATE platform_notification_rules SET rule_name = $1, enabled = false WHERE id = $2`,
		customName, ruleID); err != nil {
		t.Fatalf("customize rule: %v", err)
	}

	beforeRules, beforeChannels, beforeThresholds := platformPackCounts(t, db)

	// The upgrade.
	testdb.ApplySchemaAndSeed(t, db)

	afterRules, afterChannels, afterThresholds := platformPackCounts(t, db)
	if beforeRules != afterRules || beforeChannels != afterChannels || beforeThresholds != afterThresholds {
		t.Errorf("re-applying seed.sql changed row counts: rules %d→%d, channels %d→%d, thresholds %d→%d "+
			"(seeding must be first-install-only in effect)",
			beforeRules, afterRules, beforeChannels, afterChannels, beforeThresholds, afterThresholds)
	}

	var gotName string
	var gotEnabled bool
	if err := db.QueryRow(`SELECT rule_name, enabled FROM platform_notification_rules WHERE id = $1`,
		ruleID).Scan(&gotName, &gotEnabled); err != nil {
		t.Fatalf("re-read customized rule: %v", err)
	}
	if gotName != customName || gotEnabled {
		t.Errorf("re-applying seed.sql overwrote operator configuration: rule_name=%q enabled=%v, want %q/false",
			gotName, gotEnabled, customName)
	}
}

func platformPackCounts(t *testing.T, db *sql.DB) (rules, channels, thresholds int) {
	t.Helper()
	q := func(sqlText string) int {
		var n int
		if err := db.QueryRow(sqlText).Scan(&n); err != nil {
			t.Fatalf("count (%s): %v", sqlText, err)
		}
		return n
	}
	return q(`SELECT COUNT(*) FROM platform_notification_rules`),
		q(`SELECT COUNT(*) FROM platform_notification_channels`),
		q(`SELECT COUNT(*) FROM monitoring_alert_thresholds`)
}

func seededPlatformChannelID(t *testing.T, db *sql.DB, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM platform_notification_channels WHERE channel_name = $1`,
		name).Scan(&id); err != nil {
		t.Fatalf("seeded platform channel %q not found: %v", name, err)
	}
	return id
}
