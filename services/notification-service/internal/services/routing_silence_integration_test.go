package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The rule engine's failure mode is silence, not error: an alert matching no
// enabled rule is written to notification_history with status 'sent' and an
// EMPTY channels_used, and SendNotification returns nil. Every layer above —
// the NATS subscriber, the /internal/send handler ("status":"sent"), the
// producer — sees success. These tests pin that behavior and pin the marker
// that makes it distinguishable after the fact.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

func itNotificationService(t *testing.T, db *sql.DB) *NotificationService {
	t.Helper()
	return NewNotificationService(sqlx.NewDb(db, "postgres"), db, &config.Config{EncryptionMasterKey: itMasterKey})
}

// mkInAppRule creates an in-app channel plus one enabled rule matching exactly
// the given severities, and returns the channel id.
func mkInAppRule(t *testing.T, db *sql.DB, tenantID uuid.UUID, severities []string) uuid.UUID {
	t.Helper()
	channelID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_channels (id, tenant_id, channel_name, channel_type, config, enabled)
		VALUES ($1, $2, 'In-app', 'in_app', '{}'::jsonb, true)`, channelID, tenantID); err != nil {
		t.Fatalf("insert channel: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_rules
			(tenant_id, rule_name, alert_source, channel_ids, severity_filter, frequency, enabled, priority)
		VALUES ($1, 'Test rule', 'all', ARRAY[$2::uuid], $3::varchar[], 'immediate', true, 100)`,
		tenantID, channelID, pqTextArray(severities)); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	return channelID
}

// pqTextArray renders a Go slice as a Postgres array literal. (pq.Array would
// also work; a literal keeps the ::varchar[] cast in the SQL above readable.)
func pqTextArray(vals []string) string {
	out := "{"
	for i, v := range vals {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out + "}"
}

func countInApp(t *testing.T, db *sql.DB, tenantID uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM in_app_notifications WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
		t.Fatalf("count in_app_notifications: %v", err)
	}
	return n
}

// latestHistory returns (status, channels_used length, metadata) of the newest
// notification_history row for the tenant.
func latestHistory(t *testing.T, db *sql.DB, tenantID uuid.UUID) (string, int, map[string]interface{}) {
	t.Helper()
	var status string
	var nChannels int
	var metaRaw []byte
	err := db.QueryRow(`
		SELECT status, cardinality(channels_used), metadata
		FROM notification_history WHERE tenant_id = $1
		ORDER BY created_at DESC LIMIT 1`, tenantID).Scan(&status, &nChannels, &metaRaw)
	if err != nil {
		t.Fatalf("read notification_history: %v", err)
	}
	meta := map[string]interface{}{}
	if len(metaRaw) > 0 {
		_ = json.Unmarshal(metaRaw, &meta)
	}
	return status, nChannels, meta
}

// TestIntegration_Routing_UnmatchedSeverity_IsSilentButMarked is the core
// claim: an alert whose severity no rule covers is delivered NOWHERE, the call
// still succeeds, and the only durable trace is the history row — which now
// carries no_matching_channels so "reached nobody" is not indistinguishable
// from "delivered fine".
func TestIntegration_Routing_UnmatchedSeverity_IsSilentButMarked(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	ctx := context.Background()

	// Only critical is routed. This mirrors the pre-fix default pack, which
	// covered critical/high/medium/low and left "info" unrouted.
	mkInAppRule(t, db, tenantID, []string{"critical"})

	if err := svc.SendNotification(ctx, &models.SendNotificationRequest{
		TenantID:    &tenantID,
		AlertSource: "auth-service",
		AlertType:   "asset_limit_approaching",
		Severity:    "info",
		Message:     "Asset usage is at 80% of your plan limit.",
	}); err != nil {
		t.Fatalf("SendNotification returned an error (it never does — that IS the finding): %v", err)
	}

	if n := countInApp(t, db, tenantID); n != 0 {
		t.Fatalf("expected the unmatched alert to reach nobody, got %d in-app row(s)", n)
	}

	status, nChannels, meta := latestHistory(t, db, tenantID)
	if nChannels != 0 {
		t.Fatalf("expected empty channels_used, got %d", nChannels)
	}
	if status != "sent" {
		t.Fatalf("expected status 'sent' (the valid_notification_status CHECK has no suppressed member), got %q", status)
	}
	if got, ok := meta["no_matching_channels"]; !ok || got != true {
		t.Errorf("history row for a delivered-to-nobody alert lacks the no_matching_channels marker: metadata=%v", meta)
	}
}

// TestIntegration_Routing_MatchedSeverity_Delivers is the other polarity: with
// the severity routed, the same call lands in the bell and the history row is a
// real delivery with no marker. Without this, the test above would also pass if
// delivery were broken outright.
func TestIntegration_Routing_MatchedSeverity_Delivers(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	ctx := context.Background()

	mkInAppRule(t, db, tenantID, []string{"medium", "low", "info"})

	if err := svc.SendNotification(ctx, &models.SendNotificationRequest{
		TenantID:    &tenantID,
		AlertSource: "auth-service",
		AlertType:   "asset_limit_approaching",
		Severity:    "info",
		Message:     "Asset usage is at 80% of your plan limit.",
	}); err != nil {
		t.Fatalf("SendNotification: %v", err)
	}

	if n := countInApp(t, db, tenantID); n != 1 {
		t.Fatalf("expected 1 in-app notification, got %d", n)
	}
	status, nChannels, meta := latestHistory(t, db, tenantID)
	if status != "sent" || nChannels != 1 {
		t.Fatalf("expected a real delivery (status=sent, 1 channel), got status=%q channels=%d", status, nChannels)
	}
	if _, ok := meta["no_matching_channels"]; ok {
		t.Errorf("a real delivery must not carry the no_matching_channels marker: metadata=%v", meta)
	}
}

// TestIntegration_Routing_UnknownSeverity_NormalizesToInfo pins the boundary
// behavior that makes the "info" band load-bearing: a producer severity the
// platform does not recognize is degraded to info rather than rejected, so a
// tenant with no info routing loses it silently.
func TestIntegration_Routing_UnknownSeverity_NormalizesToInfo(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	ctx := context.Background()

	mkInAppRule(t, db, tenantID, []string{"info"})

	if err := svc.SendNotification(ctx, &models.SendNotificationRequest{
		TenantID:    &tenantID,
		AlertSource: "billing",
		AlertType:   "trial_expiring_soon",
		Severity:    "URGENT-ISH", // not a canonical severity
		Message:     "Your trial expires in 3 days.",
	}); err != nil {
		t.Fatalf("SendNotification: %v", err)
	}

	if n := countInApp(t, db, tenantID); n != 1 {
		t.Fatalf("unknown severity should normalize to info and match the info rule; got %d in-app row(s)", n)
	}
	var severity string
	if err := db.QueryRow(`SELECT severity FROM notification_history WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
		tenantID).Scan(&severity); err != nil {
		t.Fatalf("read severity: %v", err)
	}
	if severity != "info" {
		t.Errorf("expected normalized severity 'info', got %q", severity)
	}
}
