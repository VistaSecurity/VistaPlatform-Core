package services

// Database-backed proofs for the notification-channel fixes: an unconfigured
// email channel is an explicit permanent outcome (not five retries against
// localhost), a suspended tenant is not notified, Test goes through the real
// manager and reports a safe reason, and a platform channel round-tripped in its
// masked form keeps its stored secret.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_EmailNotConfigured_IsExplicitPermanentAndNeverRetried(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	svc.deliveryService.emailConfigFn = func(*uuid.UUID) (*email.EmailConfig, error) { return nil, email.ErrNotConfigured }

	ch := mkChannelRule(t, db, tenantID, "email", `{"recipients":["ops@example.test"]}`)
	sendOne(t, svc, tenantID)

	h := onlyHistory(t, db, tenantID)
	if h.status != "failed" {
		t.Errorf("history status = %q, want failed", h.status)
	}
	r := h.resultFor(t, ch)
	if r["status"] != "failed" {
		t.Errorf("channel result = %v, want failed (permanent — never 'retrying')", r)
	}
	if r["reason"] != reasonEmailNotConfigured {
		t.Errorf("channel result reason = %v, want %q", r["reason"], reasonEmailNotConfigured)
	}

	rows := queueRows(t, db, tenantID)
	if len(rows) != 1 || rows[0].status != "failed" || rows[0].nextRetryAt.Valid {
		t.Fatalf("queue = %+v; want ONE terminal 'failed' row with no next_retry_at (the old behaviour was 5 retries)", rows)
	}
	makeQueueDue(t, db, tenantID)
	if n, err := svc.RetryDueDeliveries(context.Background()); err != nil || n != 0 {
		t.Errorf("RetryDueDeliveries = %d, %v; nothing should be retried", n, err)
	}
}

// The other polarity: a configured-but-unreachable SMTP server IS transient and
// IS retried. "Not configured" must not have become a blanket for email errors.
func TestIntegration_EmailConfiguredButUnreachable_StillRetries(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	svc.deliveryService.emailConfigFn = func(*uuid.UUID) (*email.EmailConfig, error) {
		return &email.EmailConfig{SMTPHost: "127.0.0.1", SMTPPort: "1", FromEmail: "noreply@example.test", FromName: "Vista"}, nil
	}

	ch := mkChannelRule(t, db, tenantID, "email", `{"recipients":["ops@example.test"]}`)
	sendOne(t, svc, tenantID)

	r := onlyHistory(t, db, tenantID).resultFor(t, ch)
	if r["status"] != "retrying" {
		t.Errorf("channel result = %v, want retrying for an unreachable mail server", r)
	}
	if r["reason"] != reasonSMTPUnreachable {
		t.Errorf("reason = %v, want %q", r["reason"], reasonSMTPUnreachable)
	}
	if rows := queueRows(t, db, tenantID); len(rows) != 1 || rows[0].status != "retrying" {
		t.Errorf("queue = %+v, want one retrying row", rows)
	}
}

// The retry payload carries the notification's event id, so a re-send is the
// same X-Vista-Event-Id.
func TestIntegration_RetryPayloadCarriesTheEventID(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)

	const producerID = "6f1c1c0e-3b0a-4c2e-9b1e-0a1b2c3d4e5f"
	if err := svc.SendNotification(context.Background(), &models.SendNotificationRequest{
		TenantID: &tenantID, AlertSource: "compliance", AlertType: "control_noncompliant", Severity: "high",
		Message: "m", EventID: producerID,
	}); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(queueRows(t, db, tenantID)[0].payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.EventID != producerID {
		t.Errorf("retry payload event_id = %q, want the producer's %q", payload.EventID, producerID)
	}

	// No producer id: one is assigned before the payload is stored.
	tenant2 := testdb.NewTenant(t, db)
	mkChannelRule(t, db, tenant2, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenant2)
	payload.EventID = ""
	if err := json.Unmarshal(queueRows(t, db, tenant2)[0].payload, &payload); err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(payload.EventID); err != nil {
		t.Errorf("assigned event_id %q is not a UUID: %v", payload.EventID, err)
	}
}

// When retries run out, the history row says why — in the safe vocabulary, not
// the raw error (which embeds the webhook URL).
func TestIntegration_ExhaustedRetryRecordsASafeReason(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	t.Setenv("NOTIFICATION_DELIVERY_MAX_ATTEMPTS", "1")

	ch := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)
	if r := onlyHistory(t, db, tenantID).resultFor(t, ch); r["status"] != "retrying" {
		t.Fatalf("precondition: first attempt result = %v, want retrying", r)
	}

	// The retry fails for a DIFFERENT reason than the first attempt did (the
	// channel now points at an unreachable mail server), so the terminal reason
	// must come from the retry — not be a leftover from attempt one.
	if _, err := db.Exec(`UPDATE tenant_notification_channels SET channel_type='email', config='{"recipients":["ops@example.test"]}'::jsonb WHERE id=$1`, ch); err != nil {
		t.Fatal(err)
	}
	svc.deliveryService.emailConfigFn = func(*uuid.UUID) (*email.EmailConfig, error) {
		return &email.EmailConfig{SMTPHost: "127.0.0.1", SMTPPort: "1", FromEmail: "noreply@example.test", FromName: "Vista"}, nil
	}
	makeQueueDue(t, db, tenantID)
	if n, err := svc.RetryDueDeliveries(context.Background()); err != nil || n != 0 {
		t.Fatalf("RetryDueDeliveries = %d, %v; the retry must fail", n, err)
	}
	h := onlyHistory(t, db, tenantID)
	r := h.resultFor(t, ch)
	if r["status"] != "failed" || r["retries_exhausted"] != true {
		t.Fatalf("result = %v, want failed + retries_exhausted", r)
	}
	if r["reason"] != reasonSMTPUnreachable {
		t.Errorf("reason = %v, want the retry's own reason %q", r["reason"], reasonSMTPUnreachable)
	}
	if strings.Contains(h.rawMeta, "webhook.invalid") || strings.Contains(h.rawMeta, "127.0.0.1") {
		t.Errorf("history metadata leaks a host: %s", h.rawMeta)
	}
}

// A retry that hits a PERMANENT failure records that failure's reason too.
func TestIntegration_PermanentFailureOnRetryRecordsItsReason(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	ch := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)
	// The URL is edited to one the SSRF policy refuses: permanent on the retry.
	if _, err := db.Exec(`UPDATE tenant_notification_channels SET config = $2::jsonb WHERE id=$1`, ch, `{"url":"`+blockedWebhook+`"}`); err != nil {
		t.Fatal(err)
	}
	makeQueueDue(t, db, tenantID)
	if _, err := svc.RetryDueDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := onlyHistory(t, db, tenantID).resultFor(t, ch)
	if r["status"] != "failed" || r["reason"] != reasonAddressNotAllowed {
		t.Fatalf("result = %v, want failed with reason %q", r, reasonAddressNotAllowed)
	}
}

// Test through the REAL manager: stored (encrypted) config is decrypted, the
// failure comes back as a *ChannelTestError with a safe reason, and the row's
// test_status records it.
func TestIntegration_TestTenantChannel_ReturnsASafeReasonAndRecordsTheStatus(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	cm := itChannelManager(t, db)

	created, err := cm.CreateTenantChannel(context.Background(), tenant, &models.CreateChannelRequest{
		ChannelName: "hook", ChannelType: "webhook", Enabled: true,
		Config: map[string]interface{}{"url": "http://localhost/hooks/xoxb-SECRET-TOKEN-123456?apikey=SUPERSECRETKEY"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = cm.TestTenantChannel(context.Background(), tenant, created.ID)
	var failed *ChannelTestError
	if !errors.As(err, &failed) {
		t.Fatalf("TestTenantChannel = %T (%v), want *ChannelTestError", err, err)
	}
	if failed.Reason != reasonAddressNotAllowed || !failed.Permanent {
		t.Errorf("reason=%q permanent=%t, want the address-not-allowed sentence, permanent", failed.Reason, failed.Permanent)
	}
	for _, leak := range []string{"xoxb-SECRET", "SUPERSECRETKEY", "localhost"} {
		if strings.Contains(failed.Reason, leak) {
			t.Errorf("reason leaks %q: %s", leak, failed.Reason)
		}
	}
	var status string
	if err := db.QueryRow(`SELECT test_status FROM tenant_notification_channels WHERE id = $1`, created.ID).Scan(&status); err != nil || status != "failed" {
		t.Errorf("test_status = %q (%v), want failed", status, err)
	}

	// A missing channel is a distinct error, not a "test failed".
	if err := cm.TestTenantChannel(context.Background(), tenant, uuid.New()); !errors.Is(err, ErrChannelNotFound) {
		t.Errorf("unknown channel: err = %v, want ErrChannelNotFound", err)
	}
}

// --- suspended / canceled tenants -------------------------------------------

func countRows(t *testing.T, db *sql.DB, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestIntegration_SuspendedTenant_IsNotNotified(t *testing.T) {
	for _, status := range []string{"suspended", "canceled"} {
		t.Run(status, func(t *testing.T) {
			db := testdb.Connect(t)
			testdb.ApplySchemaAndSeed(t, db)
			tenantID := testdb.NewTenant(t, db)
			svc := itNotificationService(t, db)
			mkChannelRule(t, db, tenantID, "in_app", `{}`)

			if _, err := db.Exec(`UPDATE tenants SET payment_status = $1 WHERE id = $2`, status, tenantID); err != nil {
				t.Fatal(err)
			}
			sendOne(t, svc, tenantID)
			if n := countRows(t, db, `SELECT count(*) FROM notification_history WHERE tenant_id = $1`, tenantID); n != 0 {
				t.Errorf("%d history row(s) recorded for a %s tenant, want none", n, status)
			}
			if n := countRows(t, db, `SELECT count(*) FROM in_app_notifications WHERE tenant_id = $1`, tenantID); n != 0 {
				t.Errorf("%d in-app notification(s) delivered to a %s tenant, want none", n, status)
			}

			// Reactivated: the very same channel and rule now deliver (proves the
			// silence above was the gate, not a broken fixture).
			if _, err := db.Exec(`UPDATE tenants SET payment_status = 'active' WHERE id = $1`, tenantID); err != nil {
				t.Fatal(err)
			}
			sendOne(t, svc, tenantID)
			if h := onlyHistory(t, db, tenantID); h.status != "sent" {
				t.Errorf("after reactivation status = %q, want sent", h.status)
			}
			if n := countRows(t, db, `SELECT count(*) FROM in_app_notifications WHERE tenant_id = $1`, tenantID); n != 1 {
				t.Errorf("after reactivation %d in-app notification(s), want 1", n)
			}
		})
	}
}

// A retry queued BEFORE the suspension is not delivered after it.
func TestIntegration_SuspensionStopsQueuedRetries(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	ch := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)
	if rows := queueRows(t, db, tenantID); len(rows) != 1 || rows[0].status != "retrying" {
		t.Fatalf("precondition: queue = %+v, want one retrying row", rows)
	}

	if _, err := db.Exec(`UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	makeQueueDue(t, db, tenantID)
	if n, err := svc.RetryDueDeliveries(context.Background()); err != nil || n != 0 {
		t.Fatalf("RetryDueDeliveries = %d, %v", n, err)
	}
	rows := queueRows(t, db, tenantID)
	if len(rows) != 1 || rows[0].status != "failed" {
		t.Fatalf("queue = %+v, want the row terminal 'failed' rather than retried", rows)
	}
	r := onlyHistory(t, db, tenantID).resultFor(t, ch)
	if r["reason"] != "The organization is suspended, so notifications are not delivered." {
		t.Errorf("history reason = %v", r["reason"])
	}
}

// A digest batched BEFORE the suspension is dropped, not flushed to the tenant.
func TestIntegration_SuspensionDropsBatchedDigests(t *testing.T) {
	for _, suspended := range []bool{true, false} {
		name := "active tenant flushes"
		if suspended {
			name = "suspended tenant is dropped"
		}
		t.Run(name, func(t *testing.T) {
			db := testdb.Connect(t)
			testdb.ApplySchemaAndSeed(t, db)
			tenantID := testdb.NewTenant(t, db)
			svc := itNotificationService(t, db)

			channelID := uuid.New()
			if _, err := db.Exec(`
				INSERT INTO tenant_notification_channels (id, tenant_id, channel_name, channel_type, config, enabled)
				VALUES ($1, $2, 'digest in-app', 'in_app', '{}'::jsonb, true)`, channelID, tenantID); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`
				INSERT INTO tenant_notification_rules
					(tenant_id, rule_name, alert_source, channel_ids, severity_filter, frequency, enabled, priority)
				VALUES ($1, 'digest rule', 'all', ARRAY[$2::uuid], '{critical,high,medium,low,info}'::varchar[], 'digest_hourly', true, 100)`,
				tenantID, channelID); err != nil {
				t.Fatal(err)
			}
			sendOne(t, svc, tenantID) // batched: nothing delivered yet
			if n := countRows(t, db, `SELECT count(*) FROM notification_digest_queue WHERE tenant_id = $1`, tenantID); n != 1 {
				t.Fatalf("precondition: %d batched item(s), want 1", n)
			}

			if suspended {
				if _, err := db.Exec(`UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`, tenantID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`UPDATE notification_digest_queue SET flush_after = NOW() - interval '1 minute' WHERE tenant_id = $1`, tenantID); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.FlushDueDigests(context.Background()); err != nil {
				t.Fatal(err)
			}

			inApp := countRows(t, db, `SELECT count(*) FROM in_app_notifications WHERE tenant_id = $1`, tenantID)
			left := countRows(t, db, `SELECT count(*) FROM notification_digest_queue WHERE tenant_id = $1`, tenantID)
			switch {
			case suspended && inApp != 0:
				t.Errorf("a digest was delivered to a suspended tenant (%d in-app row(s))", inApp)
			case !suspended && inApp != 1:
				t.Errorf("an active tenant's digest was not delivered (%d in-app row(s))", inApp)
			}
			if left != 0 {
				t.Errorf("%d batched item(s) left in the queue; they must be flushed or dropped, never kept forever", left)
			}
		})
	}
}

// --- platform channels -------------------------------------------------------

// The platform GETs now return masked configs, so an admin UI that edits a
// channel PUTs the masked form back. That must keep the stored secret.
func TestIntegration_PlatformChannelUpdate_MaskedRoundTripKeepsTheSecret(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	cm := itChannelManager(t, db)

	created, err := cm.CreatePlatformChannel(&models.CreateChannelRequest{
		ChannelName: "w15-platform-" + uuid.NewString()[:8], ChannelType: "webhook", Enabled: true,
		Config: map[string]interface{}{
			"url":            "https://hooks.example.test/T0/platform-secret-path",
			"webhook_secret": "whsec_platform_secret_value",
			"auth":           map[string]interface{}{"type": "bearer", "token": "platform-bearer-token-1234"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cm.DeletePlatformChannel(created.ID) })

	masked := MaskChannelConfig(created.Config)
	if _, err := cm.UpdatePlatformChannel(created.ID, &models.UpdateChannelRequest{Config: masked}, nil); err != nil {
		t.Fatal(err)
	}
	back, err := cm.GetPlatformChannelByID(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.Config["url"] != "https://hooks.example.test/T0/platform-secret-path" ||
		back.Config["webhook_secret"] != "whsec_platform_secret_value" {
		t.Errorf("a masked round-trip overwrote stored secrets: %v", back.Config)
	}
	if auth, _ := back.Config["auth"].(map[string]interface{}); auth["token"] != "platform-bearer-token-1234" {
		t.Errorf("auth.token was overwritten: %v", back.Config["auth"])
	}

	// A genuinely new value still replaces (rotation).
	if _, err := cm.UpdatePlatformChannel(created.ID, &models.UpdateChannelRequest{
		Config: map[string]interface{}{"url": "https://hooks.example.test/T0/platform-secret-path", "webhook_secret": "whsec_rotated_value"},
	}, nil); err != nil {
		t.Fatal(err)
	}
	back, _ = cm.GetPlatformChannelByID(created.ID)
	if back.Config["webhook_secret"] != "whsec_rotated_value" {
		t.Errorf("webhook_secret = %v, want the rotated value", back.Config["webhook_secret"])
	}
}
