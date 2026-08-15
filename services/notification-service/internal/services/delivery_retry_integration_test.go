package services

// Gap 2 regression tests: notification_delivery_queue shipped with retry_count,
// next_retry_at, a 'retrying' status and a retention sweep that spares
// non-terminal rows — and was only ever DELETEd from. A channel send that failed
// was attempted exactly once and lost.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// unreachableWebhook is a hostname that cannot resolve. It produces a TRANSIENT
// failure (see network.ErrUnresolvableHost) rather than an SSRF policy
// rejection, and it fails fast without touching the network.
const unreachableWebhook = "https://webhook.invalid/hook"

// blockedWebhook resolves to a private address, so ValidateWebhookURL rejects it
// on policy — a PERMANENT failure no retry can fix.
const blockedWebhook = "http://127.0.0.1:1/hook"

// mkChannelRule creates a channel of the given type plus one enabled rule
// routing every severity to it, and returns the channel id.
func mkChannelRule(t *testing.T, db *sql.DB, tenantID uuid.UUID, channelType, cfg string) uuid.UUID {
	t.Helper()
	channelID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_channels (id, tenant_id, channel_name, channel_type, config, enabled)
		VALUES ($1, $2, $3, $4, $5::jsonb, true)`,
		channelID, tenantID, channelType+" channel", channelType, cfg); err != nil {
		t.Fatalf("insert %s channel: %v", channelType, err)
	}
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_rules
			(tenant_id, rule_name, alert_source, channel_ids, severity_filter, frequency, enabled, priority)
		VALUES ($1, $2, 'all', ARRAY[$3::uuid], '{critical,high,medium,low,info}'::varchar[], 'immediate', true, 100)`,
		tenantID, channelType+" rule", channelID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	return channelID
}

type queueRow struct {
	id          uuid.UUID
	channelID   uuid.UUID
	channelType string
	status      string
	retryCount  int
	nextRetryAt sql.NullTime
	deliveredAt sql.NullTime
	errMessage  sql.NullString
	payload     []byte
}

func queueRows(t *testing.T, db *sql.DB, tenantID uuid.UUID) []queueRow {
	t.Helper()
	rows, err := db.Query(`
		SELECT id, channel_id, channel_type, status, retry_count, next_retry_at, delivered_at, error_message, payload
		FROM notification_delivery_queue WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		t.Fatalf("read notification_delivery_queue: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []queueRow
	for rows.Next() {
		var r queueRow
		if err := rows.Scan(&r.id, &r.channelID, &r.channelType, &r.status, &r.retryCount,
			&r.nextRetryAt, &r.deliveredAt, &r.errMessage, &r.payload); err != nil {
			t.Fatalf("scan queue row: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func sendOne(t *testing.T, svc *NotificationService, tenantID uuid.UUID) {
	t.Helper()
	if err := svc.SendNotification(context.Background(), &models.SendNotificationRequest{
		TenantID:    &tenantID,
		AlertSource: "compliance",
		AlertType:   "control_noncompliant",
		Severity:    "high",
		Title:       "Control noncompliant: PCI-3.4",
		Message:     "TLS 1.0 is in use on 3 assets.",
	}); err != nil {
		t.Fatalf("SendNotification: %v", err)
	}
}

// The core claim: a transient channel failure is now durably queued for retry.
// Pre-fix this table had zero INSERTs anywhere in the codebase, so this returned
// no rows and the notification was gone.
func TestIntegration_DeliveryRetry_TransientFailureIsEnqueued(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	channelID := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)

	rows := queueRows(t, db, tenantID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 queued retry, got %d — a failed send is attempted once and lost", len(rows))
	}
	r := rows[0]
	if r.status != "retrying" {
		t.Errorf("status = %q, want retrying", r.status)
	}
	if r.channelID != channelID {
		t.Errorf("channel_id = %s, want the failed channel %s", r.channelID, channelID)
	}
	if r.retryCount != 0 {
		t.Errorf("retry_count = %d, want 0 on first enqueue", r.retryCount)
	}
	if !r.nextRetryAt.Valid || !r.nextRetryAt.Time.After(time.Now()) {
		t.Errorf("next_retry_at = %v, want a future time (backoff, not an immediate hot loop)", r.nextRetryAt)
	}
	if !r.errMessage.Valid || r.errMessage.String == "" {
		t.Error("error_message is empty — the reason for the failure must be durable")
	}
	// The payload must round-trip, or the retry has nothing to send.
	var req models.SendNotificationRequest
	if err := json.Unmarshal(r.payload, &req); err != nil {
		t.Fatalf("stored payload is not a decodable request: %v", err)
	}
	if req.Title != "Control noncompliant: PCI-3.4" || req.Severity != "high" {
		t.Errorf("payload lost content: %+v", req)
	}
}

// A permanent failure gets a terminal record immediately instead of four futile
// retries — but it still gets a record. Silently dropping it is the defect.
func TestIntegration_DeliveryRetry_PermanentFailureIsRecordedNotRetried(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+blockedWebhook+`"}`)
	sendOne(t, svc, tenantID)

	rows := queueRows(t, db, tenantID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 terminal record, got %d", len(rows))
	}
	r := rows[0]
	if r.status != "failed" {
		t.Errorf("status = %q, want failed (an SSRF-rejected URL cannot become valid by retrying)", r.status)
	}
	if r.nextRetryAt.Valid {
		t.Errorf("next_retry_at = %v, want NULL — a permanent failure must not be scheduled", r.nextRetryAt)
	}
	if !r.errMessage.Valid || r.errMessage.String == "" {
		t.Error("terminal failure carries no error_message — giving up silently is the same defect class")
	}
}

// The duplicate-delivery guard. Two channels, one succeeds and one fails: only
// the failed one is queued. A retry that re-fanned the whole notification would
// re-page everyone who already got it.
func TestIntegration_DeliveryRetry_OnlyTheFailedChannelIsQueued(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	mkChannelRule(t, db, tenantID, "in_app", `{}`)
	failedID := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)

	sendOne(t, svc, tenantID)

	if n := countInApp(t, db, tenantID); n != 1 {
		t.Fatalf("expected the healthy in_app channel to deliver once, got %d", n)
	}
	rows := queueRows(t, db, tenantID)
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 queued retry (the failed channel only), got %d", len(rows))
	}
	if rows[0].channelID != failedID {
		t.Errorf("queued channel_id = %s, want the FAILED channel %s — never the one that succeeded",
			rows[0].channelID, failedID)
	}
	if rows[0].channelType != "webhook" {
		t.Errorf("queued channel_type = %q, want webhook", rows[0].channelType)
	}
}

// The worker actually redelivers. A due row for a healthy channel is claimed,
// re-sent on THAT channel, and marked terminal-sent.
func TestIntegration_DeliveryRetry_WorkerRedeliversDueRow(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	ctx := context.Background()

	channelID := mkChannelRule(t, db, tenantID, "in_app", `{}`)
	notificationID := seedHistory(t, db, tenantID)
	seedQueueRow(t, db, tenantID, notificationID, channelID, "in_app", 0, time.Now().Add(-time.Minute))

	before := countInApp(t, db, tenantID)
	n, err := svc.RetryDueDeliveries(ctx)
	if err != nil {
		t.Fatalf("RetryDueDeliveries: %v", err)
	}
	if n != 1 {
		t.Fatalf("RetryDueDeliveries redelivered %d, want 1", n)
	}
	if got := countInApp(t, db, tenantID) - before; got != 1 {
		t.Fatalf("expected exactly 1 new in-app notification from the retry, got %d", got)
	}

	rows := queueRows(t, db, tenantID)
	if len(rows) != 1 {
		t.Fatalf("expected the row to persist as a record, got %d rows", len(rows))
	}
	r := rows[0]
	if r.status != "sent" {
		t.Errorf("status = %q, want sent", r.status)
	}
	if !r.deliveredAt.Valid {
		t.Error("delivered_at is NULL on a successful retry")
	}
	if r.nextRetryAt.Valid {
		t.Errorf("next_retry_at = %v, want NULL after success — a delivered row must never be re-claimed and sent twice", r.nextRetryAt)
	}
	if r.retryCount != 1 {
		t.Errorf("retry_count = %d, want 1", r.retryCount)
	}

	// Draining again must be a no-op: the row is terminal.
	if n2, err := svc.RetryDueDeliveries(ctx); err != nil || n2 != 0 {
		t.Errorf("second drain redelivered %d (err=%v), want 0 — a sent row must not be re-sent", n2, err)
	}
	if got := countInApp(t, db, tenantID) - before; got != 1 {
		t.Errorf("a second drain duplicated the delivery: %d in-app rows added", got)
	}
}

// A row that keeps failing backs off exponentially rather than hot-looping.
func TestIntegration_DeliveryRetry_ReschedulesWithBackoff(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	channelID := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	notificationID := seedHistory(t, db, tenantID)
	seedQueueRow(t, db, tenantID, notificationID, channelID, "webhook", 0, time.Now().Add(-time.Minute))

	if n, err := svc.RetryDueDeliveries(context.Background()); err != nil || n != 0 {
		t.Fatalf("RetryDueDeliveries = %d, %v; want 0 delivered (the channel is still down)", n, err)
	}

	rows := queueRows(t, db, tenantID)
	r := rows[0]
	if r.status != "retrying" {
		t.Fatalf("status = %q, want retrying (attempts remain)", r.status)
	}
	if r.retryCount != 1 {
		t.Errorf("retry_count = %d, want 1 after one failed attempt", r.retryCount)
	}
	// Attempt 2's backoff is 2m; assert it is scheduled meaningfully into the
	// future rather than immediately.
	if !r.nextRetryAt.Valid {
		t.Fatal("next_retry_at is NULL on a row that still has attempts left — it will never be retried again")
	}
	delay := time.Until(r.nextRetryAt.Time)
	if delay < 90*time.Second || delay > 3*time.Minute {
		t.Errorf("next attempt scheduled in %v, want ~2m (exponential backoff from 1m)", delay)
	}
	// And it must not be claimable right now.
	if n, _ := svc.RetryDueDeliveries(context.Background()); n != 0 {
		t.Errorf("a not-yet-due row was claimed: %d", n)
	}
	rows = queueRows(t, db, tenantID)
	if rows[0].retryCount != 1 {
		t.Errorf("a not-yet-due row was retried anyway: retry_count = %d", rows[0].retryCount)
	}
}

// The bound is real, and exhaustion leaves a durable terminal record naming the
// attempt count. A retry loop that silently gives up is the same defect we are
// closing.
func TestIntegration_DeliveryRetry_ExhaustsAndRecordsTerminalFailure(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	t.Setenv("NOTIFICATION_DELIVERY_MAX_ATTEMPTS", "3")

	channelID := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	notificationID := seedHistory(t, db, tenantID)
	// Already used 2 of 3 attempts; the next failure is terminal.
	seedQueueRow(t, db, tenantID, notificationID, channelID, "webhook", 2, time.Now().Add(-time.Minute))

	if _, err := svc.RetryDueDeliveries(context.Background()); err != nil {
		t.Fatalf("RetryDueDeliveries: %v", err)
	}

	r := queueRows(t, db, tenantID)[0]
	if r.status != "failed" {
		t.Errorf("status = %q, want failed after the attempt bound is reached", r.status)
	}
	if r.retryCount != 3 {
		t.Errorf("retry_count = %d, want 3", r.retryCount)
	}
	if r.nextRetryAt.Valid {
		t.Errorf("next_retry_at = %v, want NULL — an exhausted row must not be re-claimed forever", r.nextRetryAt)
	}
	if !r.errMessage.Valid || r.errMessage.String == "" {
		t.Fatal("exhausted delivery left no error_message — this is exactly the silent give-up being fixed")
	}
	if !strings.Contains(r.errMessage.String, "gave up after 3 attempt") {
		t.Errorf("error_message = %q, want it to name the attempt count", r.errMessage.String)
	}
	// And it stays terminal.
	if n, _ := svc.RetryDueDeliveries(context.Background()); n != 0 {
		t.Errorf("an exhausted row was picked up again: %d", n)
	}
}

// A row orphaned by a worker that died mid-attempt must come back, or the
// delivery is stranded in 'pending' forever.
func TestIntegration_DeliveryRetry_ReclaimsStaleClaims(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	channelID := mkChannelRule(t, db, tenantID, "in_app", `{}`)
	notificationID := seedHistory(t, db, tenantID)
	id := seedQueueRow(t, db, tenantID, notificationID, channelID, "in_app", 0, time.Now().Add(-time.Minute))
	// Simulate a crashed claim: in-flight, with its claim lease already expired.
	if _, err := db.Exec(`UPDATE notification_delivery_queue
		SET status='pending', next_retry_at = NOW() - interval '10 minutes' WHERE id = $1`, id); err != nil {
		t.Fatalf("simulate stale claim: %v", err)
	}

	n, err := svc.RetryDueDeliveries(context.Background())
	if err != nil {
		t.Fatalf("RetryDueDeliveries: %v", err)
	}
	if n != 1 {
		t.Fatalf("stale claim was not reclaimed and redelivered (got %d) — a pod restart mid-attempt would strand it forever", n)
	}
	if r := queueRows(t, db, tenantID)[0]; r.status != "sent" {
		t.Errorf("status = %q, want sent", r.status)
	}
}

// The kill-switch must actually switch off — both halves.
func TestIntegration_DeliveryRetry_KillSwitchDisablesEnqueueAndDrain(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	t.Setenv("NOTIFICATION_DELIVERY_RETRY_ENABLED", "false")

	channelID := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)

	if rows := queueRows(t, db, tenantID); len(rows) != 0 {
		t.Errorf("kill-switch off but %d row(s) were enqueued", len(rows))
	}

	// And an already-queued row is not drained either — no half-disabled state
	// where rows accumulate with nobody draining them.
	notificationID := seedHistory(t, db, tenantID)
	seedQueueRow(t, db, tenantID, notificationID, channelID, "webhook", 0, time.Now().Add(-time.Minute))
	if n, err := svc.RetryDueDeliveries(context.Background()); err != nil || n != 0 {
		t.Errorf("RetryDueDeliveries = %d, %v with the kill-switch off; want 0", n, err)
	}
	if r := queueRows(t, db, tenantID)[0]; r.retryCount != 0 || r.status != "retrying" {
		t.Errorf("a queued row was touched with the kill-switch off: status=%q retry_count=%d", r.status, r.retryCount)
	}
}

// --- fixtures ---------------------------------------------------------------

// seedHistory writes the notification_history row the queue's FK requires.
func seedHistory(t *testing.T, db *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO notification_history
			(id, tenant_id, notification_type, alert_source, alert_type, severity, message, channels_used, status, metadata)
		VALUES ($1,$2,'alert','compliance','control_noncompliant','high','TLS 1.0 in use','{}','failed','{}'::jsonb)`,
		id, tenantID); err != nil {
		t.Fatalf("seed notification_history: %v", err)
	}
	return id
}

func seedQueueRow(t *testing.T, db *sql.DB, tenantID, notificationID, channelID uuid.UUID,
	channelType string, retryCount int, nextRetryAt time.Time) uuid.UUID {
	t.Helper()
	payload, err := json.Marshal(models.SendNotificationRequest{
		TenantID:    &tenantID,
		AlertSource: "compliance",
		AlertType:   "control_noncompliant",
		Severity:    "high",
		Title:       "Control noncompliant: PCI-3.4",
		Message:     "TLS 1.0 is in use on 3 assets.",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO notification_delivery_queue
			(id, tenant_id, notification_id, channel_id, channel_type, payload, status, retry_count, next_retry_at)
		VALUES ($1,$2,$3,$4,$5,$6,'retrying',$7,$8)`,
		id, tenantID, notificationID, channelID, channelType, payload, retryCount, nextRetryAt); err != nil {
		t.Fatalf("seed notification_delivery_queue: %v", err)
	}
	return id
}
