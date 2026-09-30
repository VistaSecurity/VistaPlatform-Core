package services

// notification_history.status must tell the truth about a fan-out.
//
// SendToChannels only errors when EVERY channel fails, and SendNotification keyed
// the history status off that error — so a notification whose webhook failed
// while its in-app copy landed was recorded, and rendered, as a plain "sent".
// And the retry worker finished queue rows without ever touching the history
// row, so a retry that finally worked (or was abandoned) changed nothing the
// tenant could see.
//
// Each test reads the history row from the database, not from a return value.
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type historyRow struct {
	id       uuid.UUID
	status   string
	channels []string
	meta     map[string]interface{}
	rawMeta  string
}

// onlyHistory returns the tenant's single notification_history row.
func onlyHistory(t *testing.T, db *sql.DB, tenantID uuid.UUID) historyRow {
	t.Helper()
	rows, err := db.Query(`SELECT id, status, channels_used, metadata::text FROM notification_history WHERE tenant_id = $1`, tenantID)
	if err != nil {
		t.Fatalf("read notification_history: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []historyRow
	for rows.Next() {
		var h historyRow
		var used pq.StringArray
		if err := rows.Scan(&h.id, &h.status, &used, &h.rawMeta); err != nil {
			t.Fatalf("scan history: %v", err)
		}
		h.channels = used
		if err := json.Unmarshal([]byte(h.rawMeta), &h.meta); err != nil {
			t.Fatalf("history metadata is not an object: %v (%s)", err, h.rawMeta)
		}
		out = append(out, h)
	}
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 history row, got %d", len(out))
	}
	return out[0]
}

// resultFor finds a channel's entry in metadata.channel_results.
func (h historyRow) resultFor(t *testing.T, channelID uuid.UUID) map[string]interface{} {
	t.Helper()
	results, _ := h.meta["channel_results"].([]interface{})
	for _, r := range results {
		if m, ok := r.(map[string]interface{}); ok && m["channel_id"] == channelID.String() {
			return m
		}
	}
	t.Fatalf("no channel_results entry for %s in %s", channelID, h.rawMeta)
	return nil
}

// mkChannelRuleN is mkChannelRule for tests that need several channels of one
// type (channel names are unique per tenant).
func mkChannelRuleN(t *testing.T, db *sql.DB, tenantID uuid.UUID, n, channelType, cfg string) uuid.UUID {
	t.Helper()
	channelID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_channels (id, tenant_id, channel_name, channel_type, config, enabled)
		VALUES ($1, $2, $3, $4, $5::jsonb, true)`,
		channelID, tenantID, channelType+" channel "+n, channelType, cfg); err != nil {
		t.Fatalf("insert %s channel: %v", channelType, err)
	}
	if _, err := db.Exec(`
		INSERT INTO tenant_notification_rules
			(tenant_id, rule_name, alert_source, channel_ids, severity_filter, frequency, enabled, priority)
		VALUES ($1, $2, 'all', ARRAY[$3::uuid], '{critical,high,medium,low,info}'::varchar[], 'immediate', true, 100)`,
		tenantID, channelType+" rule "+n, channelID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	return channelID
}

func makeQueueDue(t *testing.T, db *sql.DB, tenantID uuid.UUID) {
	t.Helper()
	if _, err := db.Exec(`UPDATE notification_delivery_queue SET next_retry_at = NOW() - interval '1 minute'
		WHERE tenant_id = $1 AND status = 'retrying'`, tenantID); err != nil {
		t.Fatalf("make queue due: %v", err)
	}
}

func TestIntegration_History_AllChannelsSucceedIsSent(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	a := mkChannelRuleN(t, db, tenantID, "a", "in_app", `{}`)
	b := mkChannelRuleN(t, db, tenantID, "b", "in_app", `{}`)
	sendOne(t, svc, tenantID)

	h := onlyHistory(t, db, tenantID)
	if h.status != "sent" {
		t.Fatalf("status = %q, want sent when every channel delivered", h.status)
	}
	if len(h.channels) != 2 {
		t.Errorf("channels_used = %v, want both channels", h.channels)
	}
	for _, id := range []uuid.UUID{a, b} {
		if r := h.resultFor(t, id); r["status"] != "sent" {
			t.Errorf("channel %s result = %v, want sent", id, r)
		}
	}
}

// The core claim. Pre-fix this row said "sent".
func TestIntegration_History_OneOfTwoFailingIsNotPlainSuccess(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	good := mkChannelRule(t, db, tenantID, "in_app", `{}`)
	bad := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	if err := svc.SendNotification(context.Background(), &models.SendNotificationRequest{
		TenantID: &tenantID, AlertSource: "compliance", AlertType: "control_noncompliant",
		Severity: "high", Title: "t", Message: "m",
		Metadata: map[string]interface{}{"asset": "web-1"},
	}); err != nil {
		t.Fatalf("SendNotification: %v", err)
	}

	h := onlyHistory(t, db, tenantID)
	if h.status != "partial" {
		t.Fatalf("status = %q, want partial: the webhook failed even though in_app delivered", h.status)
	}
	if len(h.channels) != 1 || h.channels[0] != "in_app" {
		t.Errorf("channels_used = %v, want only the channel that delivered", h.channels)
	}
	if r := h.resultFor(t, good); r["status"] != "sent" {
		t.Errorf("in_app result = %v, want sent", r)
	}
	if r := h.resultFor(t, bad); r["status"] != "retrying" {
		t.Errorf("webhook result = %v, want retrying (transient failure, retry queued)", r)
	}
	// Error text can embed the request URL (a credential): it must not be copied.
	if strings.Contains(h.rawMeta, "webhook.invalid") {
		t.Errorf("history metadata copied delivery-error text: %s", h.rawMeta)
	}
	if h.meta["asset"] != "web-1" {
		t.Errorf("the notification's own metadata was lost: %s", h.rawMeta)
	}

	// The annotation must not leak into what a retry re-sends: history.Metadata
	// used to alias the request's metadata.
	var payload struct {
		Metadata map[string]interface{} `json:"metadata"`
	}
	if err := json.Unmarshal(queueRows(t, db, tenantID)[0].payload, &payload); err != nil {
		t.Fatal(err)
	}
	if _, leaked := payload.Metadata["channel_results"]; leaked {
		t.Errorf("channel_results leaked into the retry payload: %v", payload.Metadata)
	}
}

func TestIntegration_History_EveryChannelFailingIsFailed(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)

	if h := onlyHistory(t, db, tenantID); h.status != "failed" || len(h.channels) != 0 {
		t.Fatalf("status=%q channels_used=%v, want failed with none delivered", h.status, h.channels)
	}
}

func TestIntegration_History_PermanentFailureIsRecordedNotRetrying(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	mkChannelRule(t, db, tenantID, "in_app", `{}`)
	bad := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+blockedWebhook+`"}`)
	sendOne(t, svc, tenantID)

	h := onlyHistory(t, db, tenantID)
	if h.status != "partial" {
		t.Fatalf("status = %q, want partial", h.status)
	}
	if r := h.resultFor(t, bad); r["status"] != "failed" {
		t.Errorf("SSRF-rejected webhook result = %v, want failed (it will never be retried)", r)
	}
}

// A retry that finally works must change what the tenant sees.
func TestIntegration_History_RetrySuccessUpdatesTheRow(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	mkChannelRule(t, db, tenantID, "in_app", `{}`)
	flaky := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)
	if h := onlyHistory(t, db, tenantID); h.status != "partial" {
		t.Fatalf("precondition: status = %q, want partial", h.status)
	}

	// The destination comes back: same channel row, now deliverable.
	if _, err := db.Exec(`UPDATE tenant_notification_channels SET channel_type='in_app', config='{}'::jsonb WHERE id=$1`, flaky); err != nil {
		t.Fatal(err)
	}
	makeQueueDue(t, db, tenantID)
	if n, err := svc.RetryDueDeliveries(context.Background()); err != nil || n != 1 {
		t.Fatalf("RetryDueDeliveries = %d, %v; want 1 delivered", n, err)
	}

	h := onlyHistory(t, db, tenantID)
	if h.status != "sent" {
		t.Fatalf("status = %q after the retry delivered, want sent — the history row was left frozen at its first-attempt status", h.status)
	}
	if len(h.channels) != 2 {
		t.Errorf("channels_used = %v, want both channels after the retry", h.channels)
	}
	if r := h.resultFor(t, flaky); r["status"] != "sent" {
		t.Errorf("recovered channel result = %v, want sent", r)
	}
}

// Sole channel failed -> "failed"; its retry lands -> "sent".
func TestIntegration_History_RetrySuccessOnASoleChannelFlipsFailedToSent(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	only := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)
	if h := onlyHistory(t, db, tenantID); h.status != "failed" {
		t.Fatalf("precondition: status = %q, want failed", h.status)
	}
	if _, err := db.Exec(`UPDATE tenant_notification_channels SET channel_type='in_app', config='{}'::jsonb WHERE id=$1`, only); err != nil {
		t.Fatal(err)
	}
	makeQueueDue(t, db, tenantID)
	if _, err := svc.RetryDueDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := onlyHistory(t, db, tenantID); h.status != "sent" || len(h.channels) != 1 {
		t.Fatalf("status=%q channels_used=%v, want sent with the recovered channel", h.status, h.channels)
	}
}

// Exhaustion is recorded on the history row too — and does not upgrade it.
func TestIntegration_History_RetryExhaustionIsRecorded(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)
	t.Setenv("NOTIFICATION_DELIVERY_MAX_ATTEMPTS", "1")

	mkChannelRule(t, db, tenantID, "in_app", `{}`)
	bad := mkChannelRule(t, db, tenantID, "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)

	makeQueueDue(t, db, tenantID)
	if n, err := svc.RetryDueDeliveries(context.Background()); err != nil || n != 0 {
		t.Fatalf("RetryDueDeliveries = %d, %v; want 0 delivered", n, err)
	}
	if r := queueRows(t, db, tenantID)[0]; r.status != "failed" {
		t.Fatalf("queue row = %q, want failed (exhausted)", r.status)
	}

	h := onlyHistory(t, db, tenantID)
	if h.status != "partial" {
		t.Errorf("status = %q, want partial: one channel delivered and one was abandoned", h.status)
	}
	r := h.resultFor(t, bad)
	if r["status"] != "failed" || r["retries_exhausted"] != true {
		t.Errorf("abandoned channel result = %v, want failed + retries_exhausted (it was still 'retrying' before)", r)
	}
	if _, ok := h.meta["last_retry_at"]; !ok {
		t.Errorf("history does not record when the last retry happened: %s", h.rawMeta)
	}
}

// Two retries of the same notification finishing one after the other must
// converge on the queue's state, not on whichever finished last.
func TestIntegration_History_TwoRetriesConvergeOnQueueState(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	svc := itNotificationService(t, db)

	a := mkChannelRuleN(t, db, tenantID, "a", "webhook", `{"url":"`+unreachableWebhook+`"}`)
	b := mkChannelRuleN(t, db, tenantID, "b", "webhook", `{"url":"`+unreachableWebhook+`"}`)
	sendOne(t, svc, tenantID)
	if h := onlyHistory(t, db, tenantID); h.status != "failed" {
		t.Fatalf("precondition: status = %q, want failed", h.status)
	}

	// Only channel a recovers; b stays down.
	if _, err := db.Exec(`UPDATE tenant_notification_channels SET channel_type='in_app', config='{}'::jsonb WHERE id=$1`, a); err != nil {
		t.Fatal(err)
	}
	makeQueueDue(t, db, tenantID)
	if _, err := svc.RetryDueDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}

	h := onlyHistory(t, db, tenantID)
	if h.status != "partial" {
		t.Fatalf("status = %q, want partial: a recovered, b is still failing", h.status)
	}
	if r := h.resultFor(t, a); r["status"] != "sent" {
		t.Errorf("a = %v, want sent", r)
	}
	if r := h.resultFor(t, b); r["status"] != "retrying" {
		t.Errorf("b = %v, want still retrying", r)
	}
}
