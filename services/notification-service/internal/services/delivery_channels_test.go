package services

// Channel-level behaviour: webhook signing/idempotency, PagerDuty incident
// identity, Slack escaping, email content and the "not configured" outcome, the
// suspended-tenant gate. Receivers are real httptest servers, so every
// assertion is about the bytes a receiver would actually see.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/email"
	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
)

// captured is one request a test receiver saw.
type captured struct {
	header http.Header
	body   []byte
	user   string
	pass   string
}

type recorder struct {
	mu   sync.Mutex
	reqs []captured
}

func (r *recorder) handler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		u, p, _ := req.BasicAuth()
		r.mu.Lock()
		r.reqs = append(r.reqs, captured{header: req.Header.Clone(), body: b, user: u, pass: p})
		r.mu.Unlock()
		w.WriteHeader(status)
	}
}

func (r *recorder) all() []captured {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]captured(nil), r.reqs...)
}

// --- generic webhook --------------------------------------------------------

// A receiver following the documented recipe must be able to verify the
// signature: HMAC-SHA256(secret, timestamp + "." + body), hex, "sha256=" prefix.
func TestWebhook_SignatureVerifiesAsDocumented(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(200))
	defer srv.Close()
	ds := newTestDeliveryService()

	const secret = "whsec_test_only_not_a_real_secret"
	if err := ds.sendWebhook(map[string]interface{}{"url": srv.URL, "webhook_secret": secret}, testRequest()); err != nil {
		t.Fatalf("sendWebhook: %v", err)
	}
	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("receiver saw %d requests, want 1", len(got))
	}
	h := got[0].header

	// The receiver's verification, written independently of SignWebhook.
	ts := h.Get("X-Vista-Timestamp")
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		t.Fatalf("X-Vista-Timestamp = %q, want unix seconds", ts)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(got[0].body)))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig := h.Get("X-Vista-Signature"); sig != want {
		t.Errorf("X-Vista-Signature = %q, want %q", sig, want)
	}

	// Tampering with the body must break verification (the signature covers it).
	mac = hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(got[0].body) + " "))
	if h.Get("X-Vista-Signature") == "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Error("signature did not depend on the body")
	}

	if h.Get("X-Vista-Event-Id") == "" {
		t.Error("X-Vista-Event-Id missing")
	}
}

func TestWebhook_NoSecretMeansNoSignatureButStillAnEventID(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(200))
	defer srv.Close()
	ds := newTestDeliveryService()
	if err := ds.sendWebhook(map[string]interface{}{"url": srv.URL}, testRequest()); err != nil {
		t.Fatal(err)
	}
	h := rec.all()[0].header
	if h.Get("X-Vista-Signature") != "" {
		t.Error("an unsigned channel must not send a signature header")
	}
	if h.Get("X-Vista-Event-Id") == "" || h.Get("X-Vista-Timestamp") == "" {
		t.Errorf("event id / timestamp must always be sent: %v", h)
	}
}

// The idempotency key: identical across attempts at the SAME notification,
// different across notifications.
func TestWebhook_EventIDIsStableAcrossRetriesAndDistinctAcrossNotifications(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(200))
	defer srv.Close()
	ds := newTestDeliveryService()
	cfg := map[string]interface{}{"url": srv.URL}

	first := testRequest()
	// The retry queue serializes the request and a worker re-sends the decoded copy.
	if err := ds.sendWebhook(cfg, first); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(first)
	var replayed models.SendNotificationRequest
	if err := json.Unmarshal(payload, &replayed); err != nil {
		t.Fatal(err)
	}
	if err := ds.sendWebhook(cfg, &replayed); err != nil {
		t.Fatal(err)
	}
	other := testRequest()
	if err := ds.sendWebhook(cfg, other); err != nil {
		t.Fatal(err)
	}

	got := rec.all()
	a, b, c := got[0].header.Get("X-Vista-Event-Id"), got[1].header.Get("X-Vista-Event-Id"), got[2].header.Get("X-Vista-Event-Id")
	if a == "" || a != b {
		t.Errorf("event id changed across a retry: %q then %q", a, b)
	}
	if c == a {
		t.Errorf("two different notifications shared event id %q", a)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(got[0].body, &body)
	if body["event_id"] != a {
		t.Errorf("body event_id = %v, want the header value %q", body["event_id"], a)
	}
}

// SendToChannels assigns the id BEFORE the first send, so the failed-delivery
// retry row (which serializes req afterwards) carries it.
func TestSendToChannels_AssignsEventIDBeforeTheRetryPayloadIsBuilt(t *testing.T) {
	ds := newTestDeliveryService()
	req := testRequest()
	ch := &models.PlatformNotificationChannel{ID: uuid.New(), ChannelType: "carrier-pigeon", Enabled: true}
	if _, failures, _ := ds.SendToChannels(context.Background(), nil, nil, []interface{}{ch}, req); len(failures) != 1 {
		t.Fatalf("failures = %d, want 1", len(failures))
	}
	payload, _ := json.Marshal(req) // what enqueueFailedDelivery stores
	var back models.SendNotificationRequest
	_ = json.Unmarshal(payload, &back)
	if back.EventID == "" {
		t.Fatal("the serialized retry payload has no event_id")
	}
}

func TestWebhook_AuthAndCustomHeadersCannotOverrideTheSignature(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(200))
	defer srv.Close()
	ds := newTestDeliveryService()

	cfg := map[string]interface{}{
		"url":            srv.URL,
		"webhook_secret": "whsec_test_only",
		"auth":           map[string]interface{}{"type": "bearer", "token": "tok_test_only"},
		"headers":        map[string]interface{}{"X-Api-Key": "k_test_only", "X-Vista-Signature": "sha256=forged", "X-Vista-Event-Id": "forged"},
	}
	if err := ds.sendWebhook(cfg, testRequest()); err != nil {
		t.Fatal(err)
	}
	h := rec.all()[0].header
	if h.Get("Authorization") != "Bearer tok_test_only" {
		t.Errorf("Authorization = %q", h.Get("Authorization"))
	}
	if h.Get("X-Api-Key") != "k_test_only" {
		t.Errorf("custom header not sent: %v", h)
	}
	if h.Get("X-Vista-Signature") == "sha256=forged" || h.Get("X-Vista-Event-Id") == "forged" {
		t.Error("a custom header overwrote the signature/identity headers")
	}

	// Basic auth.
	rec2 := &recorder{}
	srv2 := httptest.NewServer(rec2.handler(200))
	defer srv2.Close()
	cfg2 := map[string]interface{}{"url": srv2.URL, "auth": map[string]interface{}{"type": "basic", "username": "svc", "password": "pw_test_only"}}
	if err := ds.sendWebhook(cfg2, testRequest()); err != nil {
		t.Fatal(err)
	}
	if r := rec2.all()[0]; r.user != "svc" || r.pass != "pw_test_only" {
		t.Errorf("basic auth = %q/%q", r.user, r.pass)
	}
}

func TestGenerateSigningSecret(t *testing.T) {
	a, b := GenerateSigningSecret(), GenerateSigningSecret()
	if a == b {
		t.Error("two generated secrets were equal")
	}
	if !strings.HasPrefix(a, "whsec_") || len(a) != len("whsec_")+64 {
		t.Errorf("secret %q is not whsec_ + 64 hex chars", a)
	}
}

// --- PagerDuty --------------------------------------------------------------

func pdEvent(t *testing.T, c captured) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(c.body, &m); err != nil {
		t.Fatalf("pagerduty body is not JSON: %v", err)
	}
	return m
}

func alertReq(transition string) *models.SendNotificationRequest {
	req := testRequest()
	req.Metadata = map[string]interface{}{"alert_id": "11111111-2222-3333-4444-555555555555", "alert_transition": transition}
	return req
}

// open, escalate and resolve of ONE alert must address ONE incident, and the
// auto-resolve notice must be a resolve — not another trigger.
func TestPagerDuty_OpenEscalateResolveShareADedupKeyAndResolveResolves(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(202))
	defer srv.Close()
	ds := newTestDeliveryService()
	ds.pagerDutyURL = srv.URL
	cfg := map[string]interface{}{"integration_key": "pd_routing_key_test_only"}

	for _, transition := range []string{"opened", "escalated", "resolved"} {
		if err := ds.sendPagerDuty(cfg, alertReq(transition)); err != nil {
			t.Fatalf("%s: %v", transition, err)
		}
	}
	got := rec.all()
	if len(got) != 3 {
		t.Fatalf("PagerDuty saw %d events, want 3", len(got))
	}
	wantKey := "vista-alert-11111111-2222-3333-4444-555555555555"
	for i, want := range []string{"trigger", "trigger", "resolve"} {
		ev := pdEvent(t, got[i])
		if ev["event_action"] != want {
			t.Errorf("event %d action = %v, want %s", i, ev["event_action"], want)
		}
		if ev["dedup_key"] != wantKey {
			t.Errorf("event %d dedup_key = %v, want %s", i, ev["dedup_key"], wantKey)
		}
		if ev["routing_key"] != "pd_routing_key_test_only" {
			t.Errorf("event %d routing_key = %v", i, ev["routing_key"])
		}
	}
	if _, has := pdEvent(t, got[2])["payload"]; has {
		t.Error("a resolve event carries no payload")
	}
	if _, has := pdEvent(t, got[0])["payload"]; !has {
		t.Error("a trigger event carries its payload")
	}
}

// A notification with no alert identity still gets a STABLE key, so a retried
// delivery cannot open a second incident.
func TestPagerDuty_NoAlertIDFallsBackToTheEventIDAndStaysStableAcrossRetries(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(202))
	defer srv.Close()
	ds := newTestDeliveryService()
	ds.pagerDutyURL = srv.URL
	cfg := map[string]interface{}{"integration_key": "pd_routing_key_test_only"}

	req := testRequest()
	req.EventID = "evt-123"
	for i := 0; i < 2; i++ { // the original attempt and a retry
		if err := ds.sendPagerDuty(cfg, req); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range rec.all() {
		if k := pdEvent(t, c)["dedup_key"]; k != "vista-event-evt-123" {
			t.Errorf("attempt %d dedup_key = %v, want vista-event-evt-123", i, k)
		}
	}
}

// Test must not leave an incident open: trigger, then resolve the SAME key.
func TestPagerDuty_TestTriggersThenResolvesTheSameThrowawayKey(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(202))
	defer srv.Close()
	ds := newTestDeliveryService()
	ds.pagerDutyURL = srv.URL

	tenant := uuid.New()
	ch := &models.TenantNotificationChannel{ID: uuid.New(), ChannelType: "pagerduty", Config: map[string]interface{}{"integration_key": "pd_routing_key_test_only"}}
	if err := ds.TestChannel(context.Background(), ch, &models.SendNotificationRequest{TenantID: &tenant}); err != nil {
		t.Fatalf("TestChannel: %v", err)
	}
	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("PagerDuty saw %d events, want trigger + resolve", len(got))
	}
	first, second := pdEvent(t, got[0]), pdEvent(t, got[1])
	if first["event_action"] != "trigger" || second["event_action"] != "resolve" {
		t.Errorf("actions = %v, %v; want trigger then resolve", first["event_action"], second["event_action"])
	}
	key, _ := first["dedup_key"].(string)
	if !strings.HasPrefix(key, "vista-test-") || second["dedup_key"] != key {
		t.Errorf("dedup keys = %v / %v; the resolve must reuse the test's throwaway key", first["dedup_key"], second["dedup_key"])
	}
}

func TestPagerDuty_TestFailureModes(t *testing.T) {
	tenant := uuid.New()
	ch := &models.TenantNotificationChannel{ID: uuid.New(), ChannelType: "pagerduty", Config: map[string]interface{}{"integration_key": "pd_routing_key_test_only"}}

	t.Run("trigger rejected: no resolve is attempted", func(t *testing.T) {
		rec := &recorder{}
		srv := httptest.NewServer(rec.handler(400))
		defer srv.Close()
		ds := newTestDeliveryService()
		ds.pagerDutyURL = srv.URL
		err := ds.TestChannel(context.Background(), ch, &models.SendNotificationRequest{TenantID: &tenant})
		var failed *ChannelTestError
		if !errors.As(err, &failed) || !strings.Contains(failed.Reason, "400") {
			t.Fatalf("err = %v, want a ChannelTestError naming HTTP 400", err)
		}
		if n := len(rec.all()); n != 1 {
			t.Errorf("PagerDuty saw %d events, want exactly the rejected trigger", n)
		}
	})

	t.Run("resolve fails: says the test incident may be open", func(t *testing.T) {
		var mu sync.Mutex
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			calls++
			n := calls
			mu.Unlock()
			if n == 1 {
				w.WriteHeader(202)
				return
			}
			w.WriteHeader(400)
		}))
		defer srv.Close()
		ds := newTestDeliveryService()
		ds.pagerDutyURL = srv.URL
		err := ds.TestChannel(context.Background(), ch, &models.SendNotificationRequest{TenantID: &tenant})
		var failed *ChannelTestError
		if !errors.As(err, &failed) || !strings.Contains(failed.Reason, "resolve") {
			t.Fatalf("err = %v, want a reason telling the tenant to resolve the test incident", err)
		}
	})
}

// --- Slack ------------------------------------------------------------------

func TestSlack_EscapesAmpersandAndAngleBracketsEverywhere(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(200))
	defer srv.Close()
	ds := newTestDeliveryService()

	req := &models.SendNotificationRequest{
		AlertSource: "a&b<src>", AlertType: "type<!here>", Severity: "high",
		Message:  "Subject <!channel> & <https://evil.example.test|click> done",
		Metadata: map[string]interface{}{"host": "a<b>&c"},
	}
	if err := ds.sendSlack(map[string]interface{}{"webhook_url": srv.URL}, req); err != nil {
		t.Fatal(err)
	}
	raw := string(rec.all()[0].body)
	// json.Marshal writes < > & as \u003c \u003e \u0026; decode, then compare the real text.
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	var texts []string
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch t := v.(type) {
		case string:
			texts = append(texts, t)
		case []interface{}:
			for _, e := range t {
				walk(e)
			}
		case map[string]interface{}:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(payload)
	all := strings.Join(texts, "\n")
	for _, bad := range []string{"<!channel>", "<!here>", "<https://", "<src>", "a<b>"} {
		if strings.Contains(all, bad) {
			t.Errorf("Slack payload contains unescaped %q:\n%s", bad, all)
		}
	}
	for _, good := range []string{"&lt;!channel&gt;", "&lt;!here&gt;", "a&amp;b&lt;src&gt;", "a&lt;b&gt;&amp;c"} {
		if !strings.Contains(all, good) {
			t.Errorf("Slack payload is missing the escaped form %q:\n%s", good, all)
		}
	}
	if strings.Contains(all, "&amp;amp;") {
		t.Error("double-escaped")
	}
}

// --- email ------------------------------------------------------------------

func TestEmail_NotConfiguredIsPermanentWithAClearReason_NeverAnSMTPAttempt(t *testing.T) {
	ds := newTestDeliveryService() // emailConfigFn → ErrNotConfigured
	err := ds.sendEmail(nil, map[string]interface{}{"recipients": []interface{}{"ops@example.test"}}, testRequest())
	if err == nil {
		t.Fatal("expected a failure")
	}
	if !IsPermanentDeliveryFailure(err) {
		t.Error("not-configured must be PERMANENT so it is never retried")
	}
	if got := SafeFailureReason(err); got != reasonEmailNotConfigured {
		t.Errorf("reason = %q, want %q", got, reasonEmailNotConfigured)
	}
}

// Even a role-recipient channel (the seeded default shape, no static address)
// reports "not configured" rather than reaching the recipient lookup.
func TestEmail_NotConfiguredIsDecidedBeforeRecipientResolution(t *testing.T) {
	ds := newTestDeliveryService() // db is nil: reaching resolveRoleRecipients would panic
	err := ds.sendEmail(nil, map[string]interface{}{"recipient_role": "platform_admin"}, testRequest())
	if got := SafeFailureReason(err); got != reasonEmailNotConfigured {
		t.Errorf("reason = %q (err %v), want the not-configured sentence", got, err)
	}
}

// A tenant's own SMTP override can only be honoured if the tenant id reaches the
// resolver; a platform channel must resolve with no tenant.
func TestEmail_ResolvesTheConfigForTheChannelsOwner(t *testing.T) {
	var got []*uuid.UUID
	ds := newTestDeliveryService()
	ds.emailConfigFn = func(id *uuid.UUID) (*email.EmailConfig, error) {
		got = append(got, id)
		return nil, email.ErrNotConfigured
	}
	cfg := map[string]interface{}{"recipients": []interface{}{"ops@example.test"}}
	tenant := uuid.New()
	_ = ds.sendEmail(&tenant, cfg, testRequest())
	_ = ds.sendEmail(nil, cfg, testRequest())
	if len(got) != 2 || got[0] == nil || *got[0] != tenant || got[1] != nil {
		t.Fatalf("resolver saw tenant ids %v, want [%s, nil]", got, tenant)
	}
}

// A lookup FAILURE is not "not configured" — it may clear, so it stays transient.
func TestEmail_ResolverErrorStaysTransient(t *testing.T) {
	ds := newTestDeliveryService()
	ds.emailConfigFn = func(*uuid.UUID) (*email.EmailConfig, error) { return nil, errors.New("connection reset by peer") }
	err := ds.sendEmail(nil, map[string]interface{}{"recipients": []interface{}{"ops@example.test"}}, testRequest())
	if err == nil || IsPermanentDeliveryFailure(err) {
		t.Fatalf("err = %v; a resolver outage must be a transient failure", err)
	}
}

func TestComposeEmail_SubjectUsesTheTitleAndBodyIsReadable(t *testing.T) {
	req := testRequest()
	req.Metadata = map[string]interface{}{
		"alert_id":  "abc-123",
		"asset_ids": []interface{}{"a1", "a2"},
		"scope":     map[string]interface{}{"env": "prod"},
		"empty":     "",
		"count":     float64(3),
	}
	subject, body := composeEmail(req)
	if subject != "[high] Control noncompliant: PCI-3.4" {
		t.Errorf("subject = %q", subject)
	}
	if strings.Contains(subject, "control_noncompliant") {
		t.Error("subject still carries the raw alert_type")
	}
	if strings.Contains(body, "{\n") || strings.Contains(body, "\"alert_id\"") {
		t.Errorf("body still dumps raw JSON:\n%s", body)
	}
	for _, want := range []string{"Control PCI-3.4 is noncompliant.", "Source: compliance-engine", "Severity: high", "Alert id: abc-123", "Asset ids: a1, a2", "Count: 3", `Scope: {"env":"prod"}`} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Empty:") {
		t.Errorf("empty values must be skipped:\n%s", body)
	}

	// No title: the humanized alert_type, never the machine-cased one.
	req.Title = ""
	if subject, _ := composeEmail(req); subject != "[high] Control noncompliant" {
		t.Errorf("no-title subject = %q", subject)
	}
}

// --- suspended / canceled / deleted tenants ---------------------------------

func TestTenantBlocked_UsesTheSharedPredicate(t *testing.T) {
	id := uuid.New()
	for _, tc := range []struct {
		name  string
		state tenantstate.State
		err   error
		want  bool
	}{
		{"active", tenantstate.State{Found: true, PaymentStatus: "active"}, nil, false},
		{"trial", tenantstate.State{Found: true, PaymentStatus: "trial"}, nil, false},
		{"past_due stays live", tenantstate.State{Found: true, PaymentStatus: "past_due"}, nil, false},
		{"suspended", tenantstate.State{Found: true, PaymentStatus: "suspended"}, nil, true},
		{"canceled", tenantstate.State{Found: true, PaymentStatus: "canceled"}, nil, true},
		{"soft-deleted", tenantstate.State{Found: true, PaymentStatus: "active", Deleted: true}, nil, true},
		{"purged", tenantstate.State{Found: false}, nil, true},
		{"lookup failure delivers (notifying is not access)", tenantstate.State{}, errors.New("db down"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &NotificationService{tenantStateLookup: func(context.Context, uuid.UUID) (tenantstate.State, error) { return tc.state, tc.err }}
			if got := s.tenantBlocked(context.Background(), &id); got != tc.want {
				t.Errorf("tenantBlocked = %t, want %t", got, tc.want)
			}
		})
	}
	s := &NotificationService{tenantStateLookup: func(context.Context, uuid.UUID) (tenantstate.State, error) {
		return tenantstate.State{Found: true, PaymentStatus: "suspended"}, nil
	}}
	if s.tenantBlocked(context.Background(), nil) {
		t.Error("a platform notification (nil tenant) is never blocked")
	}
}

// The wiring: SendNotification must stop before it touches the database (this
// service has a nil db — reaching the maintenance check or the rule lookup would
// panic) when the tenant is suspended. Deleting the gate line fails this test.
func TestSendNotification_SuspendedTenantIsDroppedBeforeAnyWork(t *testing.T) {
	looked := 0
	s := &NotificationService{
		logger: newTestDeliveryService().logger,
		tenantStateLookup: func(context.Context, uuid.UUID) (tenantstate.State, error) {
			looked++
			return tenantstate.State{Found: true, PaymentStatus: "suspended"}, nil
		},
	}
	tenant := uuid.New()
	req := testRequest()
	req.TenantID = &tenant
	if err := s.SendNotification(context.Background(), req); err != nil {
		t.Fatalf("SendNotification = %v, want nil (a dropped notification is not an error)", err)
	}
	if looked != 1 {
		t.Errorf("tenant state looked up %d times, want 1", looked)
	}
}
