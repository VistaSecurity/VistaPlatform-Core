package api

// HTTP-surface behaviour for the notification-channel fixes:
//
//   - Test answers a channel that did not deliver with a structured 422 and a
//     sanitized reason (not the generic 500 that made every failure read "Test
//     failed"), and never echoes the channel's URL / token / headers.
//   - Creating a generic webhook returns a server-generated signing secret ONCE.
//   - Platform channel reads are masked like tenant reads.
//   - GET /tenant/delivery-status reports whether email can deliver.
//
// The handlers are the real gin handlers over in-memory stubs, and responses are
// checked against the OpenAPI schemas (ADR-0001).

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/config"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const (
	leakedToken = "xoxb-SECRET-TOKEN-123456"
	leakedHost  = "hooks.example.test"
)

// failedTest builds what the delivery layer returns for a failed Test: a
// ChannelTestError whose WRAPPED error is a raw transport error carrying the
// URL — the exact thing that must not reach the response.
func failedTest(reason string, permanent bool) error {
	raw := fmt.Errorf(`Post "https://%s/services/%s?apikey=SUPERSECRETKEY": dial tcp 10.0.0.9:443: connect: refused`, leakedHost, leakedToken)
	return &services.ChannelTestError{Reason: reason, Permanent: permanent, Err: raw}
}

func assertNoLeak(t *testing.T, body string) {
	t.Helper()
	for _, leak := range []string{leakedToken, leakedHost, "SUPERSECRETKEY", "dial tcp", "10.0.0.9"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks %q: %s", leak, body)
		}
	}
}

func TestTestTenantChannel_FailureIsAStructured422WithASafeReason(t *testing.T) {
	sv := ncLoadSpec(t)
	const reason = "The receiving service says the endpoint does not exist (HTTP 404) — check the URL or key."
	eng := ncEngine(&stubChannelManager{testErr: failedTest(reason, true)}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/channels/"+ncAID+"/test", nil)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ChannelTestFailure", w.Body.Bytes())
	body := w.Body.String()
	if !strings.Contains(body, reason) {
		t.Errorf("body should carry the reason %q: %s", reason, body)
	}
	if !strings.Contains(body, `"status":"test_failed"`) || !strings.Contains(body, `"permanent":true`) {
		t.Errorf("body should be structured: %s", body)
	}
	assertNoLeak(t, body)
}

func TestTestPlatformChannel_FailureIsAStructured422WithASafeReason(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncPlatformEngine(&stubChannelManager{platTestErr: failedTest("Email delivery isn't configured by the platform operator.", true)}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/platform/channels/"+ncAID+"/test", nil)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ChannelTestFailure", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), "Email delivery isn't configured by the platform operator.") {
		t.Errorf("reason missing: %s", w.Body.String())
	}
	assertNoLeak(t, w.Body.String())
}

// The two things that must NOT become a 422: a bug (500, no detail), and a
// missing channel (404).
func TestTestChannel_NonDeliveryErrorsKeepTheirStatus(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{testErr: errors.New("pq: connection refused " + leakedToken)}, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/channels/"+ncAID+"/test", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	assertNoLeak(t, w.Body.String())

	eng = ncEngine(&stubChannelManager{testErr: fmt.Errorf("get: %w", services.ErrChannelNotFound)}, &stubRuleEngine{})
	w = ncDo(eng, http.MethodPost, ncBase+"/tenant/channels/"+ncAID+"/test", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

// --- webhook signing secret --------------------------------------------------

func createBody(channelType, cfg string) string {
	return fmt.Sprintf(`{"channel_name":"hook","channel_type":%q,"config":%s,"enabled":true}`, channelType, cfg)
}

func TestCreateWebhookChannel_GeneratesASigningSecretAndReturnsItOnce(t *testing.T) {
	sv := ncLoadSpec(t)
	ch := sampleChannel()
	stub := &stubChannelManager{created: &ch, echoRequest: true}
	eng := ncEngine(stub, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/channels", strings.NewReader(createBody("webhook", `{"url":"https://hooks.example.test/in"}`)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantNotificationChannel", w.Body.Bytes())

	// What the manager was asked to store carries the secret (so it is encrypted
	// at rest through NotificationChannelPolicy) ...
	stored, _ := stub.lastCreate.Config["webhook_secret"].(string)
	if !strings.HasPrefix(stored, "whsec_") {
		t.Fatalf("stored config has no generated webhook_secret: %v", stub.lastCreate.Config)
	}
	// ... the response shows it in the clear exactly once, at the top level ...
	if !strings.Contains(w.Body.String(), `"signing_secret":"`+stored+`"`) {
		t.Errorf("response should return the generated secret once: %s", w.Body.String())
	}
	// ... and the config in that same response is MASKED, not the secret again.
	if strings.Count(w.Body.String(), stored) != 1 {
		t.Errorf("the secret appears %d times in the response, want exactly once (config must be masked): %s",
			strings.Count(w.Body.String(), stored), w.Body.String())
	}
	if !strings.Contains(w.Body.String(), services.SecretMask) {
		t.Errorf("config.webhook_secret should be masked: %s", w.Body.String())
	}
}

func TestCreateWebhookChannel_ACallerSuppliedSecretIsNotOverwrittenOrEchoed(t *testing.T) {
	ch := sampleChannel()
	stub := &stubChannelManager{created: &ch, echoRequest: true}
	eng := ncEngine(stub, &stubRuleEngine{})
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/channels",
		strings.NewReader(createBody("webhook", `{"url":"https://hooks.example.test/in","webhook_secret":"my-own-secret-value"}`)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if got := stub.lastCreate.Config["webhook_secret"]; got != "my-own-secret-value" {
		t.Errorf("stored webhook_secret = %v, want the caller's", got)
	}
	if strings.Contains(w.Body.String(), "signing_secret") || strings.Contains(w.Body.String(), "my-own-secret-value") {
		t.Errorf("the caller already knows their secret; it must not be echoed: %s", w.Body.String())
	}
}

func TestCreateNonWebhookChannel_GetsNoSigningSecret(t *testing.T) {
	for _, typ := range []string{"slack", "email", "pagerduty"} {
		t.Run(typ, func(t *testing.T) {
			ch := sampleChannel()
			stub := &stubChannelManager{created: &ch, echoRequest: true}
			eng := ncEngine(stub, &stubRuleEngine{})
			w := ncDo(eng, http.MethodPost, ncBase+"/tenant/channels", strings.NewReader(createBody(typ, `{"webhook_url":"https://hooks.example.test/x"}`)))
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
			}
			if _, has := stub.lastCreate.Config["webhook_secret"]; has {
				t.Error("a signing secret was added to a non-webhook channel")
			}
			if strings.Contains(w.Body.String(), "signing_secret") {
				t.Errorf("unexpected signing_secret: %s", w.Body.String())
			}
		})
	}
}

// --- platform channels are masked -------------------------------------------

func platformChannelWithSecrets() models.PlatformNotificationChannel {
	now := time.Now().UTC()
	return models.PlatformNotificationChannel{
		ID: uuid.New(), ChannelName: "ops", ChannelType: "webhook", Enabled: true, CreatedAt: now, UpdatedAt: now,
		Config: map[string]interface{}{
			"url":            "https://hooks.example.test/T0/" + leakedToken,
			"webhook_secret": "whsec_platform_secret_value",
			"auth":           map[string]interface{}{"type": "bearer", "token": "bearer-token-value-1234"},
			"headers":        map[string]interface{}{"X-Api-Key": "header-secret-value"},
		},
	}
}

func TestPlatformChannels_EveryResponseIsMasked(t *testing.T) {
	ch := platformChannelWithSecrets()
	stub := &stubChannelManager{platList: []models.PlatformNotificationChannel{ch}, platGet: &ch, platCreated: &ch, platUpdated: &ch}
	eng := ncPlatformEngine(stub, &stubRuleEngine{})

	cases := []struct {
		name, method, path, body string
	}{
		{"list", http.MethodGet, "/platform/channels", ""},
		{"get", http.MethodGet, "/platform/channels/" + ncAID, ""},
		{"create", http.MethodPost, "/platform/channels", createBody("webhook", `{"url":"https://hooks.example.test/x"}`)},
		{"update", http.MethodPut, "/platform/channels/" + ncAID, `{"enabled":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			w := ncDo(eng, tc.method, ncBase+tc.path, body)
			if w.Code >= 300 {
				t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
			}
			out := w.Body.String()
			for _, secret := range []string{leakedToken, "whsec_platform_secret_value", "bearer-token-value-1234", "header-secret-value"} {
				if strings.Contains(out, secret) {
					t.Errorf("platform response leaks %q: %s", secret, out)
				}
			}
			if !strings.Contains(out, services.SecretMask) {
				t.Errorf("platform response should carry masked credentials: %s", out)
			}
		})
	}
	// The stub's own copy is untouched (masking must copy, not mutate).
	if ch.Config["webhook_secret"] != "whsec_platform_secret_value" {
		t.Error("masking mutated the source channel")
	}
}

// --- delivery status ---------------------------------------------------------

type stubEmailStatus struct {
	configured bool
	err        error
}

func (s stubEmailStatus) EmailDeliveryConfigured(uuid.UUID) (bool, error) { return s.configured, s.err }

func deliveryStatusEngine(e emailStatusIface) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithEmailStatus(e)
	r := gin.New()
	grp := r.Group(ncBase)
	grp.Use(func(c *gin.Context) { c.Set("tenantID", ncTenant.String()); c.Next() })
	grp.GET("/tenant/delivery-status", srv.getTenantDeliveryStatus)
	return r
}

// The REAL router (Server.SetupRouter — the one main() mounts): the new route
// exists, and carries the same settings.read bar as the channel list it
// annotates. Deleting the route line, or its gate, turns this red.
func TestRealRouter_DeliveryStatusIsMountedAndGatedOnSettingsRead(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	path := "/api/v1/notification-service/tenant/delivery-status"

	pdb := &permDB{granted: map[string]bool{}}
	router := withEmailStatus(t, pdb, stubEmailStatus{configured: false})
	w := gateGET(t, router, tenant, user, path)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "settings.read") {
		t.Fatalf("without settings.read: status %d body %s, want 403 naming settings.read", w.Code, w.Body.String())
	}

	pdb.granted["settings.read"] = true
	w = gateGET(t, router, tenant, user, path)
	if w.Code != http.StatusOK || w.Body.String() != `{"email":{"configured":false}}` {
		t.Fatalf("with settings.read: status %d body %s, want 200 {email:{configured:false}}", w.Code, w.Body.String())
	}
}

// withEmailStatus rebuilds gateRouter's server with an email-status surface.
func withEmailStatus(t *testing.T, pdb *permDB, e emailStatusIface) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("DATABASE_URL", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	raw := sql.OpenDB(pdb)
	t.Cleanup(func() { _ = raw.Close() })
	srv := &Server{
		config:         &config.Config{JWTSecret: gateTestSecret},
		db:             sqlx.NewDb(raw, "postgres"),
		channelManager: &stubChannelManager{},
		emailStatus:    e,
	}
	return srv.SetupRouter()
}

// Test through the real router: a failed channel is a 422 with the reason, and
// the route stays behind settings.update.
func TestRealRouter_ChannelTestFailureIs422WithReasonAndGatedOnSettingsUpdate(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	id := uuid.New().String()
	path := "/api/v1/notification-service/tenant/channels/" + id + "/test"
	const reason = "The destination did not respond in time."
	post := func(router *gin.Engine) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+testdb.SignTenantToken(t, gateTestSecret, user, tenant, "viewer"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	router, _ := gateRouter(t, map[string]bool{}, &stubChannelManager{testErr: failedTest(reason, false)})
	if w := post(router); w.Code != http.StatusForbidden {
		t.Fatalf("without settings.update: status %d, want 403; body=%s", w.Code, w.Body.String())
	}

	router, _ = gateRouter(t, map[string]bool{"settings.update": true}, &stubChannelManager{testErr: failedTest(reason, false)})
	w := post(router)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), reason) {
		t.Fatalf("with settings.update: status %d body %s, want 422 carrying the reason", w.Code, w.Body.String())
	}
	assertNoLeak(t, w.Body.String())
}

func TestDeliveryStatus_ReportsWhetherEmailCanDeliver(t *testing.T) {
	sv := ncLoadSpec(t)
	for _, configured := range []bool{true, false} {
		w := ncDo(deliveryStatusEngine(stubEmailStatus{configured: configured}), http.MethodGet, ncBase+"/tenant/delivery-status", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
		}
		sv.assertConforms(t, "TenantDeliveryStatus", w.Body.Bytes())
		want := fmt.Sprintf(`{"email":{"configured":%t}}`, configured)
		if w.Body.String() != want {
			t.Errorf("body = %s, want %s", w.Body.String(), want)
		}
	}
	w := ncDo(deliveryStatusEngine(stubEmailStatus{err: errors.New("db down")}), http.MethodGet, ncBase+"/tenant/delivery-status", nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 on a lookup failure", w.Code)
	}
}
