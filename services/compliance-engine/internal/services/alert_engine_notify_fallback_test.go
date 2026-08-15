package services

// Gap 1 regression tests: the alert engine's notification fan-out runs ONLY on
// alert open and on severity escalation — never on re-raise — so a NATS outage
// at that instant used to lose the notification permanently (publishAlertNotification
// returned early on a nil NATS client and merely logged publish errors).
// It now falls back to an HMAC-signed HTTP POST, matching audit-service.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// notifyStub stands in for notification-service: it mounts the REAL route path
// and verifies with the REAL serviceauth verifier, so a caller that agrees only
// with itself (wrong path, wrong auth scheme) fails here rather than in prod.
type notifyStub struct {
	server   *httptest.Server
	accepted bool
	path     string
	body     map[string]interface{}
	status   int
	hits     int
}

func newNotifyStub(t *testing.T, secret string) *notifyStub {
	t.Helper()
	st := &notifyStub{status: http.StatusOK}
	verifier := serviceauth.NewVerifier(secret)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/*any", func(c *gin.Context) {
		st.hits++
		st.path = c.Request.URL.Path
		st.accepted = verifier.Verify(c)
		raw, _ := io.ReadAll(c.Request.Body)
		_ = json.Unmarshal(raw, &st.body)
		c.JSON(st.status, gin.H{"status": "ok"})
	})
	st.server = httptest.NewServer(r)
	t.Cleanup(st.server.Close)
	return st
}

func TestPublishAlertNotification_FallsBackToHTTPWhenNATSUnavailable(t *testing.T) {
	const secret = "internal-auth-test-secret"
	t.Setenv("INTERNAL_AUTH_SECRET", secret)
	t.Setenv("USE_MTLS", "false")

	stub := newNotifyStub(t, secret)
	t.Setenv("NOTIFICATION_SERVICE_URL", stub.server.URL)

	// natsClient nil — exactly the condition that used to `return` and drop the
	// notification on the floor.
	s := NewAlertEngineService(nil, nil, nil, nil)

	tenantID := uuid.New()
	alertID := uuid.New()
	s.publishAlertNotification(tenantID, "compliance", "control_noncompliant", "high",
		"Control noncompliant: PCI-3.4", "TLS 1.0 in use", alertID, "opened",
		map[string]interface{}{"control_id": "PCI-3.4"})

	if stub.hits != 1 {
		t.Fatalf("notification-service received %d request(s), want 1 — the HTTP fallback did not fire", stub.hits)
	}
	if stub.path != "/api/v1/notification-service/internal/send" {
		t.Errorf("posted to %q, want /api/v1/notification-service/internal/send (the /api/v2 form 404s)", stub.path)
	}
	if !stub.accepted {
		t.Error("serviceauth verifier rejected the fallback POST — /internal/send is HMAC-only, an unsigned request 401s silently")
	}
	if got := stub.body["tenant_id"]; got != tenantID.String() {
		t.Errorf("tenant_id = %v, want %s", got, tenantID)
	}
	if got := stub.body["alert_type"]; got != "control_noncompliant" {
		t.Errorf("alert_type = %v, want control_noncompliant", got)
	}
	if got := stub.body["severity"]; got != "high" {
		t.Errorf("severity = %v, want high", got)
	}
	// Title must survive the fallback, else the in-app bell degrades to a
	// humanized alert_type precisely when delivery is already degraded.
	if got := stub.body["title"]; got != "Control noncompliant: PCI-3.4" {
		t.Errorf("title = %v, want the producer's composed title", got)
	}
	md, ok := stub.body["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata missing or wrong shape: %#v", stub.body["metadata"])
	}
	if md["alert_id"] != alertID.String() {
		t.Errorf("metadata.alert_id = %v, want %s", md["alert_id"], alertID)
	}
	if md["alert_transition"] != "opened" {
		t.Errorf("metadata.alert_transition = %v, want opened", md["alert_transition"])
	}
	if md["control_id"] != "PCI-3.4" {
		t.Errorf("producer metadata not merged through: %#v", md)
	}
}

// A non-2xx from notification-service must be reported as an error by the
// transport helper (the caller logs it as a lost notification) rather than being
// swallowed as success — the "check that cannot fail" shape.
func TestPostAlertNotification_ReportsNon2xx(t *testing.T) {
	const secret = "internal-auth-test-secret"
	t.Setenv("INTERNAL_AUTH_SECRET", secret)
	t.Setenv("USE_MTLS", "false")

	stub := newNotifyStub(t, secret)
	stub.status = http.StatusInternalServerError
	t.Setenv("NOTIFICATION_SERVICE_URL", stub.server.URL)

	s := NewAlertEngineService(nil, nil, nil, nil)
	err := s.postAlertNotification(alertNotificationEvent(uuid.New(), "compliance", "control_noncompliant",
		"high", "t", "m", uuid.New(), "opened", nil))
	if err == nil {
		t.Fatal("postAlertNotification returned nil on a 500 — failures must surface, not be swallowed")
	}
}

func TestNotificationServiceBaseURL_DerivesFromMTLSMode(t *testing.T) {
	t.Setenv("NOTIFICATION_SERVICE_URL", "")

	t.Setenv("USE_MTLS", "false")
	if got := notificationServiceBaseURL(); got != "http://notification-service:8080" {
		t.Errorf("USE_MTLS=false → %q, want http://notification-service:8080", got)
	}

	t.Setenv("USE_MTLS", "true")
	if got := notificationServiceBaseURL(); got != "https://notification-service:8443" {
		t.Errorf("USE_MTLS=true → %q, want https://notification-service:8443 (a plain-HTTP fallback fails the mesh handshake)", got)
	}

	// An explicit override is rewritten to the mesh scheme/port under mTLS.
	t.Setenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8080")
	if got := notificationServiceBaseURL(); got != "https://notification-service:8443" {
		t.Errorf("override under mTLS → %q, want the rewritten https/8443 form", got)
	}
}
