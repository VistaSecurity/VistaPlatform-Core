package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type capturedAudit struct {
	path   string
	signed bool
	body   map[string]interface{}
}

// TestPlatformAuditEmitter_EmitPostsPlatformActivity verifies that Emit posts an
// activity-log entry to the audit-service ingest route with user_type="platform",
// the actor, and the action/resource fields — over the HMAC-signed HTTP path
// (NOT NATS, which drops user_type and would fail the activity_logs CHECK).
func TestPlatformAuditEmitter_EmitPostsPlatformActivity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recvCh := make(chan capturedAudit, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		recvCh <- capturedAudit{
			path:   r.URL.Path,
			signed: r.Header.Get("X-Internal-Signature") != "",
			body:   body,
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
	}))
	defer srv.Close()

	emitter := NewPlatformAuditEmitter(AuditEmitterConfig{
		AuditServiceURL:    srv.URL,
		InternalAuthSecret: "test-secret",
		Enabled:            true,
	})

	actorID := uuid.New()
	roleID := uuid.New().String()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/admin-service/admin/roles/x/permissions", nil)
	c.Request.Header.Set("User-Agent", "unit-test-agent")
	c.Set("userID", actorID.String())
	c.Set("email", "admin@example.com")

	emitter.Emit(c, PlatformAuditEntry{
		EventType:     "platform_role.permissions_set",
		Action:        "set_permissions",
		EventCategory: "system",
		ResourceType:  "platform_role",
		ResourceID:    roleID,
		Metadata:      map[string]interface{}{"permission_count": 3},
	})

	select {
	case got := <-recvCh:
		if got.path != "/api/v1/audit-service/activity-logs" {
			t.Fatalf("posted to %q, want /api/v1/audit-service/activity-logs", got.path)
		}
		if !got.signed {
			t.Error("expected HMAC X-Internal-Signature header to be present")
		}
		assertField(t, got.body, "user_type", "platform")
		assertField(t, got.body, "event_type", "platform_role.permissions_set")
		assertField(t, got.body, "event_category", "system")
		assertField(t, got.body, "action", "set_permissions")
		assertField(t, got.body, "resource_type", "platform_role")
		assertField(t, got.body, "resource_id", roleID)
		assertField(t, got.body, "user_id", actorID.String())
		assertField(t, got.body, "user_email", "admin@example.com")
	case <-time.After(3 * time.Second):
		t.Fatal("audit emitter did not POST within timeout")
	}
}

// TestPlatformAuditEmitter_DisabledIsNoop verifies a disabled emitter sends nothing.
func TestPlatformAuditEmitter_DisabledIsNoop(t *testing.T) {
	gin.SetMode(gin.TestMode)

	calls := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	emitter := NewPlatformAuditEmitter(AuditEmitterConfig{AuditServiceURL: srv.URL, Enabled: false})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/x", nil)
	emitter.Emit(c, PlatformAuditEntry{EventType: "x", Action: "x", EventCategory: "system"})

	select {
	case <-calls:
		t.Fatal("disabled emitter must not POST")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestRecordPlatformAudit_NilAuditorIsSafe verifies the package helper is a safe
// no-op when the auditor was never initialized (e.g. in handler unit tests).
func TestRecordPlatformAudit_NilAuditorIsSafe(t *testing.T) {
	gin.SetMode(gin.TestMode)

	saved := platformAuditor
	platformAuditor = nil
	defer func() { platformAuditor = saved }()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/x", nil)
	recordPlatformAudit(c, PlatformAuditEntry{EventType: "x", Action: "x", EventCategory: "system"})
}

func assertField(t *testing.T, body map[string]interface{}, key, want string) {
	t.Helper()
	got, ok := body[key]
	if !ok {
		t.Errorf("missing field %q in audit body", key)
		return
	}
	if got != want {
		t.Errorf("%s = %v, want %q", key, got, want)
	}
}
