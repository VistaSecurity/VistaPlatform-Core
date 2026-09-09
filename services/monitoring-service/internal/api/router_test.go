package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/config"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

// newProductionRouter builds the SAME router Start serves, via buildRouter.
//
// The Server carries only a config: every request below is rejected by its
// route group's platform-auth middleware before any handler or RBAC query
// runs, so the nil services and nil db are never dereferenced. The wiring is
// what is under test.
func newProductionRouter(t *testing.T, mw *auditmiddleware.Middleware) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := &Server{config: &config.Config{JWTSecret: "test-jwt-secret"}}
	return s.buildRouter(mw)
}

// The wiring test audit_test.go's cannot be: those build their own gin.Engine
// and call attachAuditLogging on it, so they stay green even when nothing
// mounts the middleware in the running service. Deleting the attachAuditLogging
// call from buildRouter fails THIS test.
//
// /logs is the compliance-log read + SIEM export surface — the sharpest case
// for the trail, and the one this service used not to record at all.
func TestProductionRouter_AuditsLogReads(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/monitoring-service/logs", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated log read = %d, want 401 (auth must run, handler must not)", w.Code)
	}

	entries := mw.PendingEntries()
	if len(entries) != 1 {
		t.Fatalf("production router recorded %d audit entries, want 1 — is attachAuditLogging still mounted in buildRouter?", len(entries))
	}
	if got := entries[0].Metadata["path"]; got != "/api/v1/monitoring-service/logs" {
		t.Errorf("audit entry path = %v, want the requested path", got)
	}
}

// The triage decision holds on the production router: timer-polled operational
// telemetry stays out of the trail.
func TestProductionRouter_SkipsPolledTelemetry(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	for _, path := range []string{
		"/health",
		"/api/v1/monitoring-service/status/system",
		"/api/v1/monitoring-service/platform/summary",
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	}

	if n := len(mw.PendingEntries()); n != 0 {
		t.Fatalf("production router recorded %d audit entries for polled telemetry, want 0", n)
	}
}

func TestProductionRouter_AdminStatusRejectsTenantPlatformRoleToken(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	claims := &models.JWTClaims{
		UserID:   uuid.New(),
		TenantID: uuid.New(),
		Email:    "tenant@example.com",
		Role:     "platform_admin",
		Type:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-jwt-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/monitoring-service/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant token with platform role string = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}
