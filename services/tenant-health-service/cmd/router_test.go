package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/handlers"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// newProductionRouter builds the SAME router main() serves, via newRouter.
//
// Handlers and db are nil: the request below is rejected by the group's
// platform-admin auth middleware before any handler or RBAC query runs, so
// nothing nil is dereferenced. The wiring is what is under test.
func newProductionRouter(t *testing.T, mw *auditmiddleware.Middleware) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	return newRouter(handlers.NewHealthHandlers(nil), mw, "test-jwt-secret", "test-internal-secret", nil)
}

// The wiring test audit_test.go's cannot be: those build their own gin.Engine
// and call attachAuditLogging on it, so they stay green even when nothing
// mounts the middleware in the running service. Deleting the attachAuditLogging
// call from newRouter fails THIS test.
func TestProductionRouter_AuditsCrossTenantAdminAccess(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	// No credentials: auth rejects before the handler, and the attempt is
	// recorded anyway — a rejected cross-tenant read is worth auditing.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/tenant-health-service/tenants", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated cross-tenant read = %d, want 401 (auth must run, handler must not)", w.Code)
	}

	entries := mw.PendingEntries()
	if len(entries) != 1 {
		t.Fatalf("production router recorded %d audit entries, want 1 — is attachAuditLogging still mounted in newRouter?", len(entries))
	}
	if got := entries[0].Metadata["path"]; got != "/api/v1/tenant-health-service/tenants" {
		t.Errorf("audit entry path = %v, want the requested path", got)
	}
}

// /health is excluded by the shared config's SkipPaths — on the production
// router too, so kubelet probes never enter the trail.
func TestProductionRouter_SkipsHealthProbe(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /health = %d, want 200", w.Code)
	}

	if n := len(mw.PendingEntries()); n != 0 {
		t.Fatalf("production router recorded %d audit entries for /health, want 0", n)
	}
}
