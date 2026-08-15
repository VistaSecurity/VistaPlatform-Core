package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/config"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/handlers"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// newProductionRouter builds the SAME router main() serves, via newRouter.
//
// Handlers are constructed with nil services: every request below is rejected
// by its route group's auth middleware before any handler runs, so no service
// dependency is ever dereferenced. What is under test is the wiring, not the
// handlers.
func newProductionRouter(t *testing.T, mw *auditmiddleware.Middleware) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		JWTSecret:          "test-jwt-secret",
		InternalAuthSecret: "test-internal-secret",
	}
	return newRouter(cfg, handlers.NewResourceHandlers(nil, nil, logrus.New()), mw)
}

// The wiring test the ones in audit_test.go cannot be.
//
// Those build their own gin.Engine and call attachAuditLogging on it, so they
// stay green even when nothing mounts the middleware in the running service —
// which is exactly the hole this closes. Deleting the attachAuditLogging call
// from newRouter fails THIS test, and newRouter is the only way main() gets a
// router with routes on it.
func TestProductionRouter_AuditsTenantReads(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	// No credentials: the route group's auth middleware rejects the request
	// before the handler, and the audit entry is recorded anyway. A rejected
	// read of a named tenant's usage is itself worth auditing.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/resource-tracker/tenants/t1/usage", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated tenant-usage read = %d, want 401 (auth must run, handler must not)", w.Code)
	}

	entries := mw.PendingEntries()
	if len(entries) != 1 {
		t.Fatalf("production router recorded %d audit entries, want 1 — is attachAuditLogging still mounted in newRouter?", len(entries))
	}
	if got := entries[0].Metadata["path"]; got != "/api/v1/resource-tracker/tenants/t1/usage" {
		t.Errorf("audit entry path = %v, want the requested path", got)
	}
}

// The exclusion holds on the production router too: the S2S metrics ingest is
// not audited even though it sits under an audited prefix.
func TestProductionRouter_SkipsMetricsIngest(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/resource-tracker/metrics", nil))

	if n := len(mw.PendingEntries()); n != 0 {
		t.Fatalf("production router recorded %d audit entries for the metrics ingest, want 0", n)
	}
}
