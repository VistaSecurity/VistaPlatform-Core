package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

func newTestAuditMiddleware(t *testing.T) *auditmiddleware.Middleware {
	t.Helper()
	cfg := auditmiddleware.DefaultConfig()
	cfg.ServiceName = "tenant-health-service"
	cfg.BatchSize = 1000
	cfg.FlushInterval = time.Hour
	cfg.Timeout = 10 * time.Millisecond
	cfg.AuditServiceURL = "http://127.0.0.1:1"
	mw := auditmiddleware.NewMiddleware(cfg)
	t.Cleanup(mw.Stop)
	return mw
}

func newAuditTestRouter(t *testing.T, mw *auditmiddleware.Middleware) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	attachAuditLogging(r, mw)
	ok := func(c *gin.Context) { c.String(http.StatusOK, "ok") }
	r.GET("/health", ok)
	r.GET("/api/v1/tenant-health-service/tenants", ok)
	r.GET("/api/v1/tenant-health-service/tenants/:tenantId/insights", ok)
	r.POST("/api/v1/tenant-health-service/calculate", ok)
	return r
}

func serve(t *testing.T, r *gin.Engine, method, path string) {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%s %s = %d, want 200", method, path, w.Code)
	}
}

// Cross-tenant reads and health recalculation must reach the audit trail.
// This fails if the LogRequest wiring is removed from attachAuditLogging.
func TestAuditLogging_RecordsCrossTenantAdminAccess(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newAuditTestRouter(t, mw)

	serve(t, r, http.MethodGet, "/api/v1/tenant-health-service/tenants")
	serve(t, r, http.MethodGet, "/api/v1/tenant-health-service/tenants/abc/insights")
	serve(t, r, http.MethodPost, "/api/v1/tenant-health-service/calculate")

	entries := mw.PendingEntries()
	if len(entries) != 3 {
		t.Fatalf("recorded %d audit entries, want 3", len(entries))
	}
	var sawCreate bool
	for _, e := range entries {
		if e.Action == "create" {
			sawCreate = true
		}
	}
	if !sawCreate {
		t.Error("POST /calculate was not recorded as a mutation")
	}
}

// Liveness probes are not auditable events.
func TestAuditLogging_SkipsHealthProbe(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newAuditTestRouter(t, mw)

	serve(t, r, http.MethodGet, "/health")

	if n := len(mw.PendingEntries()); n != 0 {
		t.Fatalf("recorded %d audit entries for /health, want 0", n)
	}
}

// Handlers can still reach the middleware to log an explicit event.
func TestAuditLogging_MiddlewareAvailableInContext(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	attachAuditLogging(r, mw)
	var found bool
	r.GET("/api/v1/tenant-health-service/tenants", func(c *gin.Context) {
		_, found = auditmiddleware.ExtractAuditMiddleware(c)
		c.String(http.StatusOK, "ok")
	})
	serve(t, r, http.MethodGet, "/api/v1/tenant-health-service/tenants")
	if !found {
		t.Fatal("audit middleware not available to handlers")
	}
}
