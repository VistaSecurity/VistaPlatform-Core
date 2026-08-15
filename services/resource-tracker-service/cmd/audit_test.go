package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// newTestAuditMiddleware builds an audit middleware that batches in memory: a
// flush interval long enough that nothing leaves the batch during a test, and
// a short timeout so the shutdown flush cannot hang.
func newTestAuditMiddleware(t *testing.T) *auditmiddleware.Middleware {
	t.Helper()
	cfg := auditmiddleware.DefaultConfig()
	cfg.ServiceName = "resource-tracker-service"
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
	r.POST("/api/v1/resource-tracker/metrics", ok)
	r.GET("/api/v1/resource-tracker/tenants/:tenantId/usage", ok)
	r.GET("/api/v1/resource-tracker/stats", ok)
	r.GET("/api/v1/resource-tracker-service/tenants/:tenantId/cost-analysis", ok)
	r.GET("/api/v1/resource-tracker-service/tenant/:id/resource-summary", ok)
	r.GET("/health", ok)
	return r
}

func do(t *testing.T, r *gin.Engine, method, path string) {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%s %s = %d, want 200", method, path, w.Code)
	}
}

// Reading a named tenant's usage and cost figures, and the platform-wide
// rollups, must reach the audit trail. This fails if the LogRequest wiring is
// dropped from attachAuditLogging.
func TestAuditLogging_RecordsTenantAndPlatformReads(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newAuditTestRouter(t, mw)

	do(t, r, http.MethodGet, "/api/v1/resource-tracker/tenants/t1/usage")
	do(t, r, http.MethodGet, "/api/v1/resource-tracker/stats")
	do(t, r, http.MethodGet, "/api/v1/resource-tracker-service/tenants/t1/cost-analysis")
	do(t, r, http.MethodGet, "/api/v1/resource-tracker-service/tenant/t1/resource-summary")

	entries := mw.PendingEntries()
	if len(entries) != 4 {
		t.Fatalf("recorded %d audit entries, want 4 (tenant usage, platform stats, cost analysis, resource summary)", len(entries))
	}
	for _, e := range entries {
		if e.Metadata["path"] == nil {
			t.Errorf("entry %+v has no path", e)
		}
	}
}

// The HMAC-only metrics ingest is pushed on a timer by every backend. It must
// NOT be audited — burying the entries above under thousands of actor-less
// timer pushes is how an audit trail stops being usable.
func TestAuditLogging_SkipsServiceToServiceMetricsIngest(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newAuditTestRouter(t, mw)

	do(t, r, http.MethodPost, "/api/v1/resource-tracker/metrics")
	do(t, r, http.MethodGet, "/health")

	if n := len(mw.PendingEntries()); n != 0 {
		t.Fatalf("recorded %d audit entries for the metrics ingest / health, want 0", n)
	}
}

func TestShouldAuditPath(t *testing.T) {
	audited := []string{
		"/api/v1/resource-tracker/tenants/t1/usage",
		"/api/v1/resource-tracker/tenants/t1/trend",
		"/api/v1/resource-tracker/tenants/t1/cost-trend",
		"/api/v1/resource-tracker/tenants/t1/cost-analysis",
		"/api/v1/resource-tracker/tenants/usage",
		"/api/v1/resource-tracker/stats",
		"/api/v1/resource-tracker-service/stats",
		"/api/v1/resource-tracker-service/tenants/usage",
		"/api/v1/resource-tracker-service/tenant/t1/resource-summary",
	}
	skipped := []string{
		"/api/v1/resource-tracker/metrics",
		"/health",
		"/api/v1/monitoring-service/status/system",
	}
	for _, p := range audited {
		if !shouldAuditPath(p) {
			t.Errorf("%s should be audited", p)
		}
	}
	for _, p := range skipped {
		if shouldAuditPath(p) {
			t.Errorf("%s should NOT be audited", p)
		}
	}
}

// The handler-accessible middleware is still set on every request, audited or
// not, so a handler that wants to log an explicit event can.
func TestAuditLogging_MiddlewareAvailableInContext(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	attachAuditLogging(r, mw)
	var found bool
	r.POST("/api/v1/resource-tracker/metrics", func(c *gin.Context) {
		_, found = auditmiddleware.ExtractAuditMiddleware(c)
		c.String(http.StatusOK, "ok")
	})
	do(t, r, http.MethodPost, "/api/v1/resource-tracker/metrics")
	if !found {
		t.Fatal("audit middleware not available to handlers")
	}
}
