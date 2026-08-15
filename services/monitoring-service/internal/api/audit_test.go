package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// newTestAuditMiddleware builds an audit middleware that batches in memory:
// a flush interval long enough that nothing leaves the batch during a test,
// and a short timeout so the shutdown flush cannot hang.
func newTestAuditMiddleware(t *testing.T) *auditmiddleware.Middleware {
	t.Helper()
	cfg := auditmiddleware.DefaultConfig()
	cfg.ServiceName = "monitoring-service"
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
	r.GET("/api/v1/monitoring-service/logs", ok)
	r.GET("/api/v1/monitoring-service/logs/siem/export", ok)
	r.POST("/api/v1/monitoring-service/alerting/thresholds", ok)
	r.GET("/api/v1/monitoring-service/status/system", ok)
	r.GET("/api/v1/monitoring-service/version", ok)
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

// Reading and exporting the platform log corpus, and changing alert
// thresholds, must reach the audit trail. This fails if the LogRequest wiring
// is dropped from attachAuditLogging.
func TestAuditLogging_RecordsComplianceAndAlertingSurfaces(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newAuditTestRouter(t, mw)

	do(t, r, http.MethodGet, "/api/v1/monitoring-service/logs")
	do(t, r, http.MethodGet, "/api/v1/monitoring-service/logs/siem/export")
	do(t, r, http.MethodPost, "/api/v1/monitoring-service/alerting/thresholds")

	entries := mw.PendingEntries()
	if len(entries) != 3 {
		t.Fatalf("recorded %d audit entries, want 3 (log read, SIEM export, threshold create)", len(entries))
	}
	for _, e := range entries {
		if e.Metadata["path"] == nil {
			t.Errorf("entry %+v has no path", e)
		}
	}
}

// The polling surfaces must NOT be audited. A dashboard poll every few seconds
// is not an auditable event, and burying the entries above under thousands of
// them is how an audit trail stops being usable.
func TestAuditLogging_SkipsOperationalPolling(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newAuditTestRouter(t, mw)

	do(t, r, http.MethodGet, "/api/v1/monitoring-service/status/system")
	do(t, r, http.MethodGet, "/api/v1/monitoring-service/version")
	do(t, r, http.MethodGet, "/health")

	if n := len(mw.PendingEntries()); n != 0 {
		t.Fatalf("recorded %d audit entries for polling surfaces, want 0", n)
	}
}

func TestShouldAuditPath(t *testing.T) {
	audited := []string{
		"/api/v1/monitoring-service/logs",
		"/api/v1/monitoring-service/logs/siem/export",
		"/api/v1/monitoring-service/alerting/thresholds",
	}
	skipped := []string{
		"/health",
		"/api/v1/monitoring-service/status/system",
		"/api/v1/monitoring-service/platform/summary",
		"/api/v1/monitoring-service/gateway/routers",
		"/api/v1/monitoring-service/trends",
		"/api/v1/monitoring-service/version",
		"/api/v1/admin-service/status/system",
	}
	for _, p := range audited {
		if !shouldAuditPath(p) {
			t.Errorf("%s should be audited", p)
		}
	}
	for _, p := range skipped {
		if shouldAuditPath(p) {
			t.Errorf("%s should NOT be audited (operational polling)", p)
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
	r.GET("/api/v1/monitoring-service/status/system", func(c *gin.Context) {
		_, found = auditmiddleware.ExtractAuditMiddleware(c)
		c.String(http.StatusOK, "ok")
	})
	do(t, r, http.MethodGet, "/api/v1/monitoring-service/status/system")
	if !found {
		t.Fatal("audit middleware not available to handlers")
	}
}
