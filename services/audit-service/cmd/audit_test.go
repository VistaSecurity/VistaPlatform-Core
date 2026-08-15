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
	cfg.ServiceName = "audit-service"
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
	r.GET("/api/v1/audit-service/activity-logs", ok)
	r.POST("/api/v1/audit-service/activity-logs", ok)
	r.GET("/api/v1/audit-service/activity-logs/export", ok)
	r.POST("/api/v1/audit-service/activity-logs/query", ok)
	r.POST("/api/v1/audit-service/job-execution-logs/start", ok)
	r.DELETE("/api/v1/audit-service/alert-rules/:id", ok)
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

// Reading, querying and exporting the audit trail, and deleting an alert rule,
// must themselves reach the audit trail. This fails if the LogRequest wiring is
// dropped from attachAuditLogging.
func TestAuditLogging_RecordsTrailReadsAndConfigChanges(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newAuditTestRouter(t, mw)

	do(t, r, http.MethodGet, "/api/v1/audit-service/activity-logs")
	do(t, r, http.MethodGet, "/api/v1/audit-service/activity-logs/export")
	do(t, r, http.MethodPost, "/api/v1/audit-service/activity-logs/query")
	do(t, r, http.MethodDelete, "/api/v1/audit-service/alert-rules/abc")

	entries := mw.PendingEntries()
	if len(entries) != 4 {
		t.Fatalf("recorded %d audit entries, want 4 (list, export, query, alert-rule delete)", len(entries))
	}
	for _, e := range entries {
		if e.Metadata["path"] == nil {
			t.Errorf("entry %+v has no path", e)
		}
	}
}

// The S2S ingest endpoints must NOT be audited: auditing the POST that delivers
// an audit entry writes another audit entry, delivered by another POST.
func TestAuditLogging_SkipsIngest(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newAuditTestRouter(t, mw)

	do(t, r, http.MethodPost, "/api/v1/audit-service/activity-logs")
	do(t, r, http.MethodPost, "/api/v1/audit-service/job-execution-logs/start")
	do(t, r, http.MethodGet, "/health")

	if n := len(mw.PendingEntries()); n != 0 {
		t.Fatalf("recorded %d audit entries for ingest/health, want 0", n)
	}
}

// The ingest skip is method-aware on purpose: GET and POST share the
// /activity-logs path, and only the POST is ingest.
func TestShouldAuditRequest(t *testing.T) {
	audited := [][2]string{
		{http.MethodGet, "/api/v1/audit-service/activity-logs"},
		{http.MethodGet, "/api/v1/audit-service/activity-logs/summary"},
		{http.MethodGet, "/api/v1/audit-service/activity-logs/export"},
		{http.MethodPost, "/api/v1/audit-service/activity-logs/query"},
		{http.MethodGet, "/api/v1/audit-service/job-execution-logs"},
		{http.MethodPost, "/api/v1/audit-service/compliance-reports/generate"},
		{http.MethodPut, "/api/v1/audit-service/retention-policies/abc"},
		{http.MethodDelete, "/api/v1/audit-service/alert-rules/abc"},
	}
	skipped := [][2]string{
		{http.MethodPost, "/api/v1/audit-service/activity-logs"},
		{http.MethodPost, "/api/v1/audit-service/job-execution-logs/start"},
		{http.MethodPost, "/api/v1/audit-service/job-execution-logs/abc/progress"},
		{http.MethodPost, "/api/v1/audit-service/job-execution-logs/abc/complete"},
		{http.MethodGet, "/health"},
		{http.MethodGet, "/ready"},
	}
	for _, c := range audited {
		if !shouldAuditRequest(c[0], c[1]) {
			t.Errorf("%s %s should be audited", c[0], c[1])
		}
	}
	for _, c := range skipped {
		if shouldAuditRequest(c[0], c[1]) {
			t.Errorf("%s %s should NOT be audited", c[0], c[1])
		}
	}
}
