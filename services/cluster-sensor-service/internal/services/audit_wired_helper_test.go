package services_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// auditWired puts a working audit middleware (its sink an httptest server) on
// the request context, as main() does. A confirmed external scan now needs one:
// without it CreateJob cancels the job instead of scanning unrecorded.
func auditWired(t *testing.T) gin.HandlerFunc {
	t.Helper()
	srv := httptest.NewServer(&previewAudit{})
	t.Cleanup(srv.Close)
	cfg := auditmiddleware.DefaultConfig()
	cfg.ServiceName = "cluster-sensor-service"
	cfg.AuditServiceURL = srv.URL
	cfg.BatchSize = 1
	cfg.FlushInterval = 50 * time.Millisecond
	mw := auditmiddleware.NewMiddleware(cfg)
	return func(c *gin.Context) { c.Set("audit_middleware", mw); c.Next() }
}
