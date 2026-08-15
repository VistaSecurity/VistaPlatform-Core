package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/database"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// newProductionRouter builds the SAME router main() serves, via newRouter.
//
// The handler bundle is zero-valued and the DB wrapper holds no connection:
// every request below is rejected by its route group's auth middleware before
// any handler or permission query runs, so nothing nil is dereferenced. The
// wiring is what is under test.
func newProductionRouter(t *testing.T, mw *auditmiddleware.Middleware) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		JWT:                config.JWTConfig{Secret: "test-jwt-secret"},
		InternalAuthSecret: "test-internal-secret",
	}
	return newRouter(cfg, &database.DB{}, mw, routerHandlers{})
}

// The wiring test audit_test.go's cannot be: those build their own gin.Engine
// and call attachAuditLogging on it, so they stay green even when nothing
// mounts the middleware in the running service. Deleting the attachAuditLogging
// call from newRouter fails THIS test.
//
// Reading the audit trail is the event that most needs recording, and this
// service's own read path is the one that used to record nothing.
func TestProductionRouter_AuditsTrailReads(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/audit-service/activity-logs", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated activity-log read = %d, want 401 (auth must run, handler must not)", w.Code)
	}

	entries := mw.PendingEntries()
	if len(entries) != 1 {
		t.Fatalf("production router recorded %d audit entries, want 1 — is attachAuditLogging still mounted in newRouter?", len(entries))
	}
	if got := entries[0].Metadata["path"]; got != "/api/v1/audit-service/activity-logs" {
		t.Errorf("audit entry path = %v, want the requested path", got)
	}
}

// The self-referential ingest POST stays out of the trail on the production
// router too — it shares its path with the audited GET above, so this is the
// method-aware skip being exercised through the real route table.
func TestProductionRouter_SkipsIngestPost(t *testing.T) {
	mw := newTestAuditMiddleware(t)
	r := newProductionRouter(t, mw)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/audit-service/activity-logs", nil))

	if n := len(mw.PendingEntries()); n != 0 {
		t.Fatalf("production router recorded %d audit entries for the S2S ingest POST, want 0", n)
	}
}
