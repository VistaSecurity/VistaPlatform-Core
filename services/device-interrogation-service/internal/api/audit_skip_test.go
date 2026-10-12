package api

// Collector liveness traffic must not land in the tenant activity log, and
// collector data submissions must. Both are wiring facts: the shared
// middleware's opt-out is unit-tested in shared/middleware/audit, but only the
// real router says which of THIS service's routes carry it. So this drives
// SetupRouter and reads what the real audit middleware has batched, with the
// real AgentAuth satisfied (fail-open mode, the agent row and tenant found).
//
// To mutation-test: delete `auditmiddleware.Skip(), ` from the /:id/jobs (or
// /:id/heartbeat) route in router.go and the matching case fails.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

func TestAgentLivenessRoutesAreNotAudited_DataSubmissionsAre(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-key-for-route-registration-only")
	t.Setenv("NATS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "true")
	t.Setenv("AUDIT_SERVICE_URL", "http://127.0.0.1:1") // never reached: the batch is not flushed in-test

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)

	agentID, tenantID := uuid.New(), uuid.New()
	// AgentAuth, per request: resolve the agent's tenant, then the tenant's
	// state. Anything a handler queries after that is unexpected, so the
	// handler answers 5xx; audit records the request regardless of status.
	for i := 0; i < 4; i++ {
		mock.ExpectQuery(`SELECT tenant_id FROM device_agents WHERE id = \$1 AND deleted_at IS NULL`).
			WithArgs(agentID).
			WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
		mock.ExpectQuery(`FROM tenants WHERE id = \$1`).WithArgs(tenantID).
			WillReturnRows(sqlmock.NewRows([]string{"payment_status", "deleted", "session_version"}).AddRow("active", false, 0))
	}

	// A client that is never reachable: the job poll consults it and a nil
	// client panics, and the recovery middleware sits ahead of audit, so a
	// panicking handler would hide whether it was recorded.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	defer func() { _ = rdb.Close() }()

	router, _ := SetupRouter(&config.Config{AgentMTLSRequired: false}, db, db, rdb)

	// The audit middleware instance the router mounted, reached through the
	// context key the router's own global middleware sets. A route added after
	// SetupRouter inherits those global handlers.
	var mw *auditmiddleware.Middleware
	router.GET("/__audit_probe", func(c *gin.Context) {
		v, _ := c.Get("audit_middleware")
		mw, _ = v.(*auditmiddleware.Middleware)
		c.Status(http.StatusOK)
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/__audit_probe", nil))
	if mw == nil {
		t.Fatal("could not reach the router's audit middleware")
	}
	t.Cleanup(mw.Stop)
	base := len(mw.PendingEntries()) // the probe itself

	prefix := "/api/v1/device-interrogation-service/agents/" + agentID.String()
	call := func(method, path string) {
		req := httptest.NewRequest(method, prefix+path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(httptest.NewRecorder(), req)
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/jobs"},
		{http.MethodPost, "/heartbeat"},
	} {
		call(c.method, c.path)
		if got := len(mw.PendingEntries()) - base; got != 0 {
			t.Fatalf("%s %s produced %d audit entries; agent liveness traffic must not be recorded", c.method, c.path, got)
		}
	}

	call(http.MethodPost, "/results")
	if got := len(mw.PendingEntries()) - base; got != 1 {
		t.Fatalf("POST /results produced %d audit entries, want 1: an agent submitting data stays auditable", got)
	}
}
