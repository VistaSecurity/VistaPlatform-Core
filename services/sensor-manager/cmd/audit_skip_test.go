package main

// Collector liveness traffic must not land in the tenant activity log, and
// collector data submissions must. Both are wiring facts: the shared
// middleware's opt-out is unit-tested in shared/middleware/audit, but only the
// real router says which of THIS service's routes carry it. So this drives
// setupRouter, the call main makes, and reads what the real audit middleware
// has batched.
//
// To mutation-test: delete `auditmiddleware.Skip(),` from the /heartbeat (or
// /health) route in router.go and the matching case fails.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/handlers"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

func TestSensorLivenessRoutesAreNotAudited_DataSubmissionsAre(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("AUDIT_LOGGING_ENABLED", "true")
	t.Setenv("AUDIT_SERVICE_URL", "http://127.0.0.1:1") // never reached: the batch is not flushed in-test
	t.Setenv("RESOURCE_METRICS_INGEST_URL", "http://127.0.0.1:1/x")

	// A lazy handle that never connects: SensorAuth gets nil handles (the
	// dev-mode shape it accepts when mTLS is not required), and the handlers
	// fail their first query with a 5xx. Audit records the request either way.
	db, err := sql.Open("postgres", "postgres://invalid:invalid@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("opening a lazy handle: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{JWTSecret: "audit-skip-test", SensorMTLSRequired: false}
	handler := handlers.NewHandlerWithBoth(services.NewSensorService(db, db), nil, nil, db, db)
	router, _ := setupRouter(cfg, handler, nil, nil)

	// The audit middleware instance the router mounted, reached through the
	// context key the router's own global middleware sets. A route added after
	// setupRouter inherits those global handlers.
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

	const prefix = "/api/v1/sensor-manager/sensors/11111111-1111-4111-8111-111111111111"
	post := func(path string) {
		req := httptest.NewRequest(http.MethodPost, prefix+path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(httptest.NewRecorder(), req)
	}

	for _, path := range []string{"/heartbeat", "/health"} {
		post(path)
		if got := len(mw.PendingEntries()) - base; got != 0 {
			t.Fatalf("POST %s produced %d audit entries; sensor liveness reports must not be recorded", path, got)
		}
	}

	post("/discoveries")
	if got := len(mw.PendingEntries()) - base; got != 1 {
		t.Fatalf("POST /discoveries produced %d audit entries, want 1: a sensor submitting data stays auditable", got)
	}
}
