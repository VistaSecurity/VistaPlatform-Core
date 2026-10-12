package api

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
)

// The desired-state routes have to be REGISTERED, and `/agents/config/defaults`
// has to survive sitting next to `/agents/:id/...`. Both are wiring facts that
// no handler test can see: a handler that is never routed passes every test it
// has and answers no request, and a static segment shadowed by a wildcard
// answers the wrong handler.
//
// This drives the real SetupRouter. lazily-opened sql.DB handles never connect,
// because route registration makes no queries, and an empty NATSURL keeps the
// setup offline.
func TestAgentRoutesAreRegisteredAndPlatformAutoRegistrationIsRetired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// SetupRouter builds handlers that call config.Load, which refuses to
	// return a config without an encryption key. Supplying one keeps this a
	// routing test rather than a config test.
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-key-for-route-registration-only")
	t.Setenv("NATS_URL", "")

	db, err := sql.Open("postgres", "postgres://invalid:invalid@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatalf("opening a lazy handle: %v", err)
	}
	defer func() { _ = db.Close() }()

	router, _ := SetupRouter(&config.Config{}, db, db, nil)

	want := map[string]string{
		"POST /api/v1/device-interrogation-service/agents/register":                "operator-enrolled agent bootstrap",
		"POST /api/v1/device-interrogation-service/agents/:id/certificates/rotate": "enrolled-agent certificate rotation",
		"GET /api/v1/device-interrogation-service/agents/config/defaults":          "fleet defaults read",
		"PUT /api/v1/device-interrogation-service/agents/config/defaults":          "fleet defaults write",
		"GET /api/v1/device-interrogation-service/agents/:id/config":               "per-agent read",
		"PUT /api/v1/device-interrogation-service/agents/:id/config":               "per-agent write",
	}
	got := map[string]bool{}
	for _, r := range router.Routes() {
		got[r.Method+" "+r.Path] = true
	}
	for route, what := range want {
		if !got[route] {
			t.Errorf("%s is not registered (%s) — the handler exists but nothing routes to it", route, what)
		}
	}

	// The in-cluster worker uses the system sensor identity. Reintroducing this
	// route would recreate the duplicate device_agents identity retired in
	//while the two enrolled-agent routes above must remain available.
	retired := "POST /api/v1/device-interrogation-service/agents/auto-register"
	if got[retired] {
		t.Errorf("%s is registered; platform device-agent auto-registration is retired", retired)
	}
}

// gin resolves a static segment ahead of a param at the same level, whatever
// order the two were registered in. The router comment once claimed the
// host-inventory route had to precede the `/:id/...` routes; this pins that it
// does not. The real SetupRouter fixes one order, so the two route shapes are
// built here in both orders on a bare engine, and the real router is checked to
// register host-inventory against the host-inventory handler.
func TestHostInventoryStaticRouteBeatsIDParamInEitherOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	marker := func(name string) gin.HandlerFunc {
		return func(c *gin.Context) { c.String(http.StatusOK, name) }
	}
	staticFirst := func(g *gin.RouterGroup) {
		g.POST("/host-inventory", marker("host-inventory"))
		g.POST("/:id/results", marker("id-results"))
		g.GET("/:id/jobs", marker("id-jobs"))
	}
	staticLast := func(g *gin.RouterGroup) {
		g.GET("/:id/jobs", marker("id-jobs"))
		g.POST("/:id/results", marker("id-results"))
		g.POST("/host-inventory", marker("host-inventory"))
	}
	for name, register := range map[string]func(*gin.RouterGroup){
		"static registered first": staticFirst,
		"static registered last":  staticLast,
	} {
		t.Run(name, func(t *testing.T) {
			r := gin.New()
			register(r.Group("/agents"))
			for path, want := range map[string]string{
				"/agents/host-inventory": "host-inventory",
				"/agents/abc/results":    "id-results",
			} {
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
				if got := w.Body.String(); got != want {
					t.Errorf("POST %s resolved to %q, want %q", path, got, want)
				}
			}
		})
	}

	// Real router: the route exists, is POST, and is the host-inventory handler.
	t.Setenv("ENCRYPTION_MASTER_KEY", "test-key-for-route-registration-only")
	t.Setenv("NATS_URL", "")
	db, err := sql.Open("postgres", "postgres://invalid:invalid@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatalf("opening a lazy handle: %v", err)
	}
	defer func() { _ = db.Close() }()
	router, _ := SetupRouter(&config.Config{}, db, db, nil)
	found := false
	for _, r := range router.Routes() {
		if r.Method == http.MethodPost && r.Path == "/api/v1/device-interrogation-service/agents/host-inventory" {
			found = true
			if !strings.Contains(r.Handler, "HostInventoryHandler") {
				t.Errorf("host-inventory route handler = %q, want the HostInventoryHandler", r.Handler)
			}
		}
	}
	if !found {
		t.Error("POST .../agents/host-inventory is not registered")
	}
}
