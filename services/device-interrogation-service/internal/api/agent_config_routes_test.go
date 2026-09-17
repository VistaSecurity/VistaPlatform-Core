package api

import (
	"database/sql"
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

	router := SetupRouter(&config.Config{}, db, db, nil)

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
