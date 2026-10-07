package main

// The agent-mTLS passthrough listener (pentest-readiness D2). It is reached by
// TCP passthrough, so no edge deny, rate limit or body limit applies, and its
// handshake accepts ANY client certificate (AgentAuth verifies it later).
// These tests build the router with api.SetupRouter and the listener with
// newAgentMTLSServer, the two calls main makes, serve it over real TLS, and
// present a self-signed client certificate: the attacker D2 describes.

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/api"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/http/agentlistenertest"
)

const (
	guardBody = `{"error":"not found"}`
	// AgentAuth's answer to a certificate whose CN is not the claimed agent:
	// proof the request was routed to an AgentAuth route and entered its chain.
	agentAuthCNMismatch = "mTLS certificate CN does not match agent id"
)

var (
	pathAgentID  = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	clientCertCN = uuid.MustParse("33333333-3333-4333-8333-333333333333")
)

// wantAgentRoutes is the listener's entire surface, with the device-agent
// call that uses each. A change here is a change to what a self-signed client
// certificate can reach without the edge in front: review it as one.
var wantAgentRoutes = []string{
	"POST /api/v1/device-interrogation-service/agents/host-inventory",          // device-agent/internal/api/host_inventory.go SubmitHostInventory
	"GET /api/v1/device-interrogation-service/agents/:id/jobs",                 // device-agent/internal/api/client.go GetNextJob
	"POST /api/v1/device-interrogation-service/agents/:id/results",             // client.go SubmitResult (and ReportJobError)
	"POST /api/v1/device-interrogation-service/agents/:id/heartbeat",           // client.go SendHeartbeat (desired config + restart ride its response)
	"POST /api/v1/device-interrogation-service/agents/:id/certificates/rotate", // device-agent/internal/api/certificate_rotation.go RotateCertificate
}

// clientCallsNotOnTheListener are device-agent calls that deliberately do NOT
// use the passthrough listener. Each must still exist in the client (a stale
// entry fails the test).
var clientCallsNotOnTheListener = map[string]string{
	"Register POST /api/v1/device-interrogation-service/agents/register": "enrolment: the agent holds no client certificate yet, so it registers on the edge host; the response hands it the passthrough URL",
}

func newTestRouter(t *testing.T) (*gin.Engine, *sharedhttp.AgentRoutes, *config.Config) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	// SetupRouter's handlers call config.Load, which refuses a config without
	// an encryption key.
	t.Setenv("ENCRYPTION_MASTER_KEY", "agent-listener-test-key")
	t.Setenv("NATS_URL", "")
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")

	// A lazy handle that never connects: these tests are about routing, and
	// every agent request is answered by AgentAuth before any query.
	db, err := sql.Open("postgres", "postgres://invalid:invalid@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("opening a lazy handle: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	certPath, keyPath := agentlistenertest.WriteServerCert(t)
	cfg := &config.Config{
		JWTSecret:         "agent-listener-test",
		AgentMTLSRequired: true,
		AgentTLSPort:      "0",
		ServiceCertPath:   certPath,
		ServiceKeyPath:    keyPath,
	}
	router, agentRoutes := api.SetupRouter(cfg, db, db, nil)
	return router, agentRoutes, cfg
}

func startListener(t *testing.T) (*gin.Engine, *sharedhttp.AgentRoutes, *agentlistenertest.Listener) {
	t.Helper()
	router, agentRoutes, cfg := newTestRouter(t)
	srv, err := newAgentMTLSServer(cfg, router, agentRoutes)
	if err != nil {
		t.Fatalf("newAgentMTLSServer: %v", err)
	}
	return router, agentRoutes, agentlistenertest.Serve(t, srv, clientCertCN.String())
}

// concretePath fills a gin route pattern with test values.
func concretePath(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, ":"):
			segs[i] = pathAgentID.String()
		case strings.HasPrefix(s, "*"):
			segs[i] = "x"
		}
	}
	return strings.Join(segs, "/")
}

func newRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The identity claim of the routes without an :id (host inventory).
	req.Header.Set("X-Agent-ID", pathAgentID.String())
	return req
}

func do(t *testing.T, l *agentlistenertest.Listener, method, path string) (int, string) {
	t.Helper()
	resp, err := l.Client.Do(newRequest(t, method, l.URL+path))
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// Every route on the engine, driven over the listener: the agent routes reach
// AgentAuth; everything else is the guard's 404. The same request without the
// listener (the mesh/HTTP path) is NOT the guard's answer, so each 404 is the
// listener confining the route, not a route that does not exist.
func TestAgentMTLSListener_ServesOnlyAgentRoutes(t *testing.T) {
	router, agentRoutes, l := startListener(t)

	routes := router.Routes()
	if len(routes) < 40 {
		t.Fatalf("SetupRouter registered only %d routes; the test is not looking at the real router", len(routes))
	}
	agentSeen := 0
	for _, r := range routes {
		path := concretePath(r.Path)
		code, body := do(t, l, r.Method, path)
		if agentRoutes.Allows(r.Method, r.Path) {
			agentSeen++
			if code != http.StatusUnauthorized || !strings.Contains(body, agentAuthCNMismatch) {
				t.Errorf("agent route %s %s over the listener = %d %q; want AgentAuth's %q (the route must stay reachable)", r.Method, r.Path, code, body, agentAuthCNMismatch)
			}
			continue
		}
		if code != http.StatusNotFound || body != guardBody {
			t.Errorf("non-agent route %s %s over the listener = %d %q; want the guard's 404", r.Method, r.Path, code, body)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(r.Method, path, strings.NewReader("{}")))
		if rec.Code == http.StatusNotFound && rec.Body.String() == guardBody {
			t.Errorf("%s %s answers the guard's 404 off the listener too; the guard must be a no-op there", r.Method, r.Path)
		}
	}
	if agentSeen != len(wantAgentRoutes) {
		t.Errorf("drove %d agent routes, want %d", agentSeen, len(wantAgentRoutes))
	}
}

// The routes D2 names, spelled out, plus path tricks the edge would normally
// see first. Each must be registered (so the loop above covered it) and must
// not reach its handler chain over the listener.
func TestAgentMTLSListener_RefusesAdminInternalAndTenantRoutes(t *testing.T) {
	router, _, l := startListener(t)
	registered := map[string]bool{}
	for _, r := range router.Routes() {
		registered[r.Method+" "+r.Path] = true
	}
	for _, rt := range []string{
		"GET /api/v1/device-interrogation-service/admin/agents",          // platform-admin plane (cross-tenant)
		"POST /api/v1/device-interrogation-service/admin/jobs/:id/retry", // platform-admin repair
		"POST /internal/enrichment/refresh",                              // HMAC-only internal route
		"GET /api/v1/device-interrogation-service/agents",                // tenant UI API under the agent prefix
		"GET /api/v1/device-interrogation-service/agents/:id/config",     // tenant UI API under the agent prefix
		"GET /api/v1/device-interrogation-service/devices",               // tenant UI API
		"POST /api/v1/device-interrogation-service/agents/register",      // enrolment is edge-only
		"GET /health",
		"GET /ready",
	} {
		if !registered[rt] {
			t.Errorf("%s is not registered; update this table", rt)
			continue
		}
		method, pattern, _ := strings.Cut(rt, " ")
		if code, body := do(t, l, method, concretePath(pattern)); code != http.StatusNotFound || body != guardBody {
			t.Errorf("%s over the listener = %d %q, want the guard's 404", rt, code, body)
		}
	}

	for _, path := range []string{
		"/internal/enrichment/refresh/",
		"/api/v1/device-interrogation-service/agents/" + pathAgentID.String() + "/../../../../../internal/enrichment/refresh",
		"//api/v1/device-interrogation-service/admin/agents",
		"/api/v1/device-interrogation-service/admin/agents/",
	} {
		code, body := do(t, l, http.MethodPost, path)
		// A trailing-slash redirect is gin answering before any handler; the
		// client does not follow it, and its target is refused above.
		if code != http.StatusNotFound && code != http.StatusTemporaryRedirect && code != http.StatusMovedPermanently {
			t.Errorf("POST %s over the listener = %d %q, want 404 or a redirect", path, code, body)
		}
	}
}

func TestAgentMTLSListener_RouteSurfaceIsReviewed(t *testing.T) {
	_, agentRoutes, _ := newTestRouter(t)
	var got []string
	for _, r := range agentRoutes.Routes() {
		got = append(got, r.String())
	}
	want := append([]string(nil), wantAgentRoutes...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the agent-mTLS listener's routes changed.\n got:\n  %s\nwant:\n  %s\nUpdate wantAgentRoutes only for an AgentAuth route a device agent calls.",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// Every call the device-agent (and sensor) binaries make to
// device-interrogation-service is either served by the listener with the same
// method, or is a listed call that deliberately is not. A new agent call
// missing from SetupRouter's agentRoutes fails here instead of 404ing in the
// field.
func TestAgentMTLSListener_ServesEveryDeviceAgentCall(t *testing.T) {
	_, agentRoutes, _ := newTestRouter(t)
	calls := agentlistenertest.ScanClientCalls(t, "/api/v1/device-interrogation-service/", "../../../device-agent", "../../../sensor")
	if len(calls) < 6 {
		t.Fatalf("found only %d device-agent calls; the scan is not reading the device-agent client", len(calls))
	}
	used := map[string]bool{}
	for _, call := range calls {
		key := call.Func + " " + call.Method + " " + call.Format
		if _, ok := clientCallsNotOnTheListener[key]; ok {
			used[key] = true
			continue
		}
		served := false
		for _, r := range agentRoutes.Routes() {
			if r.Method == call.Method && agentlistenertest.FormatMatchesRoute(call.Format, r.Path) {
				served = true
				break
			}
		}
		if !served {
			t.Errorf("%s: %s %s %s is not served by the agent-mTLS listener; register its route through agentRoutes in api.SetupRouter (or, if it is pre-enrolment, list it in clientCallsNotOnTheListener)",
				call.Pos, call.Func, call.Method, call.Format)
		}
	}
	for key := range clientCallsNotOnTheListener {
		if !used[key] {
			t.Errorf("clientCallsNotOnTheListener lists %q, which the device agent no longer makes; remove it", key)
		}
	}
}
