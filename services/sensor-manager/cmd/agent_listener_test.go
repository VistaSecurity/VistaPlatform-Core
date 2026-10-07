package main

// The sensor-mTLS passthrough listener (pentest-readiness D2). It is reached
// by TCP passthrough, so no edge deny, rate limit or body limit applies, and
// its handshake accepts ANY client certificate (SensorAuth verifies it later).
// These tests build the router with setupRouter and the listener with
// newSensorMTLSServer, the two calls main makes, serve it over real TLS, and
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

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/handlers"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/http/agentlistenertest"
)

const (
	guardBody = `{"error":"not found"}`
	// SensorAuth's answer to a certificate whose CN is not the path's sensor:
	// proof the request was routed to a SensorAuth route and entered its chain.
	sensorAuthCNMismatch = "mTLS certificate CN does not match sensor_id"
)

var (
	pathSensorID = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	otherParamID = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	clientCertCN = uuid.MustParse("33333333-3333-4333-8333-333333333333")
)

// wantAgentRoutes is the listener's entire surface, with the sensor call that
// uses each. A change here is a change to what a self-signed client
// certificate can reach without the edge in front: review it as one.
var wantAgentRoutes = []string{
	"POST /api/v1/sensor-manager/sensors/:sensor_id/heartbeat",                       // sensor/internal/api/outbound_client.go Heartbeat (commands ride its response)
	"GET /api/v1/sensor-manager/sensors/:sensor_id/commands/poll",                    // older sensors; no current caller
	"POST /api/v1/sensor-manager/sensors/:sensor_id/commands/:command_id/ack",        // outbound_client.go AcknowledgeCommand
	"GET /api/v1/sensor-manager/sensors/:sensor_id/webhook-config",                   // older sensors; no current caller
	"POST /api/v1/sensor-manager/sensors/:sensor_id/discoveries",                     // outbound_client.go / sensor_manager.go SubmitDiscoveries
	"POST /api/v1/sensor-manager/sensors/:sensor_id/discovery-jobs/:job_id/complete", // outbound_client.go CompleteDiscoveryJob
	"POST /api/v1/sensor-manager/sensors/:sensor_id/discovery-jobs/:job_id/units",    // outbound_client.go ReportDiscoveryJobUnits
	"POST /api/v1/sensor-manager/sensors/:sensor_id/certificates/rotate",             // sensor/internal/api/certificate_rotation.go RotateCertificate
	"POST /api/v1/sensor-manager/sensors/:sensor_id/exports",                         // air-gapped export; no current caller
	"POST /api/v1/sensor-manager/sensors/:sensor_id/health",                          // sensor_manager.go ReportHealth (legacy)
	"GET /api/v1/sensor-manager/sensors/:sensor_id/config",                           // outbound_client.go / sensor_manager.go GetConfig (legacy)
}

// clientCallsNotOnTheListener are sensor calls that deliberately do NOT use
// the passthrough listener. Each must still exist in the client (a stale entry
// fails the test).
var clientCallsNotOnTheListener = map[string]string{
	"Register POST /api/v1/sensor-manager/sensors/register":          "enrolment: the sensor holds no client certificate yet, so it registers on the edge host; the response hands it the passthrough URL",
	"PollForCommands GET /api/v1/sensor-manager/sensors/%s/commands": "dead code (no caller); targets the tenant-JWT management route, which no sensor credential can pass; commands arrive in the heartbeat response",
}

func newTestRouter(t *testing.T) (*gin.Engine, *sharedhttp.AgentRoutes, *config.Config) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	t.Setenv("RESOURCE_TRACKER_URL", "http://127.0.0.1:1")

	// A lazy handle that never connects: these tests are about routing, and
	// every agent request is answered by SensorAuth before any query.
	db, err := sql.Open("postgres", "postgres://invalid:invalid@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("opening a lazy handle: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	certPath, keyPath := agentlistenertest.WriteServerCert(t)
	cfg := &config.Config{
		JWTSecret:           "agent-listener-test",
		EncryptionMasterKey: "agent-listener-test-key",
		SensorMTLSRequired:  true,
		AgentTLSPort:        "0",
		ServiceCertPath:     certPath,
		ServiceKeyPath:      keyPath,
	}
	handler := handlers.NewHandlerWithBoth(services.NewSensorService(db, db), nil, nil, db, db)
	router, agentRoutes := setupRouter(cfg, handler, db, db)
	return router, agentRoutes, cfg
}

func startListener(t *testing.T) (*gin.Engine, *sharedhttp.AgentRoutes, *agentlistenertest.Listener) {
	t.Helper()
	router, agentRoutes, cfg := newTestRouter(t)
	srv, err := newSensorMTLSServer(cfg, router, agentRoutes)
	if err != nil {
		t.Fatalf("newSensorMTLSServer: %v", err)
	}
	return router, agentRoutes, agentlistenertest.Serve(t, srv, clientCertCN.String())
}

// concretePath fills a gin route pattern with test values.
func concretePath(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, s := range segs {
		switch {
		case s == ":sensor_id":
			segs[i] = pathSensorID.String()
		case strings.HasPrefix(s, ":"):
			segs[i] = otherParamID.String()
		case strings.HasPrefix(s, "*"):
			segs[i] = "x"
		}
	}
	return strings.Join(segs, "/")
}

func do(t *testing.T, l *agentlistenertest.Listener, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, l.URL+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.Client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// Every route on the engine, driven over the listener: the agent routes reach
// SensorAuth; everything else is the guard's 404. The same request without the
// listener (the mesh/HTTP path) is NOT the guard's answer, so each 404 is the
// listener confining the route, not a route that does not exist.
func TestSensorMTLSListener_ServesOnlyAgentRoutes(t *testing.T) {
	router, agentRoutes, l := startListener(t)

	routes := router.Routes()
	if len(routes) < 30 {
		t.Fatalf("setupRouter registered only %d routes; the test is not looking at the real router", len(routes))
	}
	agentSeen := 0
	for _, r := range routes {
		path := concretePath(r.Path)
		code, body := do(t, l, r.Method, path)
		if agentRoutes.Allows(r.Method, r.Path) {
			agentSeen++
			if code != http.StatusUnauthorized || !strings.Contains(body, sensorAuthCNMismatch) {
				t.Errorf("agent route %s %s over the listener = %d %q; want SensorAuth's %q (the route must stay reachable)", r.Method, r.Path, code, body, sensorAuthCNMismatch)
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
func TestSensorMTLSListener_RefusesAdminInternalAndTenantRoutes(t *testing.T) {
	router, _, l := startListener(t)
	registered := map[string]bool{}
	for _, r := range router.Routes() {
		registered[r.Method+" "+r.Path] = true
	}
	for _, rt := range []string{
		"GET /api/v1/sensor-manager/admin/sensors",                   // platform-admin plane (cross-tenant fleet)
		"GET /api/v1/sensor-manager/platform/sensor-stats",           // platform plane
		"POST /api/v1/sensor-manager/internal/pcap/jobs/:id/results", // HMAC-only internal route
		"GET /api/v1/sensor-manager/sensors",                         // tenant UI API
		"GET /api/v1/sensor-manager/sensors/:sensor_id/commands",     // tenant UI API under the sensor prefix
		"POST /api/v1/sensor-manager/sensors/:sensor_id/certificates/revoke",
		"POST /api/v1/sensor-manager/sensors/register", // enrolment is edge-only
		"POST /api/v1/sensor-manager/sensors/auto-register",
		"GET /health",
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

	internal := "/api/v1/sensor-manager/internal/pcap/jobs/" + otherParamID.String() + "/results"
	for _, path := range []string{
		internal + "/",
		"/api/v1/sensor-manager/sensors/" + pathSensorID.String() + "/../../internal/pcap/jobs/" + otherParamID.String() + "/results",
		"//api/v1/sensor-manager/admin/sensors",
		"/api/v1/sensor-manager/admin/sensors/",
	} {
		code, body := do(t, l, http.MethodPost, path)
		// A trailing-slash redirect is gin answering before any handler; the
		// client does not follow it, and its target is refused above.
		if code != http.StatusNotFound && code != http.StatusTemporaryRedirect && code != http.StatusMovedPermanently {
			t.Errorf("POST %s over the listener = %d %q, want 404 or a redirect", path, code, body)
		}
	}
}

func TestSensorMTLSListener_RouteSurfaceIsReviewed(t *testing.T) {
	_, agentRoutes, _ := newTestRouter(t)
	var got []string
	for _, r := range agentRoutes.Routes() {
		got = append(got, r.String())
	}
	want := append([]string(nil), wantAgentRoutes...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the sensor-mTLS listener's routes changed.\n got:\n  %s\nwant:\n  %s\nUpdate wantAgentRoutes only for a SensorAuth route a sensor calls.",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// Every call the sensor (and device-agent) binaries make to sensor-manager is
// either served by the listener with the same method, or is a listed call
// that deliberately is not. A new sensor call missing from setupRouter's
// agentRoutes fails here instead of 404ing in the field.
func TestSensorMTLSListener_ServesEverySensorCall(t *testing.T) {
	_, agentRoutes, _ := newTestRouter(t)
	calls := agentlistenertest.ScanClientCalls(t, "/api/v1/sensor-manager/", "../../../sensor", "../../../device-agent")
	if len(calls) < 10 {
		t.Fatalf("found only %d sensor calls; the scan is not reading the sensor client", len(calls))
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
			t.Errorf("%s: %s %s %s is not served by the sensor-mTLS listener; register its route through agentRoutes in setupRouter (or, if it is pre-enrolment, list it in clientCallsNotOnTheListener)",
				call.Pos, call.Func, call.Method, call.Format)
		}
	}
	for key := range clientCallsNotOnTheListener {
		if !used[key] {
			t.Errorf("clientCallsNotOnTheListener lists %q, which the sensor no longer makes; remove it", key)
		}
	}
}
