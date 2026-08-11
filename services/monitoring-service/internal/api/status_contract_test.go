package api

// Contract test for the tenant /status HTTP surface (Dashboard health widget +
// Operations system status).
//
// First slice for monitoring-service (ADR-0001). Four of the five handlers
// depend only on the HealthService; the fifth (/status/health/overview) made
// two direct *sql.DB calls. This slice landed a behaviour-preserving refactor
// first (healthService → healthStatusProvider interface; the two DB calls moved
// verbatim into the healthStore interface — see health_status_repository.go), so
// the real gin handlers run over httptest with in-memory stubs — no database —
// and their bodies are asserted against api/openapi/monitoring-service.openapi.yaml.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
	"gopkg.in/yaml.v3"
)

const statusSpecBaseURI = "https://vistaplatform.local/monitoring-service.openapi.yaml"
const statusBase = "/api/v1/monitoring-service"

var errPing = errors.New("db unreachable")

// --- spec loading + response validation -----------------------------------

type statusSpecValidator struct{ compiler *jsonschema.Compiler }

func statusLoadSpec(t *testing.T) *statusSpecValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// api -> internal -> monitoring-service -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "monitoring-service.openapi.yaml",
	)
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec %s: %v", specPath, err)
	}
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatalf("yaml unmarshal spec: %v", err)
	}
	jsonBytes, err := json.Marshal(asAny)
	if err != nil {
		t.Fatalf("re-marshal spec to json: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatalf("jsonschema unmarshal spec: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(statusSpecBaseURI, doc); err != nil {
		t.Fatalf("add spec resource: %v", err)
	}
	return &statusSpecValidator{compiler: c}
}

func (sv *statusSpecValidator) assertConforms(t *testing.T, schemaName string, body []byte) {
	t.Helper()
	sch, err := sv.compiler.Compile(statusSpecBaseURI + "#/components/schemas/" + schemaName)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaName, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unmarshal response body: %v\nbody: %s", err, string(body))
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("response violates schema %q:\n%v\n--- body ---\n%s", schemaName, err, string(body))
	}
}

func statusDo(engine *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, io.Reader(nil))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// --- in-memory stubs --------------------------------------------------------

type stubHealthProvider struct {
	status models.SystemStatusResponse
}

func (s *stubHealthProvider) GetSystemStatus() models.SystemStatusResponse { return s.status }
func (s *stubHealthProvider) GetTenantStatuses() ([]models.TenantStatus, error) {
	return nil, nil
}

type stubHealthStore struct {
	active    int
	total     int
	sensorErr error
	pingErr   error
}

func (s *stubHealthStore) GetSensorStats() (int, int, error) { return s.active, s.total, s.sensorErr }
func (s *stubHealthStore) PingDB() error                     { return s.pingErr }

func newStatusEngine(hp healthStatusProvider, store healthStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithHealth(hp, store)
	r := gin.New()
	grp := r.Group(statusBase + "/status")
	grp.GET("/system", srv.getSystemStatus)
	grp.GET("/metrics", srv.getSystemMetrics)
	grp.GET("/health/overview", srv.getHealthOverview)
	grp.GET("/services/:name", srv.getServiceStatus)
	grp.GET("/incidents", srv.getIncidentHistory)
	return r
}

func sampleSystemStatus() models.SystemStatusResponse {
	now := time.Now().UTC()
	return models.SystemStatusResponse{
		Status:        "ok",
		OverallStatus: "healthy",
		Services: []models.ServiceStatus{
			{Name: "auth-service", Status: "healthy", Message: "ok", ResponseTime: 12, LastCheck: now, LastChecked: now},
			{Name: "inventory-service", Status: "degraded", Message: "slow", ResponseTime: 240, LastCheck: now, LastChecked: now},
		},
		Metrics: models.SystemMetrics{
			CPUUsage: 12.5, MemoryUsage: 40.1, DiskUsage: 55.0, NetworkIO: 1000, Uptime: 86400,
			TotalServices: 16, HealthyServices: 15, DegradedServices: 1, DownServices: 0,
			AverageResponseTime: 42.0, TotalTenants: 5, ActiveTenants: 4, TotalUsers: 30, TotalAssets: 1200,
			LastUpdated: now,
		},
		Timestamp: now,
	}
}

func healthyStore() *stubHealthStore { return &stubHealthStore{active: 3, total: 5} }

// --- contract tests ---------------------------------------------------------

func TestContract_GetSystemStatus_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newStatusEngine(&stubHealthProvider{status: sampleSystemStatus()}, healthyStore())
	w := statusDo(eng, http.MethodGet, statusBase+"/status/system")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SystemStatusResponse", w.Body.Bytes())
}

func TestContract_GetSystemMetrics_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newStatusEngine(&stubHealthProvider{status: sampleSystemStatus()}, healthyStore())
	w := statusDo(eng, http.MethodGet, statusBase+"/status/metrics")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SystemMetrics", w.Body.Bytes())
}

func TestContract_GetHealthOverview_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newStatusEngine(&stubHealthProvider{status: sampleSystemStatus()}, healthyStore())
	w := statusDo(eng, http.MethodGet, statusBase+"/status/health/overview")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SystemHealthOverview", w.Body.Bytes())
}

// DB ping failing → database.status "down" + message set; still 200.
func TestContract_GetHealthOverview_200_dbDown(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newStatusEngine(&stubHealthProvider{status: sampleSystemStatus()},
		&stubHealthStore{active: 0, total: 0, pingErr: errPing})
	w := statusDo(eng, http.MethodGet, statusBase+"/status/health/overview")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SystemHealthOverview", w.Body.Bytes())
}

// Sensor-stats query failing is non-fatal (counts fall back to 0).
func TestContract_GetHealthOverview_200_sensorErr(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newStatusEngine(&stubHealthProvider{status: sampleSystemStatus()},
		&stubHealthStore{sensorErr: errPing})
	w := statusDo(eng, http.MethodGet, statusBase+"/status/health/overview")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SystemHealthOverview", w.Body.Bytes())
}

// Empty service list → overview.services is an empty (non-null) array.
func TestContract_GetHealthOverview_200_noServices(t *testing.T) {
	sv := statusLoadSpec(t)
	status := sampleSystemStatus()
	status.Services = nil
	eng := newStatusEngine(&stubHealthProvider{status: status}, healthyStore())
	w := statusDo(eng, http.MethodGet, statusBase+"/status/health/overview")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SystemHealthOverview", w.Body.Bytes())
}

func TestContract_GetServiceStatus_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newStatusEngine(&stubHealthProvider{status: sampleSystemStatus()}, healthyStore())
	w := statusDo(eng, http.MethodGet, statusBase+"/status/services/auth-service")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ServiceStatus", w.Body.Bytes())
}

func TestContract_GetServiceStatus_404(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newStatusEngine(&stubHealthProvider{status: sampleSystemStatus()}, healthyStore())
	w := statusDo(eng, http.MethodGet, statusBase+"/status/services/does-not-exist")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetIncidentHistory_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newStatusEngine(&stubHealthProvider{status: sampleSystemStatus()}, healthyStore())
	w := statusDo(eng, http.MethodGet, statusBase+"/status/incidents")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IncidentList", w.Body.Bytes())
}

// --- drift guards -----------------------------------------------------------

func TestContract_SystemStatusResponse_DriftIsCaught(t *testing.T) {
	sv := statusLoadSpec(t)
	sch, err := sv.compiler.Compile(statusSpecBaseURI + "#/components/schemas/SystemStatusResponse")
	if err != nil {
		t.Fatalf("compile SystemStatusResponse: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(`{"status":"ok","surprise_field":true}`)))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted SystemStatusResponse, but it passed — the guardrail is not actually checking")
	}
}

func TestContract_SystemHealthOverview_DriftIsCaught(t *testing.T) {
	sv := statusLoadSpec(t)
	sch, err := sv.compiler.Compile(statusSpecBaseURI + "#/components/schemas/SystemHealthOverview")
	if err != nil {
		t.Fatalf("compile SystemHealthOverview: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(`{"overall_status":"healthy","surprise_field":true}`)))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted SystemHealthOverview, but it passed — the guardrail is not actually checking")
	}
}
