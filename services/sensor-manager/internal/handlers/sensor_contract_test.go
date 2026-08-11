package handlers

// Contract test for the tenant sensor-lifecycle HTTP surface.
//
// The Operations-area vertical slice for the spec-first API contract
// (ADR-0001), after the inventory / compliance / cbom / auth slices. It
// exercises the REAL gin handlers over httptest (with an in-memory stub
// SensorRepository, no database) and asserts that every response body conforms
// to the schema declared in api/openapi/sensor-manager.openapi.yaml.
//
// No production refactor was needed: the handlers reach their data through the
// existing database.SensorRepository interface (directly for commands/health,
// and via services.SensorServiceV2 for the sensor + pending lifecycle), so a
// single stub repo drives the whole slice.
//
// OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so we validate response bodies
// directly with santhosh-tekuri/jsonschema/v6 — same approach as the other
// contract tests. If a handler's response shape drifts from the spec (a
// renamed field, a new required key, a wrong type), the matching test fails.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"gopkg.in/yaml.v3"
)

const specBaseURI = "https://vistaplatform.local/sensor-manager.openapi.yaml"

// --- spec loading + response validation -----------------------------------

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// handlers -> internal -> sensor-manager -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "sensor-manager.openapi.yaml",
	)
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec %s: %v", specPath, err)
	}
	// YAML -> generic -> JSON -> canonical form jsonschema expects.
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
	if err := c.AddResource(specBaseURI, doc); err != nil {
		t.Fatalf("add spec resource: %v", err)
	}
	return &specValidator{compiler: c}
}

// assertConforms validates that body matches #/components/schemas/<schemaName>.
func (sv *specValidator) assertConforms(t *testing.T, schemaName string, body []byte) {
	t.Helper()
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/" + schemaName)
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

// --- in-memory stub SensorRepository --------------------------------------

// testTenantID is the tenant the harness injects into the gin context; the
// stub returns pending sensors owned by it so the tenant-ownership checks in
// SensorServiceV2 pass.
var testTenantID = uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

// stubSensorRepo satisfies database.SensorRepository. Only the methods this
// slice exercises carry behavior; the rest are no-ops present to satisfy the
// interface.
type stubSensorRepo struct {
	sensors        []*models.Sensor
	getSensor      *models.Sensor
	getSensorErr   error
	forTenantErr   error
	updateStErr    error
	deleteErr      error
	pendings       []*models.PendingSensorRegistration
	getPendingKey  *models.PendingSensorRegistration
	getPendingErr  error
	commands       []*models.SensorCommand
	createCmdErr   error
	health         *models.SensorHealthMetrics
	healthErr      error
	healthHistory  []*models.SensorHealthMetrics
	historyErr     error
	discoveries    []*models.SensorDiscovery
	discoveriesErr error
}

// Sensors
func (s *stubSensorRepo) CreateSensor(context.Context, *models.Sensor) error { return nil }
func (s *stubSensorRepo) GetSensorByID(_ context.Context, _ uuid.UUID) (*models.Sensor, error) {
	return s.getSensor, s.getSensorErr
}

// GetSensorByIDForTenant mirrors the real tenant-scoped read. When
// forTenantErr is set it simulates a cross-tenant / missing sensor; otherwise
// it returns the same fixture as GetSensorByID.
func (s *stubSensorRepo) GetSensorByIDForTenant(_ context.Context, _, _ uuid.UUID) (*models.Sensor, error) {
	if s.forTenantErr != nil {
		return nil, s.forTenantErr
	}
	return s.getSensor, s.getSensorErr
}
func (s *stubSensorRepo) ListSensorsByTenant(_ context.Context, _ uuid.UUID) ([]*models.Sensor, error) {
	return s.sensors, nil
}
func (s *stubSensorRepo) UpdateSensor(context.Context, *models.Sensor) error { return nil }
func (s *stubSensorRepo) UpdateSensorStatus(_ context.Context, _, _ uuid.UUID, _ string) error {
	return s.updateStErr
}
func (s *stubSensorRepo) UpdateSensorHeartbeat(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (s *stubSensorRepo) DeleteSensor(_ context.Context, _, _ uuid.UUID) error { return s.deleteErr }

// Pending Sensors
func (s *stubSensorRepo) CreatePendingSensor(context.Context, *models.PendingSensorRegistration) error {
	return nil
}
func (s *stubSensorRepo) GetPendingSensorByKey(_ context.Context, _ string) (*models.PendingSensorRegistration, error) {
	return s.getPendingKey, s.getPendingErr
}
func (s *stubSensorRepo) ListPendingSensorsByTenant(_ context.Context, _ uuid.UUID) ([]*models.PendingSensorRegistration, error) {
	return s.pendings, nil
}
func (s *stubSensorRepo) UpdatePendingSensorStatus(context.Context, string, string) error { return nil }
func (s *stubSensorRepo) DeletePendingSensor(context.Context, string) error               { return nil }
func (s *stubSensorRepo) ExpirePendingSensors(context.Context) error                      { return nil }

// Commands
func (s *stubSensorRepo) CreateCommand(_ context.Context, _ *models.SensorCommand) error {
	return s.createCmdErr
}
func (s *stubSensorRepo) GetPendingCommands(_ context.Context, _ uuid.UUID) ([]*models.SensorCommand, error) {
	return s.commands, nil
}
func (s *stubSensorRepo) GetRecentCommands(_ context.Context, _ uuid.UUID, _ int) ([]*models.SensorCommand, error) {
	return s.commands, nil
}
func (s *stubSensorRepo) UpdateCommandStatus(context.Context, uuid.UUID, string) error { return nil }

// Health
func (s *stubSensorRepo) RecordHealthMetrics(context.Context, *models.SensorHealthMetrics) error {
	return nil
}
func (s *stubSensorRepo) GetLatestHealthMetrics(_ context.Context, _ uuid.UUID) (*models.SensorHealthMetrics, error) {
	return s.health, s.healthErr
}
func (s *stubSensorRepo) GetHealthMetricsHistory(context.Context, uuid.UUID, time.Time, int) ([]*models.SensorHealthMetrics, error) {
	return s.healthHistory, s.historyErr
}
func (s *stubSensorRepo) ListSensorDiscoveries(context.Context, uuid.UUID, int) ([]*models.SensorDiscovery, error) {
	return s.discoveries, s.discoveriesErr
}

// --- test harness ----------------------------------------------------------

// newEngine wires the real sensor handlers under /api/v1/sensor-manager with a
// middleware that injects tenantID as uuid.UUID, the way the real JWT
// middleware does. The Handler is built with the V2 service (backed by the
// stub repo) plus the same stub as the direct repo dependency; the legacy
// sensorService is left nil — the discovery-counts and create-pending handlers
// short-circuit on that, which is exactly the path this slice pins.
func newEngine(repo *stubSensorRepo) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	h := &Handler{
		sensorServiceV2: services.NewSensorServiceV2(repo),
		repo:            repo,
		log:             logrus.New(),
	}

	grp := r.Group("/api/v1/sensor-manager")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", testTenantID)
		c.Set("userID", uuid.New())
		c.Next()
	})

	grp.GET("/sensors", h.GetSensors)
	grp.GET("/sensors/stats", h.GetSensorStats)
	grp.GET("/sensors/discovery-counts", h.GetSensorDiscoveryCounts)
	grp.GET("/sensors/:sensor_id", h.GetSensor)
	grp.PUT("/sensors/:sensor_id/status", h.UpdateSensorStatus)
	grp.DELETE("/sensors/:sensor_id", h.DeleteSensor)
	grp.POST("/sensors/:sensor_id/commands", h.CreateSensorCommand)
	grp.GET("/sensors/:sensor_id/commands", h.GetSensorCommands)
	grp.GET("/sensors/:sensor_id/health", h.GetSensorHealth)
	grp.GET("/sensors/:sensor_id/health/history", h.GetSensorHealthHistory)
	grp.GET("/sensors/:sensor_id/discoveries", h.GetSensorDiscoveries)
	grp.GET("/sensors/pending", h.GetPendingSensors)
	grp.POST("/sensors/pending", h.CreatePendingSensor)
	grp.DELETE("/sensors/pending/:key", h.DeletePendingSensor)
	grp.GET("/admin/settings", h.GetAdminSettings)
	grp.PUT("/admin/settings", h.UpdateAdminSettings)
	grp.PUT("/admin/capture-defaults", h.UpdateTenantCaptureDefaults)
	return r
}

func do(engine *gin.Engine, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func strPtr(s string) *string { return &s }

// sampleSensor sets the always-present nullable pointer fields, so the body
// exercises the spec's [string,"null"] unions on the populated side.
func sampleSensor() *models.Sensor {
	now := time.Now().UTC()
	return &models.Sensor{
		ID:                uuid.New(),
		TenantID:          testTenantID,
		Name:              "edge-sensor-01",
		SensorType:        "network",
		Description:       strPtr("rack 4 span port"),
		Platform:          "linux",
		Version:           "1.4.2",
		Profile:           "datacenter_host",
		Status:            "active",
		NetworkInterfaces: []string{"eth0"},
		Tags:              []string{"dc-east"},
		IPAddress:         strPtr("10.0.0.5"),
		LastHeartbeat:     &now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// nullFieldsSensor leaves the nullable pointer fields nil, so the response
// serializes description/ip_address/last_heartbeat/deleted_at as JSON null —
// proving the spec's required-but-nullable keys hold.
func nullFieldsSensor() *models.Sensor {
	now := time.Now().UTC()
	return &models.Sensor{
		ID:         uuid.New(),
		TenantID:   testTenantID,
		Name:       "air-gapped-02",
		SensorType: "endpoint",
		Platform:   "windows",
		Version:    "1.4.2",
		Profile:    "air_gapped",
		Status:     "offline",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

func samplePending() *models.PendingSensorRegistration {
	now := time.Now().UTC()
	return &models.PendingSensorRegistration{
		ID:                uuid.New(),
		TenantID:          testTenantID,
		RegistrationKey:   "REG-deadbeefdeadbeefdeadbeefdeadbeef",
		Name:              "pending-sensor-09",
		IPAddress:         "10.0.0.9",
		Profile:           "cloud_instance",
		NetworkInterfaces: []string{"eth0"},
		Tags:              []string{"staging"},
		Description:       strPtr("awaiting enrolment"),
		Status:            "pending",
		ExpiresAt:         now.Add(24 * time.Hour),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func sampleCommand() *models.SensorCommand {
	return &models.SensorCommand{
		ID:          uuid.New(),
		SensorID:    uuid.New(),
		CommandType: "rescan",
		Payload:     map[string]interface{}{"depth": "full"},
		Status:      "pending",
		CreatedAt:   time.Now().UTC(),
	}
}

func sampleHealth() *models.SensorHealthMetrics {
	return &models.SensorHealthMetrics{
		ID:               uuid.New(),
		SensorID:         uuid.New(),
		UptimeSeconds:    3600,
		MemoryUsageBytes: 1024 * 1024 * 64,
		CPUUsagePercent:  12.5,
		PacketsCaptured:  98765,
		DiscoveriesMade:  42,
		ErrorsCount:      0,
		RecordedAt:       time.Now().UTC(),
	}
}

const aUUID = "11111111-1111-1111-1111-111111111111"
const base = "/api/v1/sensor-manager"

// --- the contract tests ----------------------------------------------------

func TestContract_ListSensors_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{sensors: []*models.Sensor{sampleSensor(), nullFieldsSensor()}})
	w := do(eng, http.MethodGet, base+"/sensors", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SensorListResponse", w.Body.Bytes())
}

func TestContract_GetSensorStats_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{sensors: []*models.Sensor{sampleSensor(), nullFieldsSensor()}})
	w := do(eng, http.MethodGet, base+"/sensors/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SensorStats", w.Body.Bytes())
}

func TestContract_DiscoveryCounts_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	w := do(eng, http.MethodGet, base+"/sensors/discovery-counts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DiscoveryCountsResponse", w.Body.Bytes())
}

func TestContract_GetSensor_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// The handler returns the sensor object bare (NOT wrapped under "sensor").
	sv.assertConforms(t, "Sensor", w.Body.Bytes())
}

func TestContract_GetSensor_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	w := do(eng, http.MethodGet, base+"/sensors/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// GetSensor maps ANY retrieval error (including no-rows) to 404 — a documented
// quirk captured by x-quirks in the spec.
func TestContract_GetSensor_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensorErr: io.EOF})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateSensorStatus_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	body := strings.NewReader(`{"status":"inactive"}`)
	w := do(eng, http.MethodPut, base+"/sensors/"+aUUID+"/status", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// A missing required status is rejected at bind time -> 400 LegacyError.
func TestContract_UpdateSensorStatus_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	body := strings.NewReader(`{}`)
	w := do(eng, http.MethodPut, base+"/sensors/"+aUUID+"/status", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteSensor_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	w := do(eng, http.MethodDelete, base+"/sensors/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_CreateSensorCommand_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	body := strings.NewReader(`{"command_type":"rescan","payload":{"depth":"full"}}`)
	w := do(eng, http.MethodPost, base+"/sensors/"+aUUID+"/commands", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SensorCommandResponse", w.Body.Bytes())
}

// Missing required command_type is rejected at bind time -> 400 LegacyError.
func TestContract_CreateSensorCommand_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	body := strings.NewReader(`{"payload":{"depth":"full"}}`)
	w := do(eng, http.MethodPost, base+"/sensors/"+aUUID+"/commands", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListSensorCommands_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor(), commands: []*models.SensorCommand{sampleCommand()}})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/commands", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SensorCommandListResponse", w.Body.Bytes())
}

func TestContract_GetSensorHealth_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor(), health: sampleHealth()})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// Health metrics are returned bare (NOT wrapped under "health").
	sv.assertConforms(t, "SensorHealthMetrics", w.Body.Bytes())
}

func TestContract_GetSensorHealth_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor(), healthErr: io.EOF})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/health", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListPendingSensors_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{pendings: []*models.PendingSensorRegistration{samplePending()}})
	w := do(eng, http.MethodGet, base+"/sensors/pending", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PendingSensorListResponse", w.Body.Bytes())
}

// CreatePendingSensor's success path is backed by the legacy sensorService (a
// concrete *sql.DB-bound service we deliberately leave nil); its input
// validation runs first, so we pin the 400 (invalid IP) path here. The 200
// shape is specced as-is and hardened when the endpoint moves to the repo path.
func TestContract_CreatePendingSensor_400_badIP(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	body := strings.NewReader(`{"name":"x","ip_address":"not-an-ip","profile":"cloud_instance"}`)
	w := do(eng, http.MethodPost, base+"/sensors/pending", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeletePendingSensor_200(t *testing.T) {
	sv := loadSpec(t)
	// V2 delete first fetches the key, then checks tenant ownership; return a
	// pending owned by the harness tenant so the delete succeeds.
	eng := newEngine(&stubSensorRepo{getPendingKey: samplePending()})
	w := do(eng, http.MethodDelete, base+"/sensors/pending/REG-deadbeef", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// A pending key owned by a different tenant -> 404 (service returns the exact
// "pending sensor does not belong to tenant" sentinel the handler maps to 404).
func TestContract_DeletePendingSensor_404(t *testing.T) {
	sv := loadSpec(t)
	other := samplePending()
	other.TenantID = uuid.New() // not testTenantID
	eng := newEngine(&stubSensorRepo{getPendingKey: other})
	w := do(eng, http.MethodDelete, base+"/sensors/pending/REG-deadbeef", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- admin settings + capture defaults -------------------------------------

func TestContract_GetAdminSettings_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	w := do(eng, http.MethodGet, base+"/admin/settings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AdminSettings", w.Body.Bytes())
}

func TestContract_UpdateAdminSettings_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	body := strings.NewReader(
		`{"key_expiration_minutes":120,"max_pending_sensors":25,"require_ip_validation":true}`)
	w := do(eng, http.MethodPut, base+"/admin/settings", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// An out-of-range key_expiration_minutes (handler enforces 5–1440) -> 400.
func TestContract_UpdateAdminSettings_400_outOfRange(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	body := strings.NewReader(
		`{"key_expiration_minutes":1,"max_pending_sensors":25,"require_ip_validation":false}`)
	w := do(eng, http.MethodPut, base+"/admin/settings", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateCaptureDefaults_200(t *testing.T) {
	sv := loadSpec(t)
	// One active sensor owned by the harness tenant -> one update_config command
	// queued, so sensors_queued is exercised on the non-zero side.
	eng := newEngine(&stubSensorRepo{sensors: []*models.Sensor{sampleSensor()}})
	body := strings.NewReader(`{"dedup_ttl_minutes":30}`)
	w := do(eng, http.MethodPut, base+"/admin/capture-defaults", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CaptureDefaultsResponse", w.Body.Bytes())
}

// Missing required dedup_ttl_minutes is rejected at bind time -> 400 LegacyError.
func TestContract_UpdateCaptureDefaults_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	body := strings.NewReader(`{}`)
	w := do(eng, http.MethodPut, base+"/admin/capture-defaults", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// With the sensor service unwired (nil sensorServiceV2/repo), capture-defaults
// returns 503 after binding — pins the LegacyError shape on that path.
func TestContract_UpdateCaptureDefaults_503(t *testing.T) {
	sv := loadSpec(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{log: logrus.New()} // sensorServiceV2 and repo deliberately nil
	grp := r.Group("/api/v1/sensor-manager")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", testTenantID)
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.PUT("/admin/capture-defaults", h.UpdateTenantCaptureDefaults)

	body := strings.NewReader(`{"dedup_ttl_minutes":30}`)
	w := do(r, http.MethodPut, base+"/admin/capture-defaults", body)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// TestContract_DriftIsCaught proves the guardrail actually validates: a body
// that drifts from the contract (a SensorCommand missing required fields, plus
// an undeclared field that additionalProperties:false forbids) MUST be
// rejected. If this ever passes, the validator is rubber-stamping.
func TestContract_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/SensorCommand")
	if err != nil {
		t.Fatalf("compile SensorCommand: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted SensorCommand, but it passed — the guardrail is not actually checking")
	}
}
