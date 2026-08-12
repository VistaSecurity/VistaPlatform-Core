package handlers

// Contract test for the sensor config + interfaces mutations (Sensor
// Configuration page). Extends the sensor-manager spec-first contract
// (ADR-0001) and reuses the shared harness (loadSpec / assertConforms / do /
// strPtr / testTenantID) from sensor_contract_test.go.
//
// UpdateSensorInterfaces / UpdateSensorConfig depend on the legacy
// *services.SensorService (now narrowed to the legacySensorService interface so
// the concrete type still satisfies it), letting these tests drive the real
// handlers with an in-memory stub — no database.

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// --- stub legacySensorService ----------------------------------------------

// stubLegacySensorService satisfies legacySensorService. Only GetSensor /
// UpdateSensor (the methods the config + interfaces mutations call) carry
// behavior; the rest are no-ops present to satisfy the interface.
type stubLegacySensorService struct {
	getSensor    *models.Sensor
	getSensorErr error
	updateErr    error
	db           *sql.DB
	bypassDB     *sql.DB
}

func (s *stubLegacySensorService) GetSensor(uuid.UUID) (*models.Sensor, error) {
	return s.getSensor, s.getSensorErr
}
func (s *stubLegacySensorService) UpdateSensor(*models.Sensor) error { return s.updateErr }

func (s *stubLegacySensorService) AcknowledgeCommand(string, string, *models.CommandResponse) error {
	return nil
}
func (s *stubLegacySensorService) CountPendingSensors(uuid.UUID) (int, error) { return 0, nil }
func (s *stubLegacySensorService) CreatePendingSensor(*models.PendingSensorRegistration) error {
	return nil
}
func (s *stubLegacySensorService) DeletePendingSensor(string) error { return nil }
func (s *stubLegacySensorService) GetDB() *sql.DB                   { return s.db }
func (s *stubLegacySensorService) GetBypassDB() *sql.DB             { return s.bypassDB }
func (s *stubLegacySensorService) GetPendingCommands(string) ([]models.Command, error) {
	return nil, nil
}
func (s *stubLegacySensorService) GetPendingSensorByKey(string) (*models.PendingSensorRegistration, error) {
	return nil, nil
}
func (s *stubLegacySensorService) GetPendingSensors(uuid.UUID) ([]models.PendingSensorRegistration, error) {
	return nil, nil
}
func (s *stubLegacySensorService) GetSensorConfig(string) (*models.SensorConfig, error) {
	return nil, nil
}
func (s *stubLegacySensorService) GetWebhookConfig(string) (*models.WebhookConfig, error) {
	return nil, nil
}
func (s *stubLegacySensorService) MarkCommandsAsDelivered(string, []string) error { return nil }
func (s *stubLegacySensorService) RegisterSensor(*models.SensorRegistration) (*models.Sensor, error) {
	return nil, nil
}
func (s *stubLegacySensorService) StoreAirGappedExport(*models.AirGappedExport) error { return nil }
func (s *stubLegacySensorService) StoreDiscoveries(*models.DiscoveryBatch) error      { return nil }
func (s *stubLegacySensorService) UpdateSensorHealth(string, *models.SensorHealth) error {
	return nil
}
func (s *stubLegacySensorService) UpdateSensorHealthWithIP(string, *models.SensorHealth, *string) error {
	return nil
}
func (s *stubLegacySensorService) ReconcileSensorAddresses(context.Context, string, []sharednetwork.InterfaceAddress) error {
	return nil
}
func (s *stubLegacySensorService) ListSensorAddresses(context.Context, uuid.UUID, uuid.UUID) ([]models.AgentAddress, error) {
	return nil, nil
}

// newSensorConfigEngine mounts only the config + interfaces routes, with the
// legacy service stub injected (the shared newEngine leaves sensorService nil,
// which these handlers dereference).
func newSensorConfigEngine(legacy *stubLegacySensorService, repo *stubSensorRepo) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{
		sensorService: legacy,
		repo:          repo,
		log:           logrus.New(),
	}
	grp := r.Group("/api/v1/sensor-manager")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", testTenantID)
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.PUT("/sensors/:sensor_id/interfaces", h.UpdateSensorInterfaces)
	grp.PUT("/sensors/:sensor_id/config", h.UpdateSensorConfig)
	return r
}

func sampleConfigSensor() *models.Sensor {
	return &models.Sensor{
		ID:                uuid.New(),
		Profile:           "datacenter_host",
		Description:       strPtr("edge capture node"),
		Tags:              []string{"prod"},
		NetworkInterfaces: []string{"eth0"},
	}
}

// --- interfaces -------------------------------------------------------------

func TestContract_UpdateSensorInterfaces_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{getSensor: sampleConfigSensor()}, &stubSensorRepo{getSensor: sampleConfigSensor()})
	body := strings.NewReader(`{"add":["eth1"],"remove":["eth0"]}`)
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+aUUID+"/interfaces", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateSensorInterfacesResponse", w.Body.Bytes())
}

func TestContract_UpdateSensorInterfaces_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{}, &stubSensorRepo{})
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/not-a-uuid/interfaces", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateSensorInterfaces_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{getSensor: sampleConfigSensor()}, &stubSensorRepo{getSensor: sampleConfigSensor()})
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+aUUID+"/interfaces", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateSensorInterfaces_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{getSensorErr: sql.ErrNoRows}, &stubSensorRepo{})
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+aUUID+"/interfaces", strings.NewReader(`{"add":["eth1"]}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateSensorInterfaces_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{getSensor: sampleConfigSensor(), updateErr: sql.ErrConnDone}, &stubSensorRepo{getSensor: sampleConfigSensor()})
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+aUUID+"/interfaces", strings.NewReader(`{"add":["eth1"]}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- config -----------------------------------------------------------------

func TestContract_UpdateSensorConfig_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{getSensor: sampleConfigSensor()}, &stubSensorRepo{getSensor: sampleConfigSensor()})
	body := strings.NewReader(`{"air_gapped":true,"description":"moved","tags":["prod","edge"]}`)
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+aUUID+"/config", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateSensorConfigResponse", w.Body.Bytes())
}

// Capture-option changes additionally queue an update_config command via the
// repo; the response shape is unchanged. nil description/tags exercise the
// nullable union in the response schema.
func TestContract_UpdateSensorConfig_200_captureOptions(t *testing.T) {
	sv := loadSpec(t)
	sensor := &models.Sensor{ID: uuid.New(), Profile: "datacenter_host"} // nil Description + Tags
	eng := newSensorConfigEngine(&stubLegacySensorService{getSensor: sensor}, &stubSensorRepo{getSensor: sensor})
	body := strings.NewReader(`{"active_probing":true,"network_discovery":false,"dedup_ttl_minutes":30}`)
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+aUUID+"/config", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateSensorConfigResponse", w.Body.Bytes())
}

func TestContract_UpdateSensorConfig_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{}, &stubSensorRepo{})
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/not-a-uuid/config", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateSensorConfig_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{getSensorErr: sql.ErrNoRows}, &stubSensorRepo{})
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+aUUID+"/config", strings.NewReader(`{"air_gapped":true}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateSensorConfig_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newSensorConfigEngine(&stubLegacySensorService{getSensor: sampleConfigSensor(), updateErr: sql.ErrConnDone}, &stubSensorRepo{getSensor: sampleConfigSensor()})
	w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+aUUID+"/config", strings.NewReader(`{"air_gapped":true}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
