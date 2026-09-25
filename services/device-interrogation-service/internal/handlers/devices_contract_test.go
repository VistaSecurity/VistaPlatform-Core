package handlers

// Contract test for the devices read surface. Extends the
// device-interrogation-service spec-first contract (ADR-0001) and reuses the
// shared harness (loadSpec / assertConforms / do / strPtr / aUUID / base) from
// jobs_contract_test.go — only the device stub + engine + cases live here.
//
// DeviceHandlers was made testable by depending on the deviceStore interface
// for its deviceService field (the concrete *services.DeviceService still
// satisfies it), so these tests drive the real handlers with an in-memory stub
// — no database.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// deviceTestTenant is the tenant the harness injects; GetDevice enforces that
// the returned device belongs to it, so the stub device must carry the same id.
var deviceTestTenant = uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

// --- stub deviceStore ------------------------------------------------------

type stubDeviceStore struct {
	hostKeyPinResets   int
	hostKeyPinResetErr error
	list               []*models.Device
	listErr            error
	device             *models.Device
	devErr             error
	created            *models.Device
	createErr          error
	updated            *models.Device
	stored             services.StoredDeviceCredentials
	// createCalls / lastCreate record what reached CreateDevice, so a test can
	// assert that a failed probe created nothing.
	createCalls int
	lastCreate  models.CreateDeviceRequest
	// pins records PinSSHHostKeyIfUnset calls.
	pins []string
}

func (s *stubDeviceStore) PinSSHHostKeyIfUnset(_ context.Context, _, _ uuid.UUID, fingerprint, keyType string) (bool, error) {
	s.pins = append(s.pins, fingerprint+" "+keyType)
	return true, nil
}

func (s *stubDeviceStore) CreateDevice(_ context.Context, _ uuid.UUID, req models.CreateDeviceRequest) (*models.Device, error) {
	s.createCalls++
	s.lastCreate = req
	return s.created, s.createErr
}
func (s *stubDeviceStore) GetDevice(context.Context, uuid.UUID, uuid.UUID) (*models.Device, error) {
	return s.device, s.devErr
}
func (s *stubDeviceStore) ListDevices(context.Context, uuid.UUID) ([]*models.Device, error) {
	return s.list, s.listErr
}
func (s *stubDeviceStore) UpdateDevice(context.Context, uuid.UUID, uuid.UUID, models.UpdateDeviceRequest) (*models.Device, error) {
	return s.updated, nil
}
func (s *stubDeviceStore) DeleteDevice(context.Context, uuid.UUID, uuid.UUID) error { return nil }

func (s *stubDeviceStore) GetStoredDeviceCredentials(context.Context, uuid.UUID, uuid.UUID) (services.StoredDeviceCredentials, error) {
	return s.stored, nil
}

func (s *stubDeviceStore) ResetSSHHostKeyPin(context.Context, uuid.UUID, uuid.UUID) error {
	s.hostKeyPinResets++
	return s.hostKeyPinResetErr
}

type recordingJobCreator struct {
	reqs []models.CreateDeviceJobRequest
}

func (r *recordingJobCreator) CreateJob(_ context.Context, req models.CreateDeviceJobRequest) (*models.DeviceJob, error) {
	r.reqs = append(r.reqs, req)
	return &models.DeviceJob{ID: uuid.New(), JobType: req.JobType, Status: models.JobStatusPending}, nil
}

func newDeviceEngine(store *stubDeviceStore) *gin.Engine {
	return newDeviceEngineWithJobs(store, nil)
}

func newDeviceEngineWithJobs(store *stubDeviceStore, jobs jobCreator) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/device-interrogation-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", deviceTestTenant)
		c.Next()
	})
	h := &DeviceHandlers{deviceService: store, jobQueue: jobs}
	grp.GET("/devices", h.ListDevices)
	grp.POST("/devices", h.CreateDevice)
	grp.GET("/devices/:id", h.GetDevice)
	grp.PUT("/devices/:id", h.UpdateDevice)
	grp.DELETE("/devices/:id", h.DeleteDevice)
	grp.POST("/devices/:id/interrogate", h.InterrogateDevice)
	grp.POST("/devices/:id/test-connection", h.TestConnection)
	grp.DELETE("/devices/:id/ssh-host-key", h.ResetDeviceHostKeyPin)
	grp.POST("/devices/bulk-interrogate", h.BulkInterrogateDevices)
	grp.POST("/devices/discover-and-create", h.DiscoverAndCreateDevice)
	return r
}

func sampleDevice() *models.Device {
	now := time.Now().UTC()
	return &models.Device{
		ID:                    uuid.New(),
		TenantID:              deviceTestTenant,
		DeviceType:            "palo_alto",
		Vendor:                strPtr("Palo Alto Networks"),
		Model:                 strPtr("PA-3220"),
		Hostname:              strPtr("fw-01.example.com"),
		IPAddress:             strPtr("10.0.0.1"),
		ManagementURL:         strPtr("https://10.0.0.1"),
		SerialNumber:          strPtr("00123456"),
		FirmwareVersion:       strPtr("10.2.3"),
		DiscoveryMethod:       "device_interrogation",
		TLSInsecureSkipVerify: false,
		ConnectionStatus:      "connected",
		Metadata:              models.JSONB{"site": "hq"},
		Tags:                  models.JSONB{"env": "prod"},
		CreatedAt:             now,
		UpdatedAt:             now,
	}
}

// minimalDevice leaves the nullable pointer / JSONB fields nil (→ JSON null) and
// the omitempty creds unset (absent), proving the spec's required/nullable +
// optional handling holds.
func minimalDevice() *models.Device {
	now := time.Now().UTC()
	return &models.Device{
		ID:               uuid.New(),
		TenantID:         deviceTestTenant,
		DeviceType:       "f5",
		DiscoveryMethod:  "manual",
		ConnectionStatus: "unknown",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// --- the contract tests ----------------------------------------------------

func TestContract_ListDevices_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{list: []*models.Device{sampleDevice(), minimalDevice()}})
	w := do(eng, http.MethodGet, base+"/devices", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DeviceListResponse", w.Body.Bytes())
}

func TestContract_GetDevice_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{device: sampleDevice()})
	w := do(eng, http.MethodGet, base+"/devices/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Device", w.Body.Bytes())
}

func TestContract_GetDevice_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{})
	w := do(eng, http.MethodGet, base+"/devices/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A retrieval error maps to 404 (also covers the cross-tenant case).
func TestContract_GetDevice_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{devErr: context.DeadlineExceeded})
	w := do(eng, http.MethodGet, base+"/devices/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateDevice_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{created: sampleDevice()})
	w := do(eng, http.MethodPost, base+"/devices", strings.NewReader(`{"device_type":"f5"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Device", w.Body.Bytes())
}

func TestContract_CreateDevice_Retained202(t *testing.T) {
	for _, outcome := range []string{"unresolved", "conflict"} {
		t.Run(outcome, func(t *testing.T) {
			retained := &identity.RetainedObservation{Result: identity.IngestResult{Outcome: outcome, ObservationID: aUUID}}
			eng := newDeviceEngine(&stubDeviceStore{createErr: retained})
			w := do(eng, http.MethodPost, base+"/devices", strings.NewReader(`{"device_type":"f5"}`))
			if w.Code != http.StatusAccepted {
				t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
			}
			loadSpec(t).assertConforms(t, "RetainedDeviceObservation", w.Body.Bytes())
			if strings.Contains(w.Body.String(), "asset_id") {
				t.Fatal("retained evidence manufactured an asset ID")
			}
		})
	}
}

func TestContract_CreateDevice_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{})
	// Missing required device_type.
	w := do(eng, http.MethodPost, base+"/devices", strings.NewReader(`{"hostname":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateDeviceRejectsDisplayNameAsHostname(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{})
	w := do(eng, http.MethodPost, base+"/devices", strings.NewReader(`{"device_type":"unifi","hostname":"lab gateway"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), "Hostname cannot contain spaces") {
		t.Fatalf("body=%s, want actionable hostname message", w.Body.String())
	}
}

func TestContract_UpdateDevice_200(t *testing.T) {
	sv := loadSpec(t)
	// GetDevice (ownership) returns a tenant-owned device; UpdateDevice returns the updated one.
	eng := newDeviceEngine(&stubDeviceStore{device: sampleDevice(), updated: sampleDevice()})
	w := do(eng, http.MethodPut, base+"/devices/"+aUUID, strings.NewReader(`{"hostname":"renamed"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Device", w.Body.Bytes())
}

func TestContract_UpdateDevice_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{devErr: context.DeadlineExceeded})
	w := do(eng, http.MethodPut, base+"/devices/"+aUUID, strings.NewReader(`{"hostname":"x"}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteDevice_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{device: sampleDevice()})
	w := do(eng, http.MethodDelete, base+"/devices/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_Device_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/Device")
	if err != nil {
		t.Fatalf("compile Device: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted Device, but it passed — the guardrail is not actually checking")
	}
}

// --- device action mutations (validation paths) -----------------------------
//
// interrogate / test-connection / bulk-interrogate / discover-and-create all
// make live HTTP calls to the target device on their success path, so that is
// integration territory. Here we pin the request-validation paths that return
// before any device I/O.

func TestContract_InterrogateDevice_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{})
	w := do(eng, http.MethodPost, base+"/devices/not-a-uuid/interrogate", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_InterrogateDevice_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{devErr: context.DeadlineExceeded})
	w := do(eng, http.MethodPost, base+"/devices/"+aUUID+"/interrogate", strings.NewReader(`{}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_TestConnectionDevice_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{})
	w := do(eng, http.MethodPost, base+"/devices/not-a-uuid/test-connection", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_TestConnectionDevice_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{devErr: context.DeadlineExceeded})
	w := do(eng, http.MethodPost, base+"/devices/"+aUUID+"/test-connection", strings.NewReader(`{}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_BulkInterrogateDevices_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{})
	w := do(eng, http.MethodPost, base+"/devices/bulk-interrogate", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DiscoverAndCreateDevice_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newDeviceEngine(&stubDeviceStore{})
	w := do(eng, http.MethodPost, base+"/devices/discover-and-create", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- clearing the pinned SSH host key (H7) ---------------------------------
//
// These drive the REAL route, not the handler in isolation: the whole point of
// the endpoint is that it is reachable and tenant-scoped, and a test that
// called the method directly would stay green if the route were removed.

func TestContract_ResetDeviceHostKeyPin_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubDeviceStore{device: sampleDevice()}
	eng := newDeviceEngine(store)

	w := do(eng, http.MethodDelete, base+"/devices/"+aUUID+"/ssh-host-key", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
	if store.hostKeyPinResets != 1 {
		t.Fatalf("ResetSSHHostKeyPin calls = %d, want 1 — the route must actually clear the pin", store.hostKeyPinResets)
	}
}

// A device this tenant cannot see is a 404 AND must not have its pin cleared.
// Answering 404 while still clearing would let one tenant unpin another's
// device by guessing an id — the pin would silently vanish and the next
// interrogation would trust whatever answered.
func TestContract_ResetDeviceHostKeyPin_404_doesNotClear(t *testing.T) {
	sv := loadSpec(t)
	store := &stubDeviceStore{devErr: context.DeadlineExceeded}
	eng := newDeviceEngine(store)

	w := do(eng, http.MethodDelete, base+"/devices/"+aUUID+"/ssh-host-key", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if store.hostKeyPinResets != 0 {
		t.Fatalf("ResetSSHHostKeyPin was called %d time(s) for a device the tenant cannot see", store.hostKeyPinResets)
	}
}

func TestContract_ResetDeviceHostKeyPin_400_badID(t *testing.T) {
	sv := loadSpec(t)
	store := &stubDeviceStore{device: sampleDevice()}
	eng := newDeviceEngine(store)

	w := do(eng, http.MethodDelete, base+"/devices/not-a-uuid/ssh-host-key", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if store.hostKeyPinResets != 0 {
		t.Fatalf("ResetSSHHostKeyPin was called for an unparseable id")
	}
}

func TestContract_ResetDeviceHostKeyPin_500(t *testing.T) {
	sv := loadSpec(t)
	store := &stubDeviceStore{device: sampleDevice(), hostKeyPinResetErr: context.DeadlineExceeded}
	eng := newDeviceEngine(store)

	w := do(eng, http.MethodDelete, base+"/devices/"+aUUID+"/ssh-host-key", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
