package handlers

// Contract test for the remaining web-ui sensor surface: health-metrics history,
// recent discoveries, and the PCAP upload/job management endpoints. Extends the
// sensor-manager spec-first contract (ADR-0001) and reuses the shared harness
// (loadSpec / assertConforms / do / base / aUUID / testTenantID / sampleHealth)
// from sensor_contract_test.go.
//
// health-history + discoveries were rewired off the legacy sensorService.GetDB()
// inline SQL onto the SensorRepository (GetHealthMetricsHistory now takes a
// limit; ListSensorDiscoveries is new), so newEngine's stub repo drives them.
// pcap was narrowed from *services.PcapService to the pcapStore interface, so a
// small stub drives the pcap handlers — no database, no NATS.

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// --- health-metrics history -------------------------------------------------

func TestContract_GetSensorHealthHistory_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor(), healthHistory: []*models.SensorHealthMetrics{sampleHealth(), sampleHealth()}})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/health/history?limit=50", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SensorHealthHistoryResponse", w.Body.Bytes())
}

// Empty history still yields a valid (empty-array) response.
func TestContract_GetSensorHealthHistory_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/health/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SensorHealthHistoryResponse", w.Body.Bytes())
}

func TestContract_GetSensorHealthHistory_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	w := do(eng, http.MethodGet, base+"/sensors/not-a-uuid/health/history", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetSensorHealthHistory_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor(), historyErr: errors.New("db down")})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/health/history", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- discoveries ------------------------------------------------------------

func sampleDiscovery() *models.SensorDiscovery {
	return &models.SensorDiscovery{
		ID:         uuid.New(),
		SensorID:   uuid.New(),
		TenantID:   testTenantID,
		BatchID:    uuid.New().String(),
		Protocol:   "tls",
		DestIP:     "10.0.0.5",
		Port:       443,
		Confidence: 0.92,
		Metadata: map[string]interface{}{
			"source_ip":    "10.0.0.9",
			"version":      "1.3",
			"cipher_suite": "TLS_AES_128_GCM_SHA256",
			"key_size":     float64(256),
		},
		Timestamp: time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
	}
}

func TestContract_GetSensorDiscoveries_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor(), discoveries: []*models.SensorDiscovery{sampleDiscovery()}})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/discoveries?limit=25", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SensorDiscoveriesResponse", w.Body.Bytes())
}

func TestContract_GetSensorDiscoveries_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor()})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/discoveries", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SensorDiscoveriesResponse", w.Body.Bytes())
}

func TestContract_GetSensorDiscoveries_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{})
	w := do(eng, http.MethodGet, base+"/sensors/not-a-uuid/discoveries", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetSensorDiscoveries_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubSensorRepo{getSensor: sampleSensor(), discoveriesErr: errors.New("db down")})
	w := do(eng, http.MethodGet, base+"/sensors/"+aUUID+"/discoveries", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- pcap -------------------------------------------------------------------

// stubPcapService satisfies pcapStore.
type stubPcapService struct {
	maxMB     int
	maxErr    error
	created   *models.PcapUploadJob
	createErr error
	jobs      []models.PcapUploadJob
	total     int
	listErr   error
	job       *models.PcapUploadJob
	getErr    error
	deleteErr error
}

func (s *stubPcapService) GetMaxUploadSize() (int, error) { return s.maxMB, s.maxErr }
func (s *stubPcapService) CreateJob(_, _ uuid.UUID, _ string, _ int64, _ string) (*models.PcapUploadJob, error) {
	return s.created, s.createErr
}
func (s *stubPcapService) ListJobs(_ uuid.UUID, _, _ int, _ string) ([]models.PcapUploadJob, int, error) {
	return s.jobs, s.total, s.listErr
}
func (s *stubPcapService) GetJob(_, _ uuid.UUID) (*models.PcapUploadJob, error) {
	return s.job, s.getErr
}
func (s *stubPcapService) DeleteJob(_, _ uuid.UUID) error { return s.deleteErr }
func (s *stubPcapService) UpdateJobStatus(_ uuid.UUID, _ string, _ map[string]interface{}) error {
	return nil
}

func samplePcapJob() *models.PcapUploadJob {
	return &models.PcapUploadJob{
		ID:               uuid.New(),
		TenantID:         testTenantID,
		UploadedBy:       uuid.New(),
		OriginalFilename: "capture.pcap",
		FileSizeBytes:    4096,
		Status:           "pending",
		DiscoveryCount:   0,
		PacketCount:      0,
		ProtocolsFound:   map[string]int{"tls": 3},
		CaptureTimeRange: map[string]interface{}{"start": "2026-01-01T00:00:00Z"},
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
}

// newPcapEngine mounts the pcap routes with the pcapStore stub injected. Pass a
// nil pcapStore to exercise the 503 service-unavailable path.
func newPcapEngine(pcap pcapStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{pcapService: pcap, log: logrus.New()}
	grp := r.Group("/api/v1/sensor-manager")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", testTenantID)
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.POST("/pcap/upload", h.UploadPcap)
	grp.GET("/pcap/jobs", h.ListPcapJobs)
	grp.GET("/pcap/jobs/:id", h.GetPcapJob)
	grp.DELETE("/pcap/jobs/:id", h.DeletePcapJob)
	return r
}

// pcapMultipart builds a multipart/form-data body with a single `file` part.
func pcapMultipart(t *testing.T, field, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return &buf, w.FormDataContentType()
}

func doMultipart(eng *gin.Engine, url string, body *bytes.Buffer, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, url, body)
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	return w
}

// validPcapMagic is the libpcap big-endian magic — accepted by isValidPcapMagic.
var validPcapMagic = []byte{0xA1, 0xB2, 0xC3, 0xD4, 0x00, 0x00, 0x00, 0x00}

func TestContract_UploadPcap_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{maxMB: 100, created: samplePcapJob()})
	body, ct := pcapMultipart(t, "file", "capture.pcap", validPcapMagic)
	w := doMultipart(eng, base+"/pcap/upload", body, ct)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PcapUploadResponse", w.Body.Bytes())
}

func TestContract_UploadPcap_400_noFile(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{maxMB: 100})
	body, ct := pcapMultipart(t, "notfile", "x.txt", []byte("hi"))
	w := doMultipart(eng, base+"/pcap/upload", body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UploadPcap_400_badExt(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{maxMB: 100})
	body, ct := pcapMultipart(t, "file", "capture.txt", validPcapMagic)
	w := doMultipart(eng, base+"/pcap/upload", body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UploadPcap_400_badMagic(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{maxMB: 100})
	body, ct := pcapMultipart(t, "file", "capture.pcap", []byte("NOTPCAP!"))
	w := doMultipart(eng, base+"/pcap/upload", body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UploadPcap_413_tooLarge(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{maxMB: 0}) // 0 MB cap -> any non-empty file is too large
	body, ct := pcapMultipart(t, "file", "capture.pcap", validPcapMagic)
	w := doMultipart(eng, base+"/pcap/upload", body, ct)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UploadPcap_503(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(nil)
	body, ct := pcapMultipart(t, "file", "capture.pcap", validPcapMagic)
	w := doMultipart(eng, base+"/pcap/upload", body, ct)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListPcapJobs_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{jobs: []models.PcapUploadJob{*samplePcapJob()}, total: 1})
	w := do(eng, http.MethodGet, base+"/pcap/jobs?page=1&limit=20", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PcapJobListResponse", w.Body.Bytes())
}

func TestContract_ListPcapJobs_503(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(nil)
	w := do(eng, http.MethodGet, base+"/pcap/jobs", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPcapJob_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{job: samplePcapJob()})
	w := do(eng, http.MethodGet, base+"/pcap/jobs/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PcapUploadJob", w.Body.Bytes())
}

func TestContract_GetPcapJob_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{})
	w := do(eng, http.MethodGet, base+"/pcap/jobs/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPcapJob_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{getErr: errors.New("pcap job not found")})
	w := do(eng, http.MethodGet, base+"/pcap/jobs/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeletePcapJob_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{})
	w := do(eng, http.MethodDelete, base+"/pcap/jobs/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_DeletePcapJob_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newPcapEngine(&stubPcapService{deleteErr: errors.New("pcap job not found")})
	w := do(eng, http.MethodDelete, base+"/pcap/jobs/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
