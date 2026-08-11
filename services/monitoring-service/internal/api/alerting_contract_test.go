package api

// Contract test for the platform alerting HTTP surface
// (`/api/v1/monitoring-service/alerting/...`): alert-threshold CRUD + history.
//
// The handlers depend on *services.AlertingService via the Server.alertingService
// field. This slice landed a behaviour-preserving field→interface refactor first
// (the field is now the narrow alertingProvider interface the concrete service
// still satisfies — see alerting_provider.go), so the real gin handlers run over
// httptest with an in-memory stub — no database — and their bodies are asserted
// against api/openapi/monitoring-service.openapi.yaml.
//
// Reuses statusLoadSpec / statusSpecValidator.assertConforms / statusBase from
// status_contract_test.go (same package). UI consumer: admin-ui status-api.ts.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
)

var errAlerting = context.DeadlineExceeded

// --- in-memory stub ---------------------------------------------------------

type stubAlertingProvider struct {
	thresholds    []models.AlertThreshold
	thresholdsErr error
	threshold     *models.AlertThreshold
	thresholdErr  error
	created       *models.AlertThreshold
	createErr     error
	updated       *models.AlertThreshold
	updateErr     error
	deleteErr     error
	history       []models.AlertHistory
	historyTotal  int
	historyErr    error
}

func (s *stubAlertingProvider) GetAlertThresholds(*string, *bool) ([]models.AlertThreshold, error) {
	return s.thresholds, s.thresholdsErr
}
func (s *stubAlertingProvider) GetAlertThreshold(uuid.UUID) (*models.AlertThreshold, error) {
	return s.threshold, s.thresholdErr
}
func (s *stubAlertingProvider) CreateAlertThreshold(*models.CreateAlertThresholdRequest, *uuid.UUID) (*models.AlertThreshold, error) {
	return s.created, s.createErr
}
func (s *stubAlertingProvider) UpdateAlertThreshold(uuid.UUID, *models.UpdateAlertThresholdRequest, *uuid.UUID) (*models.AlertThreshold, error) {
	return s.updated, s.updateErr
}
func (s *stubAlertingProvider) DeleteAlertThreshold(uuid.UUID) error { return s.deleteErr }
func (s *stubAlertingProvider) GetAlertHistory(*string, *string, int, int) ([]models.AlertHistory, int, error) {
	return s.history, s.historyTotal, s.historyErr
}

// --- harness ----------------------------------------------------------------

func newAlertingEngine(ap alertingProvider) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := newServerWithAlerting(ap)
	r := gin.New()
	grp := r.Group(statusBase + "/alerting")
	grp.Use(func(c *gin.Context) {
		c.Set("userID", uuid.NewString())
		c.Next()
	})
	grp.GET("/thresholds", srv.GetAlertThresholds)
	grp.GET("/thresholds/:id", srv.GetAlertThreshold)
	grp.POST("/thresholds", srv.CreateAlertThreshold)
	grp.PUT("/thresholds/:id", srv.UpdateAlertThreshold)
	grp.DELETE("/thresholds/:id", srv.DeleteAlertThreshold)
	grp.GET("/history", srv.GetAlertHistory)
	return r
}

func alertingDo(engine *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func sampleAlertThreshold() models.AlertThreshold {
	now := time.Now().UTC()
	svc := "auth-service"
	warn := 75.0
	crit := 90.0
	desc := "CPU saturation"
	by := uuid.New()
	return models.AlertThreshold{
		ID:                 uuid.New(),
		ThresholdName:      "cpu-high",
		MetricType:         "cpu_usage",
		ServiceName:        &svc,
		WarningThreshold:   &warn,
		CriticalThreshold:  &crit,
		Severity:           "warning",
		Enabled:            true,
		NotifyEmail:        true,
		NotifySlack:        false,
		NotifyWebhook:      false,
		NotifyInApp:        true,
		ComparisonOperator: ">",
		DurationMinutes:    5,
		Description:        &desc,
		CreatedBy:          &by,
		CreatedAt:          now,
		UpdatedAt:          now,
		UpdatedBy:          &by,
	}
}

// minimalAlertThreshold leaves the omitempty pointer fields unset.
func minimalAlertThreshold() models.AlertThreshold {
	now := time.Now().UTC()
	return models.AlertThreshold{
		ID:                 uuid.New(),
		ThresholdName:      "mem-high",
		MetricType:         "memory_usage",
		Severity:           "critical",
		Enabled:            false,
		ComparisonOperator: ">=",
		DurationMinutes:    10,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func sampleAlertHistory() models.AlertHistory {
	now := time.Now().UTC()
	tid := uuid.New()
	svc := "inventory-service"
	msg := "threshold exceeded"
	return models.AlertHistory{
		ID:                uuid.New(),
		ThresholdID:       &tid,
		ThresholdName:     "cpu-high",
		MetricType:        "cpu_usage",
		ServiceName:       &svc,
		ThresholdValue:    75.0,
		ActualValue:       88.2,
		Severity:          "warning",
		Status:            "triggered",
		NotificationsSent: []map[string]interface{}{{"channel": "email", "ok": true}},
		Message:           &msg,
		Metadata:          map[string]interface{}{"region": "us-east-1"},
		TriggeredAt:       now,
	}
}

// --- thresholds: list -------------------------------------------------------

func TestContract_GetAlertThresholds_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{thresholds: []models.AlertThreshold{sampleAlertThreshold(), minimalAlertThreshold()}})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/thresholds", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertThresholdListResponse", w.Body.Bytes())
}

// Empty result → nil slice → `{"thresholds": null, "count": 0}`.
func TestContract_GetAlertThresholds_200_empty(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{thresholds: nil})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/thresholds", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertThresholdListResponse", w.Body.Bytes())
}

func TestContract_GetAlertThresholds_500(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{thresholdsErr: errAlerting})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/thresholds", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- thresholds: get --------------------------------------------------------

func TestContract_GetAlertThreshold_200(t *testing.T) {
	sv := statusLoadSpec(t)
	thr := sampleAlertThreshold()
	eng := newAlertingEngine(&stubAlertingProvider{threshold: &thr})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/thresholds/"+uuid.New().String(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertThreshold", w.Body.Bytes())
}

func TestContract_GetAlertThreshold_400_badID(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/thresholds/not-a-uuid", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetAlertThreshold_404(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{thresholdErr: errAlerting})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/thresholds/"+uuid.New().String(), "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- thresholds: create -----------------------------------------------------

func TestContract_CreateAlertThreshold_201(t *testing.T) {
	sv := statusLoadSpec(t)
	thr := sampleAlertThreshold()
	eng := newAlertingEngine(&stubAlertingProvider{created: &thr})
	body := `{"threshold_name":"cpu-high","metric_type":"cpu_usage","severity":"warning","comparison_operator":">","duration_minutes":5}`
	w := alertingDo(eng, http.MethodPost, statusBase+"/alerting/thresholds", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertThreshold", w.Body.Bytes())
}

// Missing required threshold_name/metric_type → binding 400.
func TestContract_CreateAlertThreshold_400(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{})
	w := alertingDo(eng, http.MethodPost, statusBase+"/alerting/thresholds", `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateAlertThreshold_500(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{createErr: errAlerting})
	body := `{"threshold_name":"cpu-high","metric_type":"cpu_usage"}`
	w := alertingDo(eng, http.MethodPost, statusBase+"/alerting/thresholds", body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- thresholds: update -----------------------------------------------------

func TestContract_UpdateAlertThreshold_200(t *testing.T) {
	sv := statusLoadSpec(t)
	thr := sampleAlertThreshold()
	eng := newAlertingEngine(&stubAlertingProvider{updated: &thr})
	w := alertingDo(eng, http.MethodPut, statusBase+"/alerting/thresholds/"+uuid.New().String(), `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertThreshold", w.Body.Bytes())
}

func TestContract_UpdateAlertThreshold_400_badID(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{})
	w := alertingDo(eng, http.MethodPut, statusBase+"/alerting/thresholds/not-a-uuid", `{"enabled":false}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Malformed JSON body → binding 400.
func TestContract_UpdateAlertThreshold_400_badBody(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{})
	w := alertingDo(eng, http.MethodPut, statusBase+"/alerting/thresholds/"+uuid.New().String(), `{not json`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateAlertThreshold_500(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{updateErr: errAlerting})
	w := alertingDo(eng, http.MethodPut, statusBase+"/alerting/thresholds/"+uuid.New().String(), `{"enabled":false}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- thresholds: delete -----------------------------------------------------

func TestContract_DeleteAlertThreshold_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{})
	w := alertingDo(eng, http.MethodDelete, statusBase+"/alerting/thresholds/"+uuid.New().String(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertThresholdDeletedResponse", w.Body.Bytes())
}

func TestContract_DeleteAlertThreshold_400_badID(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{})
	w := alertingDo(eng, http.MethodDelete, statusBase+"/alerting/thresholds/not-a-uuid", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteAlertThreshold_500(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{deleteErr: errAlerting})
	w := alertingDo(eng, http.MethodDelete, statusBase+"/alerting/thresholds/"+uuid.New().String(), "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- history ----------------------------------------------------------------

func TestContract_GetAlertHistory_200(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{history: []models.AlertHistory{sampleAlertHistory()}, historyTotal: 1})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/history", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertHistoryResponse", w.Body.Bytes())
}

// Empty result → nil slice → `"alerts": null`.
func TestContract_GetAlertHistory_200_empty(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{history: nil, historyTotal: 0})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/history?limit=10&offset=5", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertHistoryResponse", w.Body.Bytes())
}

func TestContract_GetAlertHistory_500(t *testing.T) {
	sv := statusLoadSpec(t)
	eng := newAlertingEngine(&stubAlertingProvider{historyErr: errAlerting})
	w := alertingDo(eng, http.MethodGet, statusBase+"/alerting/history", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift guard ------------------------------------------------------------

func TestContract_AlertThreshold_DriftIsCaught(t *testing.T) {
	sv := statusLoadSpec(t)
	sch, err := sv.compiler.Compile(statusSpecBaseURI + "#/components/schemas/AlertThreshold")
	if err != nil {
		t.Fatalf("compile AlertThreshold: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(`{"id":"` + uuid.New().String() + `","surprise_field":true}`)))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted AlertThreshold, but it passed — the guardrail is not actually checking")
	}
}
