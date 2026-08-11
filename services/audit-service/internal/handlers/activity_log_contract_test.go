package handlers

// Contract test for the tenant activity-logs HTTP surface.
//
// A slice of the spec-first API contract (ADR-0001). It exercises the REAL gin
// handlers over httptest (with an in-memory stub activityLogService, no
// database) and asserts that every response body conforms to the schema
// declared in api/openapi/audit-service.openapi.yaml.
//
// The handler was made testable by depending on the small activityLogService
// interface (the concrete *services.ActivityLogService still satisfies it) — the
// standard ~one-interface testability refactor from the contract recipe.
//
// OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so we validate response bodies
// directly with santhosh-tekuri/jsonschema/v6 — same approach as the other
// contract tests.

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
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"gopkg.in/yaml.v3"
)

const specBaseURI = "https://vistaplatform.local/audit-service.openapi.yaml"

// --- spec loading + response validation -----------------------------------

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// handlers -> internal -> audit-service -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "audit-service.openapi.yaml",
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
	if err := c.AddResource(specBaseURI, doc); err != nil {
		t.Fatalf("add spec resource: %v", err)
	}
	return &specValidator{compiler: c}
}

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

// --- in-memory stub activityLogService ------------------------------------

var testTenantID = uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

type stubActivityLogService struct {
	logs            []models.ActivityLog
	total           int
	logsErr         error
	getResult       *models.ActivityLog
	getErr          error
	summary         map[string]interface{}
	summaryErr      error
	capturedFilters *models.ActivityLogFilters // last filters passed to GetActivityLogs
}

func (s *stubActivityLogService) LogActivity(context.Context, *models.ActivityLog) error { return nil }
func (s *stubActivityLogService) AssignComplianceTags(string, string) []string           { return nil }
func (s *stubActivityLogService) GetActivityLogs(_ context.Context, filters models.ActivityLogFilters) ([]models.ActivityLog, int, error) {
	s.capturedFilters = &filters
	return s.logs, s.total, s.logsErr
}
func (s *stubActivityLogService) GetActivityLogByID(context.Context, uuid.UUID, *uuid.UUID) (*models.ActivityLog, error) {
	return s.getResult, s.getErr
}
func (s *stubActivityLogService) GetActivityLogsSummary(context.Context, *uuid.UUID, time.Time, time.Time) (map[string]interface{}, error) {
	return s.summary, s.summaryErr
}
func (s *stubActivityLogService) GetActivityLogsByUser(context.Context, uuid.UUID, *uuid.UUID, time.Time, time.Time) (map[string]interface{}, error) {
	return s.summary, s.summaryErr
}
func (s *stubActivityLogService) GetActivityLogsByResource(context.Context, string, uuid.UUID, *uuid.UUID, time.Time, time.Time) ([]models.ActivityLog, int, error) {
	return s.logs, s.total, s.logsErr
}

// --- test harness ----------------------------------------------------------

// newEngine wires the real activity-log handlers under /api/v1/audit-service
// with a middleware that injects a tenant user's context (userType=tenant +
// tenantID), the way the real RequireAuth middleware does.
func newEngine(svc *stubActivityLogService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &ActivityLogHandler{service: svc}

	grp := r.Group("/api/v1/audit-service")
	grp.Use(func(c *gin.Context) {
		c.Set("userType", "tenant")
		c.Set("tenantID", testTenantID)
		c.Set("userID", uuid.New())
		c.Next()
	})

	grp.GET("/activity-logs", h.GetActivityLogs)
	grp.GET("/activity-logs/export", h.ExportActivityLogs)
	grp.GET("/activity-logs/summary", h.GetActivityLogsSummary)
	grp.GET("/activity-logs/by-resource/:resource_type/:resource_id", h.GetResourceAuditTrail)
	grp.GET("/activity-logs/by-user/:user_id", h.GetUserActivityTimeline)
	grp.GET("/activity-logs/:id", h.GetActivityLogByID)
	grp.POST("/activity-logs/query", h.QueryActivityLogs)
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

// sampleLog sets the optional (omitempty) fields too, so the body exercises the
// optional properties beyond the always-present required set.
func sampleLog() models.ActivityLog {
	now := time.Now().UTC()
	uid := uuid.New()
	rid := uuid.New()
	return models.ActivityLog{
		ID:                uuid.New(),
		TenantID:          &testTenantID,
		UserID:            &uid,
		UserType:          "tenant",
		UserEmail:         strPtr("user@example.com"),
		EventType:         "asset.updated",
		EventCategory:     "inventory",
		Action:            "update",
		ResourceType:      strPtr("asset"),
		ResourceID:        &rid,
		OldValues:         models.JSONB{"status": "pending"},
		NewValues:         models.JSONB{"status": "monitoring"},
		ChangedFields:     []string{"status"},
		IPAddress:         strPtr("10.0.0.5"),
		Success:           true,
		ComplianceTags:    []string{"soc2"},
		RequiresAttention: false,
		Metadata:          map[string]interface{}{"source": "ui"},
		OccurredAt:        now,
		CreatedAt:         now,
	}
}

// minimalLog leaves all omitempty fields unset — they must be ABSENT (not null)
// in the body, proving the spec's optional-key handling holds.
func minimalLog() models.ActivityLog {
	now := time.Now().UTC()
	return models.ActivityLog{
		ID:            uuid.New(),
		UserType:      "system",
		EventType:     "session.expired",
		EventCategory: "auth",
		Action:        "logout",
		Success:       true,
		OccurredAt:    now,
		CreatedAt:     now,
	}
}

const aUUID = "11111111-1111-1111-1111-111111111111"
const base = "/api/v1/audit-service"

// --- the contract tests ----------------------------------------------------

func TestContract_ListActivityLogs_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{logs: []models.ActivityLog{sampleLog(), minimalLog()}, total: 2})
	w := do(eng, http.MethodGet, base+"/activity-logs?page=1&page_size=20", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActivityLogListResponse", w.Body.Bytes())
}

// Export: format=json returns the bare {logs:[...]} envelope (no
// pagination); format=csv returns a text/csv file download; an unsupported
// format is a 400; a service failure is a 500.
func TestContract_ExportActivityLogs_JSON_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{logs: []models.ActivityLog{sampleLog(), minimalLog()}, total: 2})
	w := do(eng, http.MethodGet, base+"/activity-logs/export?format=json", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActivityLogExportResponse", w.Body.Bytes())
}

// Default format (no query param) is json.
func TestContract_ExportActivityLogs_DefaultsToJSON_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{logs: nil, total: 0})
	w := do(eng, http.MethodGet, base+"/activity-logs/export", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActivityLogExportResponse", w.Body.Bytes())
}

func TestContract_ExportActivityLogs_CSV_200(t *testing.T) {
	eng := newEngine(&stubActivityLogService{logs: []models.ActivityLog{sampleLog()}, total: 1})
	w := do(eng, http.MethodGet, base+"/activity-logs/export?format=csv", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("Content-Type = %q, want text/csv", ct)
	}
}

func TestContract_ExportActivityLogs_400_badFormat(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{})
	w := do(eng, http.MethodGet, base+"/activity-logs/export?format=xml", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ExportActivityLogs_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{logsErr: context.DeadlineExceeded})
	w := do(eng, http.MethodGet, base+"/activity-logs/export?format=json", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_QueryActivityLogs_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{logs: []models.ActivityLog{sampleLog()}, total: 1})
	// Empty filters body — exercises the default-pagination guard (no panic).
	w := do(eng, http.MethodPost, base+"/activity-logs/query", strings.NewReader(`{"filters":{}}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActivityLogListResponse", w.Body.Bytes())
}

// QueryActivityLogs must BIND the snake_case `filters` body into
// ActivityLogFilters. Before the json tags were added, event_category /
// user_type / page_size silently no-op'd (Go matched only no-underscore field
// names), so these filters never reached the service. This locks the binding.
func TestContract_QueryActivityLogs_BindsSnakeCaseFilters(t *testing.T) {
	stub := &stubActivityLogService{logs: []models.ActivityLog{sampleLog()}, total: 1}
	eng := newEngine(stub)
	body := `{"filters":{"event_category":["inventory"],"user_type":"platform","search":"asset","impersonation":true,"page":2,"page_size":25}}`
	w := do(eng, http.MethodPost, base+"/activity-logs/query", strings.NewReader(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	f := stub.capturedFilters
	if f == nil {
		t.Fatal("filters were not passed to the service")
	}
	if len(f.EventCategory) != 1 || f.EventCategory[0] != "inventory" {
		t.Errorf("event_category did not bind: %#v", f.EventCategory)
	}
	if f.UserType == nil || *f.UserType != "platform" {
		t.Errorf("user_type did not bind: %#v", f.UserType)
	}
	if f.Search == nil || *f.Search != "asset" {
		t.Errorf("search did not bind: %#v", f.Search)
	}
	if f.Impersonation == nil || !*f.Impersonation {
		t.Errorf("impersonation did not bind: %#v", f.Impersonation)
	}
	if f.Page != 2 {
		t.Errorf("page did not bind: got %d", f.Page)
	}
	if f.PageSize != 25 {
		t.Errorf("page_size did not bind: got %d", f.PageSize)
	}
}

func TestContract_GetActivityLog_200(t *testing.T) {
	sv := loadSpec(t)
	l := sampleLog()
	eng := newEngine(&stubActivityLogService{getResult: &l})
	w := do(eng, http.MethodGet, base+"/activity-logs/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActivityLogResponse", w.Body.Bytes())
}

func TestContract_GetActivityLog_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{})
	w := do(eng, http.MethodGet, base+"/activity-logs/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// GetActivityLogByID maps any retrieval error (incl. no-rows) to 404 — a
// documented quirk captured by x-quirks in the spec.
func TestContract_GetActivityLog_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{getErr: io.EOF})
	w := do(eng, http.MethodGet, base+"/activity-logs/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_Summary_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{summary: map[string]interface{}{
		"total_events": 42, "failure_rate": 0.05,
	}})
	w := do(eng, http.MethodGet, base+"/activity-logs/summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ActivityLogSummaryResponse", w.Body.Bytes())
}

func TestContract_ResourceAuditTrail_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{logs: []models.ActivityLog{sampleLog()}, total: 1})
	w := do(eng, http.MethodGet, base+"/activity-logs/by-resource/asset/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ResourceAuditTrailResponse", w.Body.Bytes())
}

func TestContract_UserActivityTimeline_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubActivityLogService{logs: []models.ActivityLog{sampleLog()}, total: 1})
	w := do(eng, http.MethodGet, base+"/activity-logs/by-user/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UserActivityTimelineResponse", w.Body.Bytes())
}

// TestContract_DriftIsCaught proves the guardrail actually validates: a body
// that drifts from the contract (an ActivityLog missing required fields, plus
// an undeclared field that additionalProperties:false forbids) MUST be
// rejected. If this ever passes, the validator is rubber-stamping.
func TestContract_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/ActivityLog")
	if err != nil {
		t.Fatalf("compile ActivityLog: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted ActivityLog, but it passed — the guardrail is not actually checking")
	}
}
