package handlers

// Contract test for the compliance-engine framework-evaluation HTTP surface —
// the Risk & Compliance workspace reads/evaluates (compliance-api.ts +
// frameworks-api.ts):
//
//   GET  /compliance/score
//   GET  /frameworks/status
//   GET  /frameworks/context
//   POST /frameworks/batch-evaluate
//   POST /evaluate/multiple
//
// The WorkspaceHandlers.evaluationService and
// FrameworkContextHandlers.frameworkContextService fields were narrowed to the
// evaluationStore / frameworkContextStore interfaces (the concrete services
// still satisfy them), so these handlers run here over httptest with in-memory
// stubs and no database. loadSpec / do / assertConforms / aUUID /
// sampleLicensedFrameworkResponse are shared from framework_contract_test.go.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// --- stubs -----------------------------------------------------------------

// stubEvaluationStore satisfies evaluationStore. Only the three methods this
// slice exercises (GetComplianceScore / EvaluateMultipleFrameworks /
// GetFrameworkStatus) carry behavior; the rest return zero values.
type stubEvaluationStore struct {
	score     *services.ComplianceScoreResponse
	scoreErr  error
	multi     []services.MultiFrameworkEvaluationResult
	multiErr  error
	status    *services.FrameworkStatusResponse
	statusErr error
}

func (s *stubEvaluationStore) GetComplianceScore(_ uuid.UUID, _ *uuid.UUID) (*services.ComplianceScoreResponse, error) {
	return s.score, s.scoreErr
}
func (s *stubEvaluationStore) EvaluateMultipleFrameworks(_ uuid.UUID, _ []uuid.UUID, _ map[string]string, _ models.ScenarioFilters, _ string) ([]services.MultiFrameworkEvaluationResult, error) {
	return s.multi, s.multiErr
}
func (s *stubEvaluationStore) GetFrameworkStatus(_ uuid.UUID) (*services.FrameworkStatusResponse, error) {
	return s.status, s.statusErr
}

// Unused-by-this-slice methods (present only to satisfy evaluationStore).
func (s *stubEvaluationStore) EvaluateFramework(_, _ uuid.UUID, _ string, _ models.ScenarioFilters, _ *uuid.UUID) (*services.SummaryResponse, error) {
	return nil, nil
}
func (s *stubEvaluationStore) GetControlDetails(_, _ uuid.UUID, _ *uuid.UUID, _ models.ScenarioFilters, _, _ int) (*services.ControlDetailsResponse, error) {
	return nil, nil
}
func (s *stubEvaluationStore) GetControlDetailsTotalCount(_, _ uuid.UUID, _ models.ScenarioFilters) (int, error) {
	return 0, nil
}
func (s *stubEvaluationStore) ResolveControlID(_, _ string) (uuid.UUID, error) {
	return uuid.Nil, nil
}

// stubFrameworkContextStore satisfies frameworkContextStore.
type stubFrameworkContextStore struct {
	context    *services.FrameworkContextResponse
	contextErr error
	batch      *services.BatchEvaluateResponse
	batchErr   error
}

func (s *stubFrameworkContextStore) GetFrameworkContext(_, _ uuid.UUID) (*services.FrameworkContextResponse, error) {
	return s.context, s.contextErr
}
func (s *stubFrameworkContextStore) BatchEvaluateFrameworks(_ uuid.UUID, _ *services.BatchEvaluateRequest, _ bool) (*services.BatchEvaluateResponse, error) {
	return s.batch, s.batchErr
}

// --- harness ---------------------------------------------------------------

func newEvalEngine(es evaluationStore, fc frameworkContextStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	wh := &WorkspaceHandlers{evaluationService: es}
	fch := &FrameworkContextHandlers{frameworkContextService: fc}

	grp.GET("/compliance/score", wh.GetComplianceScore)
	grp.POST("/evaluate/multiple", wh.EvaluateMultipleFrameworks)
	grp.GET("/frameworks/status", wh.GetFrameworkStatus)
	grp.GET("/frameworks/context", fch.GetFrameworkContext)
	grp.POST("/frameworks/batch-evaluate", fch.BatchEvaluateFrameworks)
	return r
}

const evalBase = "/api/v1/compliance-engine"

// --- sample data -----------------------------------------------------------

func ptr[T any](v T) *T { return &v }

func sampleComplianceScore() *services.ComplianceScoreResponse {
	return &services.ComplianceScoreResponse{
		Score:          ptr(87.5),
		FrameworkCount: 1,
		Frameworks: []services.FrameworkScoreDetail{
			{ID: uuid.NewString(), Name: "PCI DSS 4.0", Code: "pci-dss-4-0", Version: "4.0", Score: ptr(88), Type: "platform"},
		},
	}
}

func sampleFrameworkStatus() *services.FrameworkStatusResponse {
	d := services.FrameworkStatusDetail{
		ID: uuid.NewString(), Name: "PCI DSS 4.0", Code: "pci-dss-4-0", Version: "4.0",
		CompliancePercent: ptr(88), Type: "platform", IsSelected: true,
	}
	return &services.FrameworkStatusResponse{
		Frameworks:        []services.FrameworkStatusDetail{d},
		OverallScore:      ptr(88.0),
		SelectedFramework: &d,
	}
}

func sampleMultiResult() services.MultiFrameworkEvaluationResult {
	return services.MultiFrameworkEvaluationResult{
		FrameworkID:      uuid.NewString(),
		FrameworkName:    "PCI DSS 4.0",
		FrameworkCode:    "pci-dss-4-0",
		FrameworkVersion: "4.0",
		FrameworkType:    "platform",
		Score:            ptr(88),
		Summary:          nil, // serializes as null; schema allows ["object","null"]
		AffectedEntities: map[string][]string{"certificates": {uuid.NewString()}},
		Controls: struct {
			Total       int `json:"total"`
			Passing     int `json:"passing"`
			Failing     int `json:"failing"`
			NotAssessed int `json:"not_assessed"`
		}{Total: 10, Passing: 8, Failing: 1, NotAssessed: 1},
		LastEvaluated: time.Now().UTC().Format(time.RFC3339),
	}
}

func sampleFrameworkContext() *services.FrameworkContextResponse {
	def := uuid.NewString()
	return &services.FrameworkContextResponse{
		Licensed:           []models.LicensedFrameworkResponse{sampleLicensedFrameworkResponse()},
		DefaultFrameworkID: &def,
		Status: &services.FrameworkContextStatus{
			Frameworks: []services.FrameworkStatusItem{{
				ID: uuid.NewString(), Name: "PCI DSS 4.0", Code: "pci-dss-4-0", Version: "4.0",
				CompliancePercent: ptr(88), ControlsTotal: 10, ControlsPassing: 8, ControlsFailing: 1,
				ControlsNotAssessed: 1, OpenFindingsControls: 1, IsDefault: true,
			}},
			OverallScore: ptr(88.0),
		},
		Subscription: &services.FrameworkSubscriptionInfo{
			Tier: "enterprise", FrameworkLimit: 10, FrameworksUsed: 2, CanAddMore: true,
		},
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}
}

func sampleBatchEvaluate() *services.BatchEvaluateResponse {
	return &services.BatchEvaluateResponse{
		Results: []services.BatchEvaluateResult{{
			FrameworkID: uuid.NewString(), FrameworkName: "PCI DSS 4.0", FrameworkCode: "pci-dss-4-0",
			FrameworkVersion: "4.0", Score: ptr(88), ControlsTotal: 10, ControlsPassing: 8, ControlsFailing: 1,
			ControlsNotAssessed: 1, AffectedAssets: 3,
		}},
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}
}

// --- tests -----------------------------------------------------------------

func TestContract_GetComplianceScore_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{score: sampleComplianceScore()}, &stubFrameworkContextStore{})
	w := do(eng, http.MethodGet, evalBase+"/compliance/score", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ComplianceScoreResponse", w.Body.Bytes())
}

func TestContract_GetComplianceScore_400_badFrameworkID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{}, &stubFrameworkContextStore{})
	w := do(eng, http.MethodGet, evalBase+"/compliance/score?framework_id=not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetFrameworkStatus_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{status: sampleFrameworkStatus()}, &stubFrameworkContextStore{})
	w := do(eng, http.MethodGet, evalBase+"/frameworks/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FrameworkStatusResponse", w.Body.Bytes())
}

func TestContract_GetFrameworkContext_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{}, &stubFrameworkContextStore{context: sampleFrameworkContext()})
	w := do(eng, http.MethodGet, evalBase+"/frameworks/context", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FrameworkContextResponse", w.Body.Bytes())
}

func TestContract_BatchEvaluate_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{}, &stubFrameworkContextStore{batch: sampleBatchEvaluate()})
	body := strings.NewReader(`{"framework_ids":["` + aUUID + `"]}`)
	w := do(eng, http.MethodPost, evalBase+"/frameworks/batch-evaluate", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BatchEvaluateResponse", w.Body.Bytes())
}

// Missing required framework_ids -> 400.
func TestContract_BatchEvaluate_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{}, &stubFrameworkContextStore{})
	w := do(eng, http.MethodPost, evalBase+"/frameworks/batch-evaluate", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_EvaluateMultiple_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{multi: []services.MultiFrameworkEvaluationResult{sampleMultiResult()}}, &stubFrameworkContextStore{})
	body := strings.NewReader(`{"framework_ids":["` + aUUID + `"],"entity_type":"certificates"}`)
	w := do(eng, http.MethodPost, evalBase+"/evaluate/multiple", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EvaluateMultipleResponse", w.Body.Bytes())
}

// Bind error (missing framework_ids) -> 400; validates against the
// details-optional LegacyErrorWithDetails the spec maps the 400 to.
func TestContract_EvaluateMultiple_400_bind(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{}, &stubFrameworkContextStore{})
	w := do(eng, http.MethodPost, evalBase+"/evaluate/multiple", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyErrorWithDetails", w.Body.Bytes())
}

// A non-UUID framework_id surfaces as 400 with an extra details string.
func TestContract_EvaluateMultiple_400_badUUID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEvalEngine(&stubEvaluationStore{}, &stubFrameworkContextStore{})
	body := strings.NewReader(`{"framework_ids":["not-a-uuid"]}`)
	w := do(eng, http.MethodPost, evalBase+"/evaluate/multiple", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyErrorWithDetails", w.Body.Bytes())
}
