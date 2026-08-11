package handlers

// Contract test for the compliance findings HTTP surface (Risk & Compliance
// workspace). Extends the compliance-engine spec-first contract (ADR-0001) and
// reuses the shared harness (loadSpec / assertConforms / do / specBaseURI) from
// framework_contract_test.go — only the findings stub + engine + cases live
// here.
//
// WorkspaceHandlers was made testable by depending on the findingsStore
// interface for its FindingsService field (the concrete *services.FindingsService
// still satisfies it), so these tests drive the real handlers with an in-memory
// stub — no database.

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// --- stub findingsStore ----------------------------------------------------

type stubFindingsStore struct {
	stats         *services.FindingStatistics
	statsErr      error
	list          []models.ComplianceFinding
	listTotal     int
	listErr       error
	byAsset       []models.ComplianceFinding
	byAssetErr    error
	history       []models.ComplianceFindingHistory
	historyErr    error
	assignErr     error
	unassignErr   error
	evidenceID    string
	evidenceRef   string
	evidenceErr   error
	finding       *models.ComplianceFinding
	findingErr    error
	updWorkflowEr error
	byControl     []services.FindingsByControlGroup
	byControlErr  error
}

func (s *stubFindingsStore) ListFindings(_ uuid.UUID, _ services.FindingListFilters, _, _ int) ([]models.ComplianceFinding, int, error) {
	return s.list, s.listTotal, s.listErr
}
func (s *stubFindingsStore) AssignFindingOwner(_, _, _, _ uuid.UUID, _ *string) error {
	return s.assignErr
}
func (s *stubFindingsStore) UnassignFindingOwner(_, _ uuid.UUID) error { return s.unassignErr }
func (s *stubFindingsStore) GetFinding(_, _ uuid.UUID) (*models.ComplianceFinding, error) {
	return s.finding, s.findingErr
}
func (s *stubFindingsStore) GetFindingsByAsset(_, _ uuid.UUID) ([]models.ComplianceFinding, error) {
	return s.byAsset, s.byAssetErr
}
func (s *stubFindingsStore) GetFindingStatistics(_ uuid.UUID) (*services.FindingStatistics, error) {
	return s.stats, s.statsErr
}
func (s *stubFindingsStore) GetFindingsByControl(_ uuid.UUID, _ int) ([]services.FindingsByControlGroup, error) {
	return s.byControl, s.byControlErr
}
func (s *stubFindingsStore) GetEvidenceID(_, _ uuid.UUID) (string, string, error) {
	return s.evidenceID, s.evidenceRef, s.evidenceErr
}
func (s *stubFindingsStore) UpdateWorkflowStatus(_, _, _ uuid.UUID, _ string, _ *string, _ *time.Time) error {
	return s.updWorkflowEr
}
func (s *stubFindingsStore) GetFindingHistory(_, _ uuid.UUID) ([]models.ComplianceFindingHistory, error) {
	return s.history, s.historyErr
}

func newFindingsEngine(svc *stubFindingsStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New().String()) // UpdateFindingWorkflowStatus reads userID via raw .(string)
		c.Next()
	})
	h := &WorkspaceHandlers{findingsService: svc}
	grp.GET("/findings", h.ListFindings)
	grp.GET("/findings/statistics", h.GetFindingStatistics)
	grp.GET("/findings/by-control", h.GetFindingsByControl)
	grp.GET("/findings/:id/history", h.GetFindingHistory)
	grp.GET("/assets/:assetId/findings", h.GetFindingsByAsset)
	grp.POST("/findings/:id/assign", h.AssignFindingOwner)
	grp.DELETE("/findings/:id/assign", h.UnassignFindingOwner)
	grp.GET("/findings/:id/evidence-id", h.GetEvidenceId)
	grp.PUT("/findings/:id/workflow-status", h.UpdateFindingWorkflowStatus)
	return r
}

func sampleFinding() models.ComplianceFinding {
	now := time.Now().UTC()
	return models.ComplianceFinding{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ControlID:         uuid.New(),
		AssetID:           uuid.New(),
		AssetType:         "network_asset",
		Severity:          "high",
		Summary:           "Weak protocol in use",
		Evidence:          map[string]any{"protocol": "TLS 1.0"},
		FirstSeen:         now,
		LastSeen:          now,
		DetectionState:    "ACTIVE",
		WorkflowStatus:    "NEW",
		OccurrenceCount:   3,
		IsStale:           false,
		EvaluationVersion: 2,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func sampleHistory() models.ComplianceFindingHistory {
	now := time.Now().UTC()
	by := uuid.New()
	old, nw := "NEW", "RESOLVED"
	return models.ComplianceFindingHistory{
		ID:        uuid.New(),
		FindingID: uuid.New(),
		ChangedBy: &by,
		ChangedAt: now,
		FieldName: "workflow_status",
		OldValue:  &old,
		NewValue:  &nw,
	}
}

const cBase = "/api/v1/compliance-engine"
const fUUID = "11111111-1111-1111-1111-111111111111"

// --- the contract tests ----------------------------------------------------

func TestContract_GetFindingStatistics_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{stats: &services.FindingStatistics{
		TotalFindings: 10, ActiveFindings: 7, InactiveFindings: 2, ArchivedFindings: 1,
		NewFindings: 4, NotifiedFindings: 2, ResolvedFindings: 3, SuppressedFindings: 1,
		ResurfacedFindings: 0,
	}})
	w := do(eng, http.MethodGet, cBase+"/findings/statistics", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingStatistics", w.Body.Bytes())
}

func TestContract_GetFindingsByControl_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{byControl: []services.FindingsByControlGroup{
		{
			ControlID: uuid.New(), ControlName: "Strong Cryptography", FrameworkID: uuid.New(),
			FrameworkName: "PCI DSS", WorstSeverity: "Critical", FindingCount: 29, AffectedAssets: 29,
			SeverityCounts: services.SeverityCounts{Critical: 29},
		},
		{
			ControlID: uuid.New(), ControlName: "Secure Protocols", FrameworkID: uuid.New(),
			FrameworkName: "ISO/IEC 27001", WorstSeverity: "High", FindingCount: 12, AffectedAssets: 8,
			SeverityCounts: services.SeverityCounts{High: 12},
		},
	}})
	w := do(eng, http.MethodGet, cBase+"/findings/by-control?limit=5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingsByControlResponse", w.Body.Bytes())
}

func TestContract_GetFindingsByControl_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{byControl: nil})
	w := do(eng, http.MethodGet, cBase+"/findings/by-control", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingsByControlResponse", w.Body.Bytes())
}

func TestContract_GetFindingsByControl_500(t *testing.T) {
	eng := newFindingsEngine(&stubFindingsStore{byControlErr: errors.New("boom")})
	w := do(eng, http.MethodGet, cBase+"/findings/by-control", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestContract_GetFindingHistory_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{history: []models.ComplianceFindingHistory{sampleHistory()}})
	w := do(eng, http.MethodGet, cBase+"/findings/"+fUUID+"/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingHistoryResponse", w.Body.Bytes())
}

func TestContract_GetFindingHistory_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{})
	w := do(eng, http.MethodGet, cBase+"/findings/not-a-uuid/history", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListFindings_200(t *testing.T) {
	sv := loadSpec(t)
	f := sampleFinding()
	host := "web-01.example.com"
	env := "production"
	f.Asset = &models.Asset{ID: f.AssetID, TenantID: f.TenantID, Hostname: &host, Environment: &env, AssetType: "server"}
	eng := newFindingsEngine(&stubFindingsStore{list: []models.ComplianceFinding{f}, listTotal: 1})
	w := do(eng, http.MethodGet, cBase+"/findings?workflow_status=NEW&page=1&page_size=50", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingListResponse", w.Body.Bytes())
}

func TestContract_ListFindings_200_emptyIsNullable(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{})
	w := do(eng, http.MethodGet, cBase+"/findings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingListResponse", w.Body.Bytes())
}

func TestContract_ListFindings_400_badFrameworkID(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{})
	w := do(eng, http.MethodGet, cBase+"/findings?framework_id=not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetFindingsByAsset_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{byAsset: []models.ComplianceFinding{sampleFinding()}})
	w := do(eng, http.MethodGet, cBase+"/assets/"+fUUID+"/findings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingsByAssetResponse", w.Body.Bytes())
}

func TestContract_GetFindingsByAsset_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{})
	w := do(eng, http.MethodGet, cBase+"/assets/not-a-uuid/findings", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- findings workflow mutations --------------------------------------------

func TestContract_AssignFindingOwner_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{})
	w := do(eng, http.MethodPost, cBase+"/findings/"+fUUID+"/assign", strings.NewReader(`{"assigned_to":"`+fUUID+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_AssignFindingOwner_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{})
	w := do(eng, http.MethodPost, cBase+"/findings/"+fUUID+"/assign", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UnassignFindingOwner_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{})
	w := do(eng, http.MethodDelete, cBase+"/findings/"+fUUID+"/assign", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_GetEvidenceId_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{evidenceID: "EV-123", evidenceRef: "s3://bucket/ev/123"})
	w := do(eng, http.MethodGet, cBase+"/findings/"+fUUID+"/evidence-id", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EvidenceIdResponse", w.Body.Bytes())
}

func TestContract_UpdateFindingWorkflowStatus_200(t *testing.T) {
	sv := loadSpec(t)
	f := sampleFinding()
	eng := newFindingsEngine(&stubFindingsStore{finding: &f})
	w := do(eng, http.MethodPut, cBase+"/findings/"+fUUID+"/workflow-status", strings.NewReader(`{"workflow_status":"resolved"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingResponse", w.Body.Bytes())
}

func TestContract_UpdateFindingWorkflowStatus_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newFindingsEngine(&stubFindingsStore{})
	w := do(eng, http.MethodPut, cBase+"/findings/"+fUUID+"/workflow-status", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_Finding_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/ComplianceFinding")
	if err != nil {
		t.Fatalf("compile ComplianceFinding: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + fUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted ComplianceFinding, but it passed — the guardrail is not actually checking")
	}
}
