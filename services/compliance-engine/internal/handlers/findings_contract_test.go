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
	stats          *services.FindingStatistics
	statsErr       error
	list           []models.ComplianceFinding
	listTotal      int
	listErr        error
	producerCounts map[string]int
	producerErr    error
	// lastFilters records what the handler passed down, so a query-parameter
	// case can assert the filter ARRIVED rather than only that the request
	// returned 200 — a parameter the handler drops is invisible from the
	// status code.
	lastFilters   *services.FindingListFilters
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

func (s *stubFindingsStore) ListFindings(_ uuid.UUID, f services.FindingListFilters, _, _ int) ([]models.ComplianceFinding, int, error) {
	s.lastFilters = &f
	return s.list, s.listTotal, s.listErr
}
func (s *stubFindingsStore) CountFindingsByProducer(_ uuid.UUID, _ services.FindingListFilters) (map[string]int, error) {
	return s.producerCounts, s.producerErr
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
		Producer:          "compliance",
		Kind:              "control_noncompliant",
		ControlID:         uuid.New(),
		SubjectID:         uuid.New(),
		SubjectType:       "asset",
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
		SeverityCounts:     services.SeverityCounts{Critical: 4, High: 3, Medium: 2, Low: 1},
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
			FrameworkName: "PCI DSS", WorstSeverity: "critical", FindingCount: 29, AffectedAssets: 29,
			SeverityCounts: services.SeverityCounts{Critical: 29}, TargetKind: "asset",
		},
		{
			ControlID: uuid.New(), ControlName: "Secure Protocols", FrameworkID: uuid.New(),
			FrameworkName: "ISO/IEC 27001", WorstSeverity: "high", FindingCount: 12, AffectedAssets: 8,
			SeverityCounts: services.SeverityCounts{High: 12}, TargetKind: "certificate",
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
	f.Asset = &models.Asset{ID: f.SubjectID, TenantID: f.TenantID, Hostname: &host, Environment: &env, AssetType: "server"}
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

// Every producer, and the per-producer tally beside the page.
//
// The list this endpoint returns is what Risk & Compliance → Findings renders,
// and it carried a compliance-only scope until the eol and vulnerability
// producers shipped. The response has to CARRY a non-compliance row — one whose
// subject is a software install and whose control_id is the nil uuid — or the
// contract would still be describing the old, narrower answer.
func TestContract_ListFindings_200_everyProducer(t *testing.T) {
	sv := loadSpec(t)
	compliance := sampleFinding()
	eol := sampleFinding()
	eol.Producer = "eol"
	eol.Kind = "software_end_of_life"
	eol.ControlID = uuid.Nil
	eol.SubjectType = "software_install"
	eol.Severity = "medium"
	eol.Score = 50
	eol.Summary = "openssl 1.1.1 is end of life (412 days ago)"
	eol.Evidence = map[string]any{
		"catalogue_id":         uuid.New().String(),
		"catalogue_source_url": "https://endoflife.date/openssl",
	}
	vuln := sampleFinding()
	vuln.Producer = "vulnerability"
	vuln.Kind = "known_vulnerability"
	vuln.ControlID = uuid.Nil
	vuln.SubjectType = "software_install"
	vuln.Severity = "critical"
	vuln.Score = 98
	vuln.Evidence = map[string]any{"cves": []any{map[string]any{"cve_id": "CVE-2026-1000"}}}

	svc := &stubFindingsStore{
		list:           []models.ComplianceFinding{compliance, eol, vuln},
		listTotal:      3,
		producerCounts: map[string]int{"compliance": 1, "eol": 1, "vulnerability": 1},
	}
	w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingListResponse", w.Body.Bytes())

	if !strings.Contains(w.Body.String(), `"producer_counts"`) {
		t.Error("the response carries no producer_counts; the page's producer facets have nothing to count")
	}
	// The default is EVERY producer. A filter left set here would make the
	// widening a no-op that still passed every schema assertion above.
	if svc.lastFilters == nil || svc.lastFilters.Producer != "" {
		t.Errorf("ListFindings was called with Producer=%q, want \"\" (every producer) by default", svc.lastFilters.Producer)
	}
}

func TestContract_ListFindings_200_producerFilterReachesTheService(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFindingsStore{producerCounts: map[string]int{"eol": 4}}
	w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings?producer=eol", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingListResponse", w.Body.Bytes())
	if svc.lastFilters == nil || svc.lastFilters.Producer != "eol" {
		t.Fatalf("the producer filter did not reach the service (%+v) — a query parameter the handler drops narrows nothing and looks fine", svc.lastFilters)
	}
}

func TestContract_ListFindings_400_unknownProducer(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFindingsStore{}
	w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings?producer=eol-typo", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if svc.lastFilters != nil {
		t.Error("an unregistered producer key reached the service; it would have listed EVERY producer while the caller believed it had narrowed to one")
	}
}

// A failed COUNT must not fail the page: the findings are the answer and the
// facet numbers are navigation.
func TestContract_ListFindings_200_producerCountFailureDoesNotFailThePage(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFindingsStore{
		list:        []models.ComplianceFinding{sampleFinding()},
		listTotal:   1,
		producerErr: errors.New("boom"),
	}
	w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingListResponse", w.Body.Bytes())
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

// --- the subject filter ------------------------------------------------------
//
// This is what makes a count in a table clickable. The software surfaces render
// "3 vulnerabilities" from a per-install rollup and link here; if the parameter
// did not reach the service the link would open the whole tenant's findings
// stream while claiming to show one package's.

func TestContract_ListFindings_200_subjectFilterReachesTheService(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFindingsStore{}
	install := uuid.New()
	w := do(newFindingsEngine(svc), http.MethodGet,
		cBase+"/findings?subject_type=software_install&subject_id="+install.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingListResponse", w.Body.Bytes())
	if svc.lastFilters == nil {
		t.Fatal("the service was never called")
	}
	if svc.lastFilters.SubjectType != "software_install" {
		t.Errorf("SubjectType = %q, want software_install — a dropped filter lists the whole tenant while the link says otherwise", svc.lastFilters.SubjectType)
	}
	if svc.lastFilters.SubjectID == nil || *svc.lastFilters.SubjectID != install {
		t.Errorf("SubjectID = %v, want %s", svc.lastFilters.SubjectID, install)
	}
}

// Both or neither. Either half alone is refused rather than half-applied: a
// lone id can collide across subject vocabularies and a lone type is the
// producer filter with a worse name — and answering either with a WIDER set is
// the "filter that reads as applied and is not" failure this handler already
// refuses for `producer`.
func TestContract_ListFindings_400_subjectHalfGiven(t *testing.T) {
	sv := loadSpec(t)
	for _, q := range []string{
		"?subject_type=software_install",
		"?subject_id=" + uuid.New().String(),
	} {
		svc := &stubFindingsStore{}
		w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings"+q, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, w.Code)
			continue
		}
		sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		if svc.lastFilters != nil {
			t.Errorf("%s: reached the service; it would have answered the unfiltered stream", q)
		}
	}
}

func TestContract_ListFindings_400_unknownSubjectType(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFindingsStore{}
	w := do(newFindingsEngine(svc), http.MethodGet,
		cBase+"/findings?subject_type=softwareinstall&subject_id="+uuid.New().String(), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if svc.lastFilters != nil {
		t.Error("an unregistered subject type reached the service")
	}
}

func TestContract_ListFindings_400_badSubjectID(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFindingsStore{}
	w := do(newFindingsEngine(svc), http.MethodGet,
		cBase+"/findings?subject_type=software_install&subject_id=not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if svc.lastFilters != nil {
		t.Error("an unparseable subject id reached the service")
	}
}

// The other polarity: with NEITHER parameter the filter must stay off, or every
// caller that does not ask for a subject would get an empty page.
func TestContract_ListFindings_200_noSubjectFilterByDefault(t *testing.T) {
	svc := &stubFindingsStore{}
	w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if svc.lastFilters == nil {
		t.Fatal("the service was never called")
	}
	if svc.lastFilters.SubjectType != "" || svc.lastFilters.SubjectID != nil {
		t.Errorf("a subject filter was applied without being asked for: %+v", svc.lastFilters)
	}
}

// --- free-text search (`q`) ------------------------------------------------
//
// The page's search box used to narrow the rows it had already fetched, and it
// fetches at most five pages of 200. A term that matched only the 1,200th
// finding therefore answered "no findings match". These pin the parameter
// REACHING the service — a handler that drops it returns a perfectly valid 200
// over the unnarrowed set, which is the failure shape the whole thing is
// written against.

func TestContract_ListFindings_200_searchTermReachesTheService(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFindingsStore{producerCounts: map[string]int{"eol": 1}}
	w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings?q=openssl", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingListResponse", w.Body.Bytes())
	if svc.lastFilters == nil || svc.lastFilters.Search != "openssl" {
		t.Fatalf("the search term did not reach the service (%+v) — a dropped `q` lists the whole tenant under a link that promised a match", svc.lastFilters)
	}
}

// No `q` must leave the filter EMPTY, not defaulted to something. A search
// applied when none was asked for narrows a page nobody narrowed.
func TestContract_ListFindings_200_noSearchLeavesTheFilterEmpty(t *testing.T) {
	svc := &stubFindingsStore{producerCounts: map[string]int{}}
	w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if svc.lastFilters == nil || svc.lastFilters.Search != "" {
		t.Fatalf("Search = %q with no q= in the request", svc.lastFilters.Search)
	}
}

// An unmatchable term is a 200 with an empty page, NOT a 400. A search that
// finds nothing is an answer; only a filter KEY that does not exist is a
// caller bug (which is why `producer` is refused and this is not).
func TestContract_ListFindings_200_unmatchableSearchIsAnAnswerNotAnError(t *testing.T) {
	sv := loadSpec(t)
	svc := &stubFindingsStore{producerCounts: map[string]int{}}
	w := do(newFindingsEngine(svc), http.MethodGet, cBase+"/findings?q=%25%25%25", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FindingListResponse", w.Body.Bytes())
	if svc.lastFilters == nil || svc.lastFilters.Search != "%%%" {
		t.Fatalf("Search = %q, want the literal %%%%%% — the handler must not strip or interpret wildcards", svc.lastFilters.Search)
	}
}
