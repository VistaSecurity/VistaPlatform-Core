package handlers

// Contract test for the crypto-risks HTTP surface (Risk & Compliance → Crypto
// Risks). Extends the inventory-service spec-first contract (ADR-0001) and
// reuses the shared harness (loadSpec / assertConforms / do / aUUID) defined in
// asset_contract_test.go — only the crypto-risks stub + engine + cases live
// here.
//
// CryptoRisksHandlers was made testable by depending on the small
// cryptoRisksService interface (the concrete *services.CryptoRisksService still
// satisfies it), so these tests drive the real handlers with an in-memory stub
// — no database.

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// --- stub cryptoRisksService ----------------------------------------------

type stubCryptoRisksService struct {
	summary    *services.CryptoRisksSummary
	summaryErr error
	list       *services.CryptoRisksResponse
	listByPage map[int]*services.CryptoRisksResponse
	listCalls  []services.CryptoRiskFilters
	listErr    error
	risk       *services.CryptoRisk
	riskErr    error
}

func (s *stubCryptoRisksService) GetSummary(_ uuid.UUID) (*services.CryptoRisksSummary, error) {
	return s.summary, s.summaryErr
}
func (s *stubCryptoRisksService) ListRisks(_ uuid.UUID, filters services.CryptoRiskFilters) (*services.CryptoRisksResponse, error) {
	s.listCalls = append(s.listCalls, filters)
	if s.listByPage != nil {
		if response, ok := s.listByPage[filters.Page]; ok {
			return response, s.listErr
		}
		return &services.CryptoRisksResponse{Risks: []services.CryptoRisk{}, Page: filters.Page, PageSize: filters.PageSize}, s.listErr
	}
	return s.list, s.listErr
}
func (s *stubCryptoRisksService) GetRiskByID(_, _ uuid.UUID) (*services.CryptoRisk, error) {
	return s.risk, s.riskErr
}

func newCryptoRisksEngine(svc *stubCryptoRisksService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	h := &CryptoRisksHandlers{service: svc}
	grp.GET("/crypto-risks", h.ListRisks)
	grp.GET("/crypto-risks/summary", h.GetSummary)
	grp.GET("/crypto-risks/export", h.ExportRisks)
	grp.GET("/crypto-risks/:id", h.GetRisk)
	return r
}

// sampleRisk sets the optional asset/crypto enrichment fields too.
func sampleRisk() services.CryptoRisk {
	return services.CryptoRisk{
		ID:                     uuid.New(),
		TenantID:               uuid.New(),
		AssetID:                uuid.New(),
		CryptoImplementationID: uuid.New(),
		Severity:               "high",
		Category:               "protocol",
		IssueType:              "deprecated_tls",
		CurrentValue:           "TLS 1.0",
		Description:            "Deprecated TLS version negotiated",
		Recommendation:         "Disable TLS 1.0/1.1; require TLS 1.2+",
		DetectedAt:             time.Now().UTC(),
		AssetHostname:          strPtr("web-01.example.com"),
		AssetIPAddress:         strPtr("10.0.0.5"),
		AssetPort:              intPtr(443),
		AssetType:              "server",
		Protocol:               "tls",
		ProtocolVersion:        strPtr("1.0"),
		CipherSuite:            strPtr("TLS_RSA_WITH_AES_128_CBC_SHA"),
	}
}

// minimalRisk leaves the omitempty enrichment fields unset — they must be ABSENT
// (not null), proving the spec's optional-key handling holds.
func minimalRisk() services.CryptoRisk {
	return services.CryptoRisk{
		ID:                     uuid.New(),
		TenantID:               uuid.New(),
		AssetID:                uuid.New(),
		CryptoImplementationID: uuid.New(),
		Severity:               "medium",
		Category:               "algorithm",
		IssueType:              "weak_cipher",
		CurrentValue:           "3DES",
		Description:            "Weak symmetric cipher",
		Recommendation:         "Migrate to AES-GCM",
		DetectedAt:             time.Now().UTC(),
	}
}

// --- the contract tests ----------------------------------------------------

func TestContract_ListCryptoRisks_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoRisksEngine(&stubCryptoRisksService{list: &services.CryptoRisksResponse{
		Risks:      []services.CryptoRisk{sampleRisk(), minimalRisk()},
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks?page=1&page_size=20", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoRisksResponse", w.Body.Bytes())
}

func TestContract_CryptoRisksSummary_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoRisksEngine(&stubCryptoRisksService{summary: &services.CryptoRisksSummary{
		Critical: 1, High: 2, Medium: 3, Informational: 4,
		TotalAffected: 5, ProtocolIssues: 2, AlgorithmIssues: 1,
		CertificateIssues: 1, KeySizeIssues: 0,
	}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks/summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoRisksSummary", w.Body.Bytes())
}

func TestContract_GetCryptoRisk_200(t *testing.T) {
	sv := loadSpec(t)
	r := sampleRisk()
	eng := newCryptoRisksEngine(&stubCryptoRisksService{risk: &r})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CryptoRisk", w.Body.Bytes())
}

func TestContract_GetCryptoRisk_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoRisksEngine(&stubCryptoRisksService{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// GetRisk maps the no-rows sentinel to 404 (string-matched in the handler).
func TestContract_GetCryptoRisk_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoRisksEngine(&stubCryptoRisksService{riskErr: errors.New("sql: no rows in result set")})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- CSV export (Risk & Compliance → Crypto Risks → Export) ----------------
//
// The 200 body is a text/csv attachment, not JSON, so these cases assert the
// status + Content-Type/Content-Disposition headers rather than a JSON schema.
// The error path still returns the standard JSON LegacyError, validated as usual.

func TestContract_ExportCryptoRisks_200(t *testing.T) {
	eng := newCryptoRisksEngine(&stubCryptoRisksService{list: &services.CryptoRisksResponse{
		Risks:      []services.CryptoRisk{sampleRisk(), minimalRisk()},
		Total:      2,
		Page:       1,
		PageSize:   10000,
		TotalPages: 1,
	}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks/export", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("Content-Type = %q, want text/csv", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "crypto-risks.csv") {
		t.Fatalf("Content-Disposition = %q, want attachment crypto-risks.csv", cd)
	}
	// The CSV always carries the header row even when rows are present.
	if !strings.HasPrefix(w.Body.String(), "ID,Severity,Category,") {
		t.Fatalf("CSV body missing expected header row; got: %q", w.Body.String())
	}
}

func TestContract_ExportCryptoRisks_PaginatesPastFirstClampedPage(t *testing.T) {
	firstPage := make([]services.CryptoRisk, services.MaxCryptoRiskPageSize)
	for i := range firstPage {
		firstPage[i] = exportRisk(i, fmt.Sprintf("page-one-%03d", i))
	}
	secondPage := []services.CryptoRisk{
		exportRisk(services.MaxCryptoRiskPageSize, "page-two-000"),
		exportRisk(services.MaxCryptoRiskPageSize+1, "page-two-001"),
	}
	svc := &stubCryptoRisksService{listByPage: map[int]*services.CryptoRisksResponse{
		1: {
			Risks:      firstPage,
			Total:      len(firstPage) + len(secondPage),
			Page:       1,
			PageSize:   services.MaxCryptoRiskPageSize,
			TotalPages: 2,
		},
		2: {
			Risks:      secondPage,
			Total:      len(firstPage) + len(secondPage),
			Page:       2,
			PageSize:   services.MaxCryptoRiskPageSize,
			TotalPages: 2,
		},
	}}
	eng := newCryptoRisksEngine(svc)

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks/export", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse exported CSV: %v\nbody=%s", err, w.Body.String())
	}
	if got, want := len(records), 1+services.MaxCryptoRiskPageSize+len(secondPage); got != want {
		t.Fatalf("CSV records = %d, want %d", got, want)
	}
	if got := records[1][3]; got != "page-one-000" {
		t.Fatalf("first exported issue_type = %q, want page-one-000", got)
	}
	if got := records[services.MaxCryptoRiskPageSize][3]; got != "page-one-099" {
		t.Fatalf("last first-page issue_type = %q, want page-one-099", got)
	}
	if got := records[services.MaxCryptoRiskPageSize+1][3]; got != "page-two-000" {
		t.Fatalf("first second-page issue_type = %q, want page-two-000", got)
	}
	if got := records[services.MaxCryptoRiskPageSize+2][3]; got != "page-two-001" {
		t.Fatalf("last second-page issue_type = %q, want page-two-001", got)
	}
	if got := len(svc.listCalls); got != 2 {
		t.Fatalf("ListRisks calls = %d, want 2", got)
	}
	for i, call := range svc.listCalls {
		if got, want := call.Page, i+1; got != want {
			t.Fatalf("call %d page = %d, want %d", i, got, want)
		}
		if got := call.PageSize; got != services.MaxCryptoRiskPageSize {
			t.Fatalf("call %d page_size = %d, want %d", i, got, services.MaxCryptoRiskPageSize)
		}
	}
}

// An empty result still produces a valid CSV (just the header row).
func TestContract_ExportCryptoRisks_200_empty(t *testing.T) {
	eng := newCryptoRisksEngine(&stubCryptoRisksService{list: &services.CryptoRisksResponse{
		Risks: []services.CryptoRisk{},
	}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks/export", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(w.Body.String(), "ID,Severity,Category,") {
		t.Fatalf("CSV body missing expected header row; got: %q", w.Body.String())
	}
}

func TestContract_ExportCryptoRisks_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newCryptoRisksEngine(&stubCryptoRisksService{listErr: errors.New("db down")})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/crypto-risks/export", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func exportRisk(seq int, issueType string) services.CryptoRisk {
	risk := minimalRisk()
	risk.ID = uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012d", seq+1))
	risk.IssueType = issueType
	risk.CurrentValue = fmt.Sprintf("value-%03d", seq)
	risk.DetectedAt = time.Date(2026, 7, 10, 5, 0, 0, 0, time.UTC)
	return risk
}

// TestContract_DriftIsCaught proves the guardrail validates: a drifted CryptoRisk
// (missing required fields + an undeclared field forbidden by
// additionalProperties:false) MUST be rejected.
func TestContract_CryptoRisks_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/CryptoRisk")
	if err != nil {
		t.Fatalf("compile CryptoRisk: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted CryptoRisk, but it passed — the guardrail is not actually checking")
	}
}
