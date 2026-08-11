package handlers

// Contract test for the Infrastructure Assets HTTP surface.
//
// Second vertical slice for the spec-first API contract (ADR-0001), after the
// cbom-service/scopes pilot. It exercises the REAL gin handlers over httptest
// (with an in-memory stub store, no database) and asserts that every response
// body conforms to the schema declared in
// api/openapi/inventory-service.openapi.yaml.
//
// OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so we validate response bodies
// directly with santhosh-tekuri/jsonschema/v6 — same approach as the scopes
// contract test.
//
// If a handler's response shape drifts from the spec (a renamed field, a new
// required key, a wrong type), the matching test here fails. That is the
// guardrail: the spec cannot silently diverge from what the service returns.

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
	"gopkg.in/yaml.v3"
)

const specBaseURI = "https://vistaplatform.local/inventory-service.openapi.yaml"

// --- spec loading + response validation -----------------------------------

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// handlers -> internal -> inventory-service -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "inventory-service.openapi.yaml",
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

// --- in-memory stub stores -------------------------------------------------

// stubAssetStore satisfies the assetStore interface used by AssetHandler. Only
// the methods exercised by this slice (list / get / update) carry behavior;
// the rest are present to satisfy the interface and panic if ever called.
type stubAssetStore struct {
	list          []models.Asset
	total         int
	listErr       error
	getResult     *models.Asset
	getErr        error
	updateRes     *models.Asset
	updateErr     error
	cryptoImpls   []models.CryptoImplementation
	riskSummary   *models.RiskSummary
	riskErr       error
	trend         []models.PostureTrendPoint
	trendErr      error
	pqcReady      *models.PQCReadinessSummary
	pqcReadyErr   error
	facets        []models.AssetFacetBucket
	facetsErr     error
	stats         *models.AssetStats
	statsErr      error
	history       []models.AssetHistory
	historyErr    error
	createRes     *models.Asset
	createErr     error
	deleteErr     error
	hardDeleteErr error
	restoreErr    error
	elevatedAsset *models.Asset
	elevateErr    error
	recentCount   int
	recentErr     error
	gotFilters    models.AssetFilters
}

func (s *stubAssetStore) GetAssets(_ uuid.UUID, filters models.AssetFilters) ([]models.Asset, int, error) {
	s.gotFilters = filters
	return s.list, s.total, s.listErr
}
func (s *stubAssetStore) GetAssetByID(_, _ uuid.UUID) (*models.Asset, error) {
	return s.getResult, s.getErr
}
func (s *stubAssetStore) GetCryptoImplementations(_, _ uuid.UUID) ([]models.CryptoImplementation, error) {
	return s.cryptoImpls, nil
}
func (s *stubAssetStore) UpdateAsset(_, _ uuid.UUID, _ models.AssetInput) (*models.Asset, error) {
	return s.updateRes, s.updateErr
}

func (s *stubAssetStore) GetAssetHistory(_, _ uuid.UUID) ([]models.AssetHistory, error) {
	return s.history, s.historyErr
}
func (s *stubAssetStore) GetRiskSummary(_ uuid.UUID) (*models.RiskSummary, error) {
	return s.riskSummary, s.riskErr
}
func (s *stubAssetStore) GetPostureTrend(_ uuid.UUID, _ int) ([]models.PostureTrendPoint, error) {
	return s.trend, s.trendErr
}
func (s *stubAssetStore) GetPQCReadinessSummary(_ uuid.UUID) (*models.PQCReadinessSummary, error) {
	return s.pqcReady, s.pqcReadyErr
}
func (s *stubAssetStore) GetAssetStats(_ uuid.UUID, _ string) (*models.AssetStats, error) {
	return s.stats, s.statsErr
}
func (s *stubAssetStore) GetRecentAssetsCount(_ uuid.UUID, _ int, _ models.AssetFilters) (int, error) {
	return s.recentCount, s.recentErr
}
func (s *stubAssetStore) GetAssetFacets(_ uuid.UUID, _ models.AssetFilters, _ string, _ int) ([]models.AssetFacetBucket, error) {
	return s.facets, s.facetsErr
}
func (s *stubAssetStore) GetTenantActivitySummary(_ uuid.UUID) (*services.TenantActivitySummary, error) {
	return nil, nil
}
func (s *stubAssetStore) CreateAsset(_ uuid.UUID, _ models.AssetInput) (*models.Asset, error) {
	return s.createRes, s.createErr
}
func (s *stubAssetStore) BulkCreateAssets(_ uuid.UUID, inputs []models.AssetInput) *models.BulkImportResult {
	res := models.NewBulkImportResult(len(inputs))
	for i := range inputs {
		res.Add(i, models.BulkRowCreated, nil, "")
	}
	return res
}
func (s *stubAssetStore) UpdateAssetService(_, _ uuid.UUID, _ models.UpdateAssetServiceInput) (*models.Asset, error) {
	return nil, nil
}
func (s *stubAssetStore) EnrichAllAssets(_ uuid.UUID) (int, error) { return 0, nil }
func (s *stubAssetStore) DeleteAsset(_, _ uuid.UUID) error         { return s.deleteErr }
func (s *stubAssetStore) RestoreAsset(_, _ uuid.UUID) error        { return s.restoreErr }
func (s *stubAssetStore) HardDeleteAsset(_, _ uuid.UUID) error     { return s.hardDeleteErr }
func (s *stubAssetStore) ElevateExternalConnection(_, _ uuid.UUID) (*models.Asset, error) {
	return s.elevatedAsset, s.elevateErr
}
func (s *stubAssetStore) Health() error { return nil }

// stubApprovalStore satisfies assetApprovalStore.
type stubApprovalStore struct {
	approveErr error
	denyErr    error
}

func (s *stubApprovalStore) ApproveAssets(_ uuid.UUID, _ []uuid.UUID) error { return s.approveErr }
func (s *stubApprovalStore) DenyAssets(_ uuid.UUID, _ []uuid.UUID, _ uuid.UUID) error {
	return s.denyErr
}

// --- test harness ----------------------------------------------------------

// newEngine wires the real asset + approval handlers under /api/v2 with a
// middleware that injects tenantID/userID as uuid.UUID, the way the real
// JWTMiddleware does (the handlers type-assert to uuid.UUID).
func newEngine(assets *stubAssetStore, approvals *stubApprovalStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})

	ah := NewAssetHandler(assets, nil)
	aph := NewAssetApprovalHandler(approvals)

	grp.GET("/inventory-service/infrastructure-assets", ah.GetAssets)
	grp.GET("/inventory-service/infrastructure-assets/:id", ah.GetAssetByID)
	grp.PUT("/inventory-service/infrastructure-assets/:id", ah.UpdateAsset)
	grp.POST("/inventory-service/infrastructure-assets/approve", aph.ApproveAssets)
	grp.POST("/inventory-service/infrastructure-assets/deny", aph.DenyAssets)
	grp.GET("/inventory-service/risk/summary", ah.GetRiskSummary)
	grp.GET("/inventory-service/risk/posture/trend", ah.GetPostureTrend)
	grp.GET("/inventory-service/pqc/summary", ah.GetPQCReadinessSummary)
	grp.GET("/inventory-service/infrastructure-assets/search", ah.SearchAssets)
	grp.GET("/inventory-service/infrastructure-assets/facets", ah.GetAssetFacets)
	grp.GET("/inventory-service/infrastructure-assets/stats", ah.GetAssetStats)
	grp.GET("/inventory-service/infrastructure-assets/recent-count", ah.GetRecentAssetsCount)
	grp.POST("/inventory-service/infrastructure-assets", ah.CreateAsset)
	grp.DELETE("/inventory-service/infrastructure-assets/:id", ah.DeleteAsset)
	grp.POST("/inventory-service/infrastructure-assets/:id/restore", ah.RestoreAsset)
	grp.GET("/inventory-service/infrastructure-assets/:id/crypto", ah.GetAssetCrypto)
	grp.GET("/inventory-service/infrastructure-assets/:id/history", ah.GetAssetHistory)
	return r
}

// stubPermissionChecker satisfies the permissionChecker interface so the
// HardDeleteAsset contract can exercise the real handler — including its 403
// path — without a database.
type stubPermissionChecker struct {
	allowed bool
	err     error
}

func (s *stubPermissionChecker) CheckPermission(_, _ uuid.UUID, _ string) (bool, error) {
	return s.allowed, s.err
}

// newAssetHardDeleteEngine mounts only the hard-delete route with an injected
// permission checker. (newEngine builds NewAssetHandler with a nil-DB repo,
// which would panic in checkPermission — hard delete needs the seam.)
func newAssetHardDeleteEngine(assets *stubAssetStore, perms permissionChecker) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	ah := NewAssetHandler(assets, nil)
	ah.perms = perms
	grp.DELETE("/inventory-service/infrastructure-assets/:id/hard", ah.HardDeleteAsset)
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
func intPtr(i int) *int       { return &i }

// sampleAsset mirrors what the real GetAssetByID / list path populate, with the
// always-present (non-omitempty) pointer fields set so the body exercises the
// nullable-or-string union in the spec.
func sampleAsset() models.Asset {
	now := time.Now().UTC()
	return models.Asset{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		Hostname:          strPtr("web-01.example.com"),
		IPAddress:         strPtr("10.0.0.5"),
		Port:              intPtr(443),
		AssetType:         "server",
		OperatingSystem:   strPtr("linux"),
		Environment:       strPtr("production"),
		BusinessUnit:      strPtr("platform"),
		OwnerEmail:        strPtr("ops@example.com"),
		Description:       strPtr("edge web server"),
		Tags:              map[string]interface{}{"team": "infra"},
		Metadata:          map[string]interface{}{"discovery_source": "sensor_discoveries"},
		AssetOwnership:    "owned",
		AssetStatus:       "monitoring",
		FirstDiscoveredAt: now,
		LastSeenAt:        now,
		CreatedAt:         now,
		UpdatedAt:         now,
		RiskScore:         42,
		RiskLevel:         "Medium",
	}
}

// nullFieldsAsset has the nullable pointer fields left nil, so the response
// serializes hostname/ip_address/etc. as JSON null — proving the spec's
// [string,"null"] unions and the required-but-nullable keys hold.
func nullFieldsAsset() models.Asset {
	now := time.Now().UTC()
	return models.Asset{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		AssetType:         "service",
		Tags:              map[string]interface{}{},
		Metadata:          map[string]interface{}{},
		AssetOwnership:    "unknown",
		AssetStatus:       "pending_approval",
		FirstDiscoveredAt: now,
		LastSeenAt:        now,
		CreatedAt:         now,
		UpdatedAt:         now,
		RiskScore:         0,
		RiskLevel:         "Informational",
	}
}

const aUUID = "11111111-1111-1111-1111-111111111111"

// --- the contract tests ----------------------------------------------------

func TestContract_ListAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{
		list:  []models.Asset{sampleAsset(), nullFieldsAsset()},
		total: 2,
	}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets?page=1&page_size=20", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetListResponse", w.Body.Bytes())
}

// Pins the asset_status query param the spec declares: the handler must bind
// the (repeatable) values into AssetFilters.AssetStatus so the service layer
// can override its monitoring-only default (the approval queue depends on it).
func TestContract_ListAssets_assetStatusFilterBinds(t *testing.T) {
	sv := loadSpec(t)
	store := &stubAssetStore{list: []models.Asset{sampleAsset()}, total: 1}
	eng := newEngine(store, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets?asset_status=pending_approval&asset_status=monitoring", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := store.gotFilters.AssetStatus; len(got) != 2 || got[0] != "pending_approval" || got[1] != "monitoring" {
		t.Fatalf("AssetStatus filter = %v, want [pending_approval monitoring]", got)
	}
	sv.assertConforms(t, "AssetListResponse", w.Body.Bytes())
}

// Pins the last_seen_before query param (the time arm of the Stale lens's
// server-side cut): the handler must bind it into
// AssetFilters.LastSeenBefore. RFC3339 validation itself lives in the service
// layer (see asset_query_builder tests).
func TestContract_ListAssets_lastSeenBeforeBinds(t *testing.T) {
	sv := loadSpec(t)
	store := &stubAssetStore{list: []models.Asset{sampleAsset()}, total: 1}
	eng := newEngine(store, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets?last_seen_before=2026-05-29T00%3A00%3A00Z", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := store.gotFilters.LastSeenBefore; got != "2026-05-29T00:00:00Z" {
		t.Fatalf("LastSeenBefore filter = %q, want 2026-05-29T00:00:00Z", got)
	}
	sv.assertConforms(t, "AssetListResponse", w.Body.Bytes())
}

// The service rejects a non-RFC3339 last_seen_before; the handler must map
// that validation error to a 400, not the generic 500.
func TestContract_ListAssets_lastSeenBeforeInvalid_400(t *testing.T) {
	store := &stubAssetStore{listErr: fmt.Errorf("invalid last_seen_before 'yesterday': must be an RFC3339 timestamp (e.g. 2026-05-29T00:00:00Z)")}
	eng := newEngine(store, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets?last_seen_before=yesterday", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestContract_GetAsset_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAsset()
	eng := newEngine(&stubAssetStore{getResult: &a}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetResponse", w.Body.Bytes())
}

func TestContract_GetAsset_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// GetAssetByID maps ANY service error (including no-rows) to 404 — a documented
// quirk captured by x-quirks in the spec.
func TestContract_GetAsset_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{getErr: io.EOF}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateAsset_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAsset()
	eng := newEngine(&stubAssetStore{getResult: &a, updateRes: &a}, &stubApprovalStore{})
	body := strings.NewReader(`{"asset_type":"server","environment":"production"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetResponse", w.Body.Bytes())
}

// A missing required asset_type is rejected at bind time -> 400 LegacyError.
func TestContract_UpdateAsset_400_missingType(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	body := strings.NewReader(`{"environment":"production"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ApproveAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	body := strings.NewReader(`{"asset_ids":["` + aUUID + `"]}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/approve", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ApprovalResult", w.Body.Bytes())
}

func TestContract_DenyAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	body := strings.NewReader(`{"asset_ids":["` + aUUID + `"]}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/deny", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ApprovalResult", w.Body.Bytes())
}

// Approve with no valid asset ids -> 400 LegacyError.
func TestContract_ApproveAssets_400_noValidIDs(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	body := strings.NewReader(`{"asset_ids":["not-a-uuid"]}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/approve", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// TestContract_DriftIsCaught proves the guardrail actually validates: a body
// that drifts from the contract (an Asset missing required fields, plus an
// undeclared field that additionalProperties:false forbids) MUST be rejected.
// If this ever passes, the validator is rubber-stamping and the whole contract
// test is worthless.
func TestContract_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/Asset")
	if err != nil {
		t.Fatalf("compile Asset: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted Asset, but it passed — the guardrail is not actually checking")
	}
}

// --- risk + PQC-readiness summaries (Dashboard / Risk & Compliance cards) ---

func TestContract_GetRiskSummary_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{riskSummary: &models.RiskSummary{
		TotalAssets: 120, HighRisk: 8, MediumRisk: 20, LowRisk: 80, UnknownRisk: 12,
		TotalCrypto: 340, CriticalFindings: 3,
	}}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/risk/summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RiskSummaryResponse", w.Body.Bytes())
}

func TestContract_GetRiskSummary_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{riskErr: io.EOF}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/risk/summary", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPostureTrend_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{trend: []models.PostureTrendPoint{
		{Date: "2026-05-27", RiskIndex: 7, Seeded: true},
		{Date: "2026-05-28", RiskIndex: 7, Seeded: false},
		{Date: "2026-05-29", RiskIndex: 6, Seeded: false},
	}}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/risk/posture/trend?days=30", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PostureTrendResponse", w.Body.Bytes())
}

func TestContract_GetPostureTrend_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{trendErr: io.EOF}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/risk/posture/trend", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetPQCReadinessSummary_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{pqcReady: &models.PQCReadinessSummary{
		TotalImplementations: 340, PQCImplementations: 51, ReadinessPercent: 15.0,
	}}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/pqc/summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// Returned bare (not wrapped).
	sv.assertConforms(t, "PQCReadinessSummary", w.Body.Bytes())
}

// --- asset reads: search / facets / stats / history / crypto-detail ---

func TestContract_SearchAssets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{list: []models.Asset{sampleAsset()}, total: 1}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/search?q=web", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetSearchResponse", w.Body.Bytes())
}

// Missing required q -> 400.
func TestContract_SearchAssets_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/search", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetAssetFacets_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{facets: []models.AssetFacetBucket{{Key: "production", Count: 12}, {Key: "staging", Count: 4}}}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/facets?level=environment", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetFacetsResponse", w.Body.Bytes())
}

func TestContract_GetAssetStats_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{stats: &models.AssetStats{
		Current: 120, Previous: 100, Change: 20, ChangePercent: 20.0, Period: "7d",
	}}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/stats?period=7d", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// Returned bare (not wrapped).
	sv.assertConforms(t, "AssetStats", w.Body.Bytes())
}

// An invalid period -> 400.
func TestContract_GetAssetStats_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/stats?period=99y", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetAssetHistory_200(t *testing.T) {
	sv := loadSpec(t)
	now := time.Now().UTC()
	uid := uuid.New()
	eng := newEngine(&stubAssetStore{history: []models.AssetHistory{{
		ID: uuid.New(), AssetID: uuid.New(), TenantID: uuid.New(),
		ActorUserID: &uid, Source: "api", Action: "update",
		ChangesJSON: map[string]interface{}{"asset_status": "monitoring"}, CreatedAt: now,
	}}}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetHistoryListResponse", w.Body.Bytes())
}

func TestContract_GetAssetCrypto_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{cryptoImpls: []models.CryptoImplementation{sampleCryptoConfig()}}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/crypto", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetCryptoResponse", w.Body.Bytes())
}

// --- asset write-CRUD: create / delete / restore + recent-count ---

func TestContract_CreateAsset_201(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAsset()
	eng := newEngine(&stubAssetStore{createRes: &a}, &stubApprovalStore{})
	body := strings.NewReader(`{"asset_type":"server","hostname":"web-01"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetResponse", w.Body.Bytes())
}

// stubAssetLimitChecker satisfies assetLimitChecker so the CreateAsset
// subscription-cap gate can be exercised without a database.
type stubAssetLimitChecker struct {
	res *sharedservices.LimitCheckResult
	err error
}

func (s *stubAssetLimitChecker) CheckAssetLimit(_ uuid.UUID, _ int) (*sharedservices.LimitCheckResult, error) {
	return s.res, s.err
}

// newAssetCreateEngineWithLimits mounts only the create route with an injected
// asset limit checker, so the cap path can be tested in isolation (newEngine
// leaves limits nil, which skips enforcement).
func newAssetCreateEngineWithLimits(assets *stubAssetStore, limits assetLimitChecker) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	ah := NewAssetHandler(assets, nil)
	ah.limits = limits
	grp.POST("/inventory-service/infrastructure-assets", ah.CreateAsset)
	return r
}

// Over the subscription asset cap -> 402 Payment Required, and the insert is
// never attempted.
func TestContract_CreateAsset_402_overLimit(t *testing.T) {
	limit := 100
	a := sampleAsset()
	eng := newAssetCreateEngineWithLimits(
		&stubAssetStore{createRes: &a},
		&stubAssetLimitChecker{res: &sharedservices.LimitCheckResult{
			Allowed:       false,
			CurrentUsage:  100,
			Limit:         &limit,
			Message:       "Asset limit exceeded: 100/100",
			UpgradePrompt: "Upgrade your plan or contact support to add more assets",
		}},
	)
	body := strings.NewReader(`{"asset_type":"server","hostname":"web-01"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets", body)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
}

// Under the cap -> create proceeds normally (201).
func TestContract_CreateAsset_201_underLimit(t *testing.T) {
	limit := 100
	a := sampleAsset()
	eng := newAssetCreateEngineWithLimits(
		&stubAssetStore{createRes: &a},
		&stubAssetLimitChecker{res: &sharedservices.LimitCheckResult{Allowed: true, CurrentUsage: 1, Limit: &limit}},
	)
	body := strings.NewReader(`{"asset_type":"server","hostname":"web-01"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
}

// Missing required asset_type -> 400.
func TestContract_CreateAsset_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// DeleteAsset returns 204 with no body.
func TestContract_DeleteAsset_204(t *testing.T) {
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodDelete, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body on 204, got: %s", w.Body.String())
	}
}

func TestContract_DeleteAsset_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodDelete, "/api/v2/inventory-service/infrastructure-assets/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// RestoreAsset re-fetches the asset after restoring and returns it under `asset`.
func TestContract_RestoreAsset_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAsset()
	eng := newEngine(&stubAssetStore{getResult: &a}, &stubApprovalStore{})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/restore", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetResponse", w.Body.Bytes())
}

func TestContract_RestoreAsset_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/not-a-uuid/restore", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetRecentAssetsCount_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{recentCount: 17}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/recent-count?days=7", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RecentAssetsCountResponse", w.Body.Bytes())
}

// A negative days param -> 400.
func TestContract_GetRecentAssetsCount_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/recent-count?days=-3", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- hard delete (DELETE /infrastructure-assets/{id}/hard) ------------------
//
// HardDeleteAsset runs its own assets.hard_delete RBAC check (via the injected
// permissionChecker) on top of the route-level gate, so these cases cover the
// 204 success, the 403 insufficient-permission path, a bad id, and the
// store-error 500.

func TestContract_HardDeleteAsset_204(t *testing.T) {
	eng := newAssetHardDeleteEngine(&stubAssetStore{}, &stubPermissionChecker{allowed: true})
	w := do(eng, http.MethodDelete, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/hard", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Fatalf("204 should have no body; got: %s", w.Body.String())
	}
}

func TestContract_HardDeleteAsset_403(t *testing.T) {
	sv := loadSpec(t)
	eng := newAssetHardDeleteEngine(&stubAssetStore{}, &stubPermissionChecker{allowed: false})
	w := do(eng, http.MethodDelete, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/hard", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	// Body carries error + required_permission; LegacyError permits the extra key.
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_HardDeleteAsset_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newAssetHardDeleteEngine(&stubAssetStore{}, &stubPermissionChecker{allowed: true})
	w := do(eng, http.MethodDelete, "/api/v2/inventory-service/infrastructure-assets/not-a-uuid/hard", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_HardDeleteAsset_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAssetHardDeleteEngine(&stubAssetStore{hardDeleteErr: io.EOF}, &stubPermissionChecker{allowed: true})
	w := do(eng, http.MethodDelete, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/hard", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A permission-check error (not a deny) maps to 500, distinct from the 403 deny.
func TestContract_HardDeleteAsset_500_permCheckError(t *testing.T) {
	sv := loadSpec(t)
	eng := newAssetHardDeleteEngine(&stubAssetStore{}, &stubPermissionChecker{err: io.EOF})
	w := do(eng, http.MethodDelete, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/hard", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
