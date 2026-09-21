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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
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
	list            []models.Asset
	total           int
	listErr         error
	getResult       *models.Asset
	getErr          error
	updateRes       *models.Asset
	updateReport    *models.IdentifierUpdateReport
	updateErr       error
	gotActor        uuid.UUID
	cryptoImpls     []models.CryptoImplementation
	riskSummary     *models.RiskSummary
	riskErr         error
	trend           []models.PostureTrendPoint
	trendErr        error
	pqcReady        *models.PQCReadinessSummary
	pqcReadyErr     error
	facets          []models.AssetFacetBucket
	facetsErr       error
	stats           *models.AssetStats
	statsErr        error
	history         []models.AssetHistory
	historyErr      error
	classHistory    []models.AssetClassChange
	classHistoryErr error
	createRes       *models.Asset
	createErr       error
	deleteErr       error
	hardDeleteErr   error
	restoreErr      error
	elevatedAsset   *models.Asset
	elevateErr      error
	recentCount     int
	recentErr       error
	gotFilters      models.AssetFilters
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
func (s *stubAssetStore) UpdateAsset(_, _ uuid.UUID, _ models.AssetInput, actor uuid.UUID) (*models.Asset, *models.IdentifierUpdateReport, error) {
	s.gotActor = actor
	return s.updateRes, s.updateReport, s.updateErr
}

func (s *stubAssetStore) GetAssetHistory(_, _ uuid.UUID) ([]models.AssetHistory, error) {
	return s.history, s.historyErr
}

func (s *stubAssetStore) GetAssetClassHistory(_, _ uuid.UUID) ([]models.AssetClassChange, error) {
	return s.classHistory, s.classHistoryErr
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

func (s *stubApprovalStore) ApproveAssets(_ uuid.UUID, _ []uuid.UUID, _ uuid.UUID) error {
	return s.approveErr
}
func (s *stubApprovalStore) DenyAssets(_ uuid.UUID, _ []uuid.UUID, _ uuid.UUID) error {
	return s.denyErr
}
func (s *stubApprovalStore) AutoApproveAgentHost(_, _, _ uuid.UUID) (bool, error) {
	return false, nil
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
	grp.GET("/inventory-service/infrastructure-assets/:id/class-history", ah.GetAssetClassHistory)
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
		ID:              uuid.New(),
		TenantID:        uuid.New(),
		Hostname:        strPtr("web-01.example.com"),
		PrimaryAddress:  strPtr("10.0.0.5"),
		ClassKey:        assetclass.KeyServer,
		ClassPath:       "hardware.computer.server",
		ClassSourceKind: "measured",
		Attributes:      map[string]interface{}{"operating_system": "linux"},
		PrimaryEndpoint: &models.Endpoint{
			ID: uuid.New(), TenantID: uuid.New(), AssetID: uuid.New(),
			Address: strPtr("10.0.0.5"), Port: intPtr(443), Transport: "tcp",
			SourceKind: "measured", Status: "active",
			FirstSeenAt: now, LastSeenAt: now,
		},
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
		RiskAssessedBy:    []string{"crypto"},
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
		ClassKey:          assetclass.KeyApplication,
		ClassPath:         "application",
		ClassSourceKind:   "measured",
		Attributes:        map[string]interface{}{},
		Tags:              map[string]interface{}{},
		Metadata:          map[string]interface{}{},
		AssetOwnership:    "unknown",
		AssetStatus:       "pending_approval",
		FirstDiscoveredAt: now,
		LastSeenAt:        now,
		CreatedAt:         now,
		UpdatedAt:         now,
		RiskScore:         0,
		// Empty, not nil: an asset nothing has assessed. Score 0 with an empty
		// array is NOT ASSESSED; score 0 with {crypto} is assessed clean.
		RiskAssessedBy: []string{},
		RiskLevel:      "Informational",
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
	body := strings.NewReader(`{"class_key":"server","environment":"production"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetUpdateResponse", w.Body.Bytes())
}

// TestContract_UpdateAsset_ReportsWhatItDidToTheIdentifiers: the update is the
// only hand-driven write path, and `identifiers` used to be accepted and
// dropped. The response now says what was attached, what was retired, and —
// the part that matters — what was KEPT BACK, because a collector-minted
// identifier is not an edit form's to delete and a client that reported the
// deletion as successful would be lying on the next read.
func TestContract_UpdateAsset_ReportsWhatItDidToTheIdentifiers(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAsset()
	store := &stubAssetStore{getResult: &a, updateRes: &a, updateReport: &models.IdentifierUpdateReport{
		Attached: []models.IdentifierChange{
			{Kind: "serial_number", Value: "SN-1", SourceKind: "declared"},
		},
		Removed: []models.IdentifierChange{
			{Kind: "hostname", Value: "old-01", Scope: "tenant", SourceKind: "declared"},
		},
		Kept: []models.IdentifierChange{{
			Kind: "cloud_resource_id", Value: "arn:aws:ec2:::i-1", SourceKind: "measured",
			Reason: "issued by a collector, not by a person — an edit form does not retire it",
		}},
	}}
	eng := newEngine(store, &stubApprovalStore{})
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/infrastructure-assets/"+aUUID,
		strings.NewReader(`{"identifiers":[{"kind":"serial_number","value":"SN-1"}]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetUpdateResponse", w.Body.Bytes())

	var got struct {
		Identifiers *models.IdentifierUpdateReport `json:"identifiers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Identifiers == nil {
		t.Fatal("the response must carry the identifier report; without it a refused deletion reads as a successful one")
	}
	if len(got.Identifiers.Kept) != 1 || got.Identifiers.Kept[0].Reason == "" {
		t.Errorf("kept = %+v; a kept identifier must say WHY it was kept", got.Identifiers.Kept)
	}
	if store.gotActor == uuid.Nil {
		t.Error("the actor from the session must reach the service; an identifier edit is attributable")
	}
}

// TestContract_UpdateAsset_409OnAForeignIdentifier: the edit is refused and the
// body names the merge proposal that was opened. A 409 saying only "conflict"
// would leave the operator with no way to reach the asset that disagreed.
func TestContract_UpdateAsset_409OnAForeignIdentifier(t *testing.T) {
	sv := loadSpec(t)
	owner, proposal := uuid.New(), uuid.New()
	eng := newEngine(&stubAssetStore{updateErr: &services.IdentifierConflictError{
		Kind: "serial_number", Value: "SN-1", OwnerAssetID: owner, ProposalID: proposal,
	}}, &stubApprovalStore{})
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/infrastructure-assets/"+aUUID,
		strings.NewReader(`{"identifiers":[{"kind":"serial_number","value":"SN-1"}]}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IdentifierConflict", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), proposal.String()) {
		t.Errorf("the 409 must name the merge proposal it told the operator to read; body=%s", w.Body.String())
	}
}

// TestContract_UpdateAsset_400WhenItWouldStripTheLastIdentifier: an asset with
// no identifiers can never be matched again. The engine refuses to CREATE one;
// an edit must not be able to produce one by subtraction.
func TestContract_UpdateAsset_400WhenItWouldStripTheLastIdentifier(t *testing.T) {
	eng := newEngine(&stubAssetStore{updateErr: services.ErrIdentifierFloor}, &stubApprovalStore{})
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/infrastructure-assets/"+aUUID,
		strings.NewReader(`{"identifiers":[]}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "at least one identifier") {
		t.Errorf("the 400 must say what the floor is; body=%s", w.Body.String())
	}
}

// A partial update does NOT have to restate the class.
//
// This asserted 400 while `asset_type` carried `binding:"required"` on the
// input struct that create and update share — so changing an owner email meant
// resending the type, and a client that forgot silently got a 400 for a field
// it was not editing. The class is required on CREATE (checked in the handler,
// see TestContract_CreateAsset_400) and optional here.
func TestContract_UpdateAsset_200_partialWithoutClass(t *testing.T) {
	sv := loadSpec(t)
	updated := sampleAsset()
	eng := newEngine(&stubAssetStore{updateRes: &updated}, &stubApprovalStore{})
	body := strings.NewReader(`{"environment":"production"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetUpdateResponse", w.Body.Bytes())
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

func TestContract_Approval_409_ArchivedSource(t *testing.T) {
	for _, action := range []string{"approve", "deny"} {
		t.Run(action, func(t *testing.T) {
			eng := newEngine(&stubAssetStore{}, &stubApprovalStore{approveErr: services.ErrAssetLifecycleConflict, denyErr: services.ErrAssetLifecycleConflict})
			w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/"+action, strings.NewReader(`{"asset_ids":["`+uuid.NewString()+`"]}`))
			if w.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
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

// The list and facet envelopes carry the CANONICAL query that selected the
// rows, not the string the caller sent. ADR-0008 D4.4: an agent repeating an
// answer has to be able to show the query behind it, and the two differ — the
// platform AND-s its default scope in, and normalises the spelling.
//
// Both surfaces are asserted here because they have to agree: a rail whose
// counts were taken over a different predicate from its list is the drift the
// single-predicate design exists to prevent.
func TestContract_ListAndFacets_echoTheCanonicalQuery(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{
		list:   []models.Asset{sampleAsset()},
		total:  1,
		facets: []models.AssetFacetBucket{{Key: "production", Count: 12}},
	}, &stubApprovalStore{})

	const sent = "environment:PRODUCTION"
	// The default scope the platform adds; a caller that echoed its own input
	// would never show it, and would describe a wider set than it read.
	const want = "environment:PRODUCTION and status:monitoring"

	for _, tc := range []struct{ name, path, schema string }{
		{"list", "/api/v2/inventory-service/infrastructure-assets?query=" + url.QueryEscape(sent), "AssetListResponse"},
		{"facets", "/api/v2/inventory-service/infrastructure-assets/facets?level=environment&query=" + url.QueryEscape(sent), "AssetFacetsResponse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(eng, http.MethodGet, tc.path, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, tc.schema, w.Body.Bytes())

			var body struct {
				Query string `json:"query"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Query == "" {
				t.Fatalf("no query echo; a caller cannot show the query it ran. body=%s", w.Body.String())
			}
			if body.Query != want {
				t.Errorf("query echo = %q, want %q", body.Query, want)
			}
		})
	}
}

// An empty predicate is still a predicate: with no query and no filters the
// platform's own default scope is what ran, and the echo has to say so rather
// than going silent and leaving a caller to assume "everything".
func TestContract_ListAssets_echoShowsTheDefaultScope(t *testing.T) {
	eng := newEngine(&stubAssetStore{list: []models.Asset{sampleAsset()}, total: 1}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Query != "status:monitoring" {
		t.Errorf("query echo = %q, want the default scope the read applied", body.Query)
	}
}

// The default scope is a DEFAULT, not a floor: a caller who names `status`
// themselves gets their own term and nothing added. The echo is how they can
// tell, which is the only way an MCP agent can report honestly on the approval
// queue or on an asset a merge archived — both of which the default hides.
func TestContract_ListAssets_echoDropsTheDefaultWhenTheCallerNamesStatus(t *testing.T) {
	eng := newEngine(&stubAssetStore{list: []models.Asset{sampleAsset()}, total: 1}, &stubApprovalStore{})

	for _, tc := range []struct{ name, query, want string }{
		{"pending approval", "status:pending_approval", "status:pending_approval"},
		{"archived — where a merge tombstone lives", "status:archived", "status:archived"},
		{"a different column does NOT count", "stale_status:stale", "stale_status:stale and status:monitoring"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(eng, http.MethodGet,
				"/api/v2/inventory-service/infrastructure-assets?query="+url.QueryEscape(tc.query), nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			var body struct {
				Query string `json:"query"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Query != tc.want {
				t.Errorf("query echo = %q, want %q", body.Query, tc.want)
			}
		})
	}
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

// The class-history endpoint conforms to the spec, in both the shape a
// reclassified asset produces and the one its creation produces.
//
// Two rows, not one: `from_class_key` is REQUIRED to be absent on the creation
// row and present on every other, and a fixture with only one of them would
// pass whichever half the schema happened to get right.
func TestContract_GetAssetClassHistory_200(t *testing.T) {
	sv := loadSpec(t)
	now := time.Now().UTC()
	uid := uuid.New()
	from := "unknown_host"
	eng := newEngine(&stubAssetStore{classHistory: []models.AssetClassChange{
		{
			ID: uuid.New(), AssetID: uuid.New(), TenantID: uuid.New(),
			FromClassKey: &from, FromClassLabel: "Unknown host",
			ToClassKey: "printer", ToClassLabel: "Printer",
			Source: "proposal", ActorUserID: &uid,
			Evidence:  map[string]interface{}{"rule_ids": []string{"r-1"}},
			CreatedAt: now,
		},
		{
			ID: uuid.New(), AssetID: uuid.New(), TenantID: uuid.New(),
			ToClassKey: "unknown_host", ToClassLabel: "Unknown host",
			Source:    "classifier",
			Evidence:  map[string]interface{}{"class_source_kind": "measured"},
			CreatedAt: now.Add(-time.Hour),
		},
	}}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/class-history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetClassHistoryListResponse", w.Body.Bytes())
}

// An asset with no recorded class change answers with an EMPTY array, not
// `null`. `[]` and `null` are the same to a Go client and different to every
// TypeScript one, and the spec says array.
func TestContract_GetAssetClassHistory_EmptyIsAnArray(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAssetStore{}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/class-history", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !strings.Contains(got, `"class_history":[]`) {
		t.Errorf("body = %s, want an empty array under class_history", got)
	}
	sv.assertConforms(t, "AssetClassHistoryListResponse", w.Body.Bytes())
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
	body := strings.NewReader(`{"class_key":"server","hostname":"web-01"}`)
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
	body := strings.NewReader(`{"class_key":"server","hostname":"web-01"}`)
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
	body := strings.NewReader(`{"class_key":"server","hostname":"web-01"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
}

// Missing required class_key -> 400.
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

// ---------------------------------------------------------------------------
// The asset cap on the OTHER user-initiated managed-asset increases.
//
// Restore un-soft-deletes a row (the enforced count is `deleted_at IS NULL`),
// and elevate creates a managed asset from a third-party connection. Both
// used to bypass the cap that manual create and spreadsheet import enforce.
// ---------------------------------------------------------------------------

func newAssetCapEngine(assets *stubAssetStore, limits assetLimitChecker) *gin.Engine {
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
	grp.POST("/inventory-service/infrastructure-assets/:id/restore", ah.RestoreAsset)
	grp.POST("/inventory-service/external-connections/:id/elevate", ah.ElevateExternalConnection)
	return r
}

func overCap() *stubAssetLimitChecker {
	limit := 100
	return &stubAssetLimitChecker{res: &sharedservices.LimitCheckResult{
		Allowed: false, CurrentUsage: 100, Limit: &limit,
		Message:       "Asset limit exceeded: 100/100",
		UpgradePrompt: "Upgrade your plan or contact support to add more assets",
	}}
}

func TestContract_RestoreAsset_402_overLimit(t *testing.T) {
	a := sampleAsset()
	store := &stubAssetStore{getResult: &a}
	eng := newAssetCapEngine(store, overCap())
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/restore", nil)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
}

// A cap check that cannot be answered stops the restore (500), never passes it.
func TestContract_RestoreAsset_500_capCheckError(t *testing.T) {
	a := sampleAsset()
	eng := newAssetCapEngine(&stubAssetStore{getResult: &a}, &stubAssetLimitChecker{err: errors.New("resolver down")})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/restore", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestContract_RestoreAsset_200_underLimit(t *testing.T) {
	sv := loadSpec(t)
	limit := 100
	a := sampleAsset()
	eng := newAssetCapEngine(&stubAssetStore{getResult: &a},
		&stubAssetLimitChecker{res: &sharedservices.LimitCheckResult{Allowed: true, CurrentUsage: 1, Limit: &limit}})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/infrastructure-assets/"+aUUID+"/restore", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetResponse", w.Body.Bytes())
}

func TestContract_ElevateExternalConnection_402_overLimit(t *testing.T) {
	elevated := sampleAsset()
	eng := newAssetCapEngine(&stubAssetStore{elevatedAsset: &elevated}, overCap())
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/external-connections/"+uuid.New().String()+"/elevate", nil)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
}

func TestContract_ElevateExternalConnection_500_capCheckError(t *testing.T) {
	elevated := sampleAsset()
	eng := newAssetCapEngine(&stubAssetStore{elevatedAsset: &elevated}, &stubAssetLimitChecker{err: errors.New("resolver down")})
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/external-connections/"+uuid.New().String()+"/elevate", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}
