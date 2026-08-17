package handlers

// Contract test for the algorithms HTTP surface (the algorithm reference
// catalogue). Extends the inventory-service spec-first contract (ADR-0001) and
// reuses the shared harness (loadSpec / assertConforms / do / strPtr / intPtr /
// aUUID) from asset_contract_test.go — only the algorithm stub + engine + cases
// live here.
//
// AlgorithmHandler was made testable by depending on the algorithmReader
// interface (the concrete *services.AlgorithmService still satisfies it), so
// these tests drive the real handlers with an in-memory stub — no database.

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// --- stub algorithmReader --------------------------------------------------

type stubAlgorithmReader struct {
	algorithms     []services.Algorithm
	listErr        error
	byCode         *services.Algorithm
	byCodeErr      error
	pqcProgress    *models.PQCProgress
	pqcProgressErr error
	batchResult    map[string]*services.Algorithm
	batchFailed    []string
	batchErr       error
	updated        *services.Algorithm
	updatedErr     error
	created        *services.Algorithm
	createdErr     error
}

func (s *stubAlgorithmReader) GetAllAlgorithms() ([]services.Algorithm, error) {
	return s.algorithms, s.listErr
}
func (s *stubAlgorithmReader) GetAlgorithmsByCategory(string) ([]services.Algorithm, error) {
	return s.algorithms, s.listErr
}
func (s *stubAlgorithmReader) GetPQCAlgorithms() ([]services.Algorithm, error) {
	return s.algorithms, s.listErr
}
func (s *stubAlgorithmReader) GetNonPQCAlgorithms() ([]services.Algorithm, error) {
	return s.algorithms, s.listErr
}
func (s *stubAlgorithmReader) GetStandardizedPQCAlgorithms() ([]services.Algorithm, error) {
	return s.algorithms, s.listErr
}
func (s *stubAlgorithmReader) GetAlgorithmByCode(string) (*services.Algorithm, error) {
	return s.byCode, s.byCodeErr
}
func (s *stubAlgorithmReader) GetBatchRecommendations([]string) (map[string]*services.Algorithm, []string, error) {
	return s.batchResult, s.batchFailed, s.batchErr
}
func (s *stubAlgorithmReader) GetPQCProgress(uuid.UUID) (*models.PQCProgress, error) {
	return s.pqcProgress, s.pqcProgressErr
}
func (s *stubAlgorithmReader) UpdateAlgorithmAssessment(string, services.AlgorithmAssessmentUpdate) (*services.Algorithm, error) {
	return s.updated, s.updatedErr
}
func (s *stubAlgorithmReader) CreateAlgorithm(services.AlgorithmCreate) (*services.Algorithm, error) {
	return s.created, s.createdErr
}
func (s *stubAlgorithmReader) DB() *database.DB { return nil }

func newAlgorithmEngine(svc *stubAlgorithmReader) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	h := &AlgorithmHandler{algorithmService: svc}
	grp.GET("/algorithms", h.ListAlgorithms)
	grp.GET("/algorithms/pqc", h.GetPQCAlgorithms)
	grp.GET("/algorithms/non-pqc", h.GetNonPQCAlgorithms)
	grp.GET("/algorithms/pqc/standardized", h.GetStandardizedPQCAlgorithms)
	grp.GET("/pqc/progress", h.GetPQCProgress)
	grp.GET("/algorithms/:code", h.GetAlgorithmByCode)
	grp.GET("/algorithms/:code/recommendations", h.GetAlgorithmRecommendations)
	grp.POST("/algorithms/recommendations/batch", h.GetBatchRecommendations)
	// Source-of-truth editor write routes. They live under /admin/ so the
	// admin-plane host split covers them. The route gate
	// (RequirePlatformPermission) is exercised in main.go, not here — these
	// contract tests drive the handlers directly to validate request/response
	// envelopes against the spec.
	grp.POST("/admin/algorithms", h.CreateAlgorithm)
	grp.PUT("/admin/algorithms/:code", h.UpdateAlgorithm)
	return r
}

// sampleAlgorithm sets the optional CycloneDX/enrichment fields too.
func sampleAlgorithm() services.Algorithm {
	return services.Algorithm{
		ID:                       uuid.New(),
		Code:                     "AES-256-GCM",
		Category:                 "symmetric",
		Subcategory:              strPtr("aead"),
		Name:                     "AES-256-GCM",
		Description:              strPtr("Authenticated encryption"),
		Strength:                 "recommended",
		DeprecationStatus:        "current",
		RiskScore:                5,
		RecommendedAlternatives:  []string{},
		ComplianceMappings:       map[string]interface{}{"fips": "approved"},
		Metadata:                 map[string]interface{}{"source": "seed"},
		IsStandard:               true,
		IsPQC:                    false,
		PQCStandardizationStatus: "none",
		CreatedAt:                "2026-01-01T00:00:00Z",
		UpdatedAt:                "2026-01-01T00:00:00Z",
		AlgorithmFamily:          strPtr("AES"),
		Primitive:                strPtr("ae"),
		Mode:                     strPtr("gcm"),
		CryptoFunctions:          []string{"encrypt", "decrypt"},
		ClassicalSecurityLevel:   intPtr(256),
	}
}

// minimalAlgorithm leaves omitempty fields unset and the required-but-nullable
// maps nil (→ JSON null), proving the spec's required/nullable handling holds.
func minimalAlgorithm() services.Algorithm {
	return services.Algorithm{
		ID:                       uuid.New(),
		Code:                     "RSA-1024",
		Category:                 "asymmetric",
		Name:                     "RSA 1024",
		Strength:                 "weak",
		DeprecationStatus:        "deprecated",
		RiskScore:                90,
		IsStandard:               true,
		IsPQC:                    false,
		PQCStandardizationStatus: "none",
		CreatedAt:                "2026-01-01T00:00:00Z",
		UpdatedAt:                "2026-01-01T00:00:00Z",
	}
}

// --- the contract tests ----------------------------------------------------

func TestContract_ListAlgorithms_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{algorithms: []services.Algorithm{sampleAlgorithm(), minimalAlgorithm()}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/algorithms", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmListResponse", w.Body.Bytes())
}

func TestContract_ListPQCAlgorithms_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{algorithms: []services.Algorithm{sampleAlgorithm()}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/algorithms/pqc", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmListResponse", w.Body.Bytes())
}

func TestContract_ListNonPQCAlgorithms_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{algorithms: []services.Algorithm{minimalAlgorithm()}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/algorithms/non-pqc", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmListResponse", w.Body.Bytes())
}

func TestContract_ListStandardizedPQCAlgorithms_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{algorithms: []services.Algorithm{sampleAlgorithm()}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/algorithms/pqc/standardized", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmListResponse", w.Body.Bytes())
}

func TestContract_GetAlgorithmByCode_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleAlgorithm()
	eng := newAlgorithmEngine(&stubAlgorithmReader{byCode: &a})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/algorithms/AES-256-GCM", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmResponse", w.Body.Bytes())
}

// A nil algorithm (no error) maps to 404.
func TestContract_GetAlgorithmByCode_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{byCode: nil})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/algorithms/NOPE", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_Algorithm_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/Algorithm")
	if err != nil {
		t.Fatalf("compile Algorithm: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted Algorithm, but it passed — the guardrail is not actually checking")
	}
}

// --- PQC migration progress (Risk & Compliance → crypto-risks-api.ts) ---

func TestContract_GetPQCProgress_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{pqcProgress: &models.PQCProgress{
		TotalImplementations: 340,
		PQCReady:             51,
		SymmetricSafe:        120,
		NonPQC:               169,
		PQCPercentage:        15.0,
		ByFamily: []models.PQCFamilyStats{
			{Family: "RSA", Count: 100, IsPQC: false, QuantumSafe: false, MigrateTo: "ML-KEM"},
			{Family: "AES", Count: 120, IsPQC: false, QuantumSafe: true},
		},
	}})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/pqc/progress", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PQCProgressResponse", w.Body.Bytes())
}

func TestContract_GetPQCProgress_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{pqcProgressErr: io.EOF})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/pqc/progress", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- per-algorithm recommendations (Inventory algorithm modal) -------------

func TestContract_GetAlgorithmRecommendations_200(t *testing.T) {
	sv := loadSpec(t)
	a := minimalAlgorithm() // weak algorithm with no alternatives -> alternatives null
	eng := newAlgorithmEngine(&stubAlgorithmReader{byCode: &a})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/algorithms/RSA-1024/recommendations", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmRecommendationsResponse", w.Body.Bytes())
}

// A nil algorithm (no error) maps to 404, same quirk as GetAlgorithmByCode.
func TestContract_GetAlgorithmRecommendations_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{byCode: nil})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/algorithms/NOPE/recommendations", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- batch recommendations (migration-path visualizer) ---------------------

func TestContract_BatchRecommendations_200(t *testing.T) {
	sv := loadSpec(t)
	// The batch item's current_algorithm carries a recorded alternative; byCode
	// resolves that alternative to a full algorithm object, exercising the
	// recommended_alternatives expansion.
	cur := minimalAlgorithm()
	cur.RecommendedAlternatives = []string{"AES-256-GCM"}
	alt := sampleAlgorithm()
	eng := newAlgorithmEngine(&stubAlgorithmReader{
		batchResult: map[string]*services.Algorithm{"RSA-1024": &cur},
		byCode:      &alt,
	})
	body := strings.NewReader(`{"algorithm_codes":["RSA-1024"]}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/algorithms/recommendations/batch", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BatchRecommendationsResponse", w.Body.Bytes())
}

func TestContract_BatchRecommendations_200_withFailed(t *testing.T) {
	sv := loadSpec(t)
	cur := sampleAlgorithm()
	eng := newAlgorithmEngine(&stubAlgorithmReader{
		batchResult: map[string]*services.Algorithm{"AES-256-GCM": &cur},
		batchFailed: []string{"BOGUS-CODE"},
		byCode:      &cur,
	})
	body := strings.NewReader(`{"algorithm_codes":["AES-256-GCM","BOGUS-CODE"]}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/algorithms/recommendations/batch", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "BatchRecommendationsResponse", w.Body.Bytes())
}

func TestContract_BatchRecommendations_400_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{})
	body := strings.NewReader(`{"algorithm_codes":[]}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/algorithms/recommendations/batch", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_BatchRecommendations_400_tooMany(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{})
	codes := make([]string, 0, 101)
	for i := 0; i < 101; i++ {
		codes = append(codes, `"c`+strconv.Itoa(i)+`"`)
	}
	body := strings.NewReader(`{"algorithm_codes":[` + strings.Join(codes, ",") + `]}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/algorithms/recommendations/batch", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- update algorithm (source-of-truth editor) -----------------------------

// Extended PUT: the full assessment set (strength, deprecation_status/date,
// risk_score, is_pqc, pqc_standardization_status, recommended_alternatives,
// migration_guidance, remediation_guidance, compliance_mappings) is accepted and
// the response conforms to AlgorithmResponse. byCode supplies the before-image.
func TestContract_UpdateAlgorithm_200(t *testing.T) {
	sv := loadSpec(t)
	before := sampleAlgorithm()
	after := sampleAlgorithm()
	after.Strength = "weak"
	after.DeprecationStatus = "deprecated"
	after.RiskScore = 80
	eng := newAlgorithmEngine(&stubAlgorithmReader{byCode: &before, updated: &after})
	body := strings.NewReader(`{
		"strength":"weak",
		"risk_score":80,
		"deprecation_status":"deprecated",
		"deprecation_date":"2027-01-01",
		"is_pqc":false,
		"pqc_standardization_status":"none",
		"migration_guidance":"Migrate to AES-256-GCM",
		"recommended_alternatives":["AES-256-GCM"],
		"remediation_guidance":{"summary":"upgrade"},
		"compliance_mappings":{"fips":"not-approved"}
	}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/admin/algorithms/RSA-1024", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmResponse", w.Body.Bytes())
}

// Deprecate is just a PUT with deprecation_status=obsolete (no dedicated route).
func TestContract_UpdateAlgorithm_Deprecate_200(t *testing.T) {
	sv := loadSpec(t)
	before := sampleAlgorithm()
	after := sampleAlgorithm()
	after.DeprecationStatus = "obsolete"
	eng := newAlgorithmEngine(&stubAlgorithmReader{byCode: &before, updated: &after})
	body := strings.NewReader(`{"deprecation_status":"obsolete"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/admin/algorithms/AES-256-GCM", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmResponse", w.Body.Bytes())
}

// Invalid strength enum -> 400 before the DB is touched.
func TestContract_UpdateAlgorithm_400_badStrength(t *testing.T) {
	sv := loadSpec(t)
	before := sampleAlgorithm()
	eng := newAlgorithmEngine(&stubAlgorithmReader{byCode: &before})
	body := strings.NewReader(`{"strength":"bogus"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/admin/algorithms/AES-256-GCM", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Unknown code (byCode nil) -> 404.
func TestContract_UpdateAlgorithm_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{byCode: nil})
	body := strings.NewReader(`{"strength":"strong"}`)
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/admin/algorithms/NOPE", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- create algorithm (source-of-truth editor) -----------------------------

func TestContract_CreateAlgorithm_201(t *testing.T) {
	sv := loadSpec(t)
	created := sampleAlgorithm()
	created.Code = "ML-KEM-768"
	created.Name = "ML-KEM-768"
	created.Category = "key_exchange"
	created.IsPQC = true
	created.PQCStandardizationStatus = "standardized"
	eng := newAlgorithmEngine(&stubAlgorithmReader{created: &created})
	body := strings.NewReader(`{
		"code":"ML-KEM-768",
		"name":"ML-KEM-768",
		"category":"key_exchange",
		"primitive":"kem",
		"is_pqc":true,
		"pqc_standardization_status":"standardized",
		"strength":"recommended",
		"risk_score":5
	}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/admin/algorithms", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlgorithmResponse", w.Body.Bytes())
}

// Missing required category -> 400.
func TestContract_CreateAlgorithm_400_missingCategory(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{})
	body := strings.NewReader(`{"code":"FOO","name":"Foo"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/admin/algorithms", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Invalid category enum -> 400.
func TestContract_CreateAlgorithm_400_badCategory(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{})
	body := strings.NewReader(`{"code":"FOO","name":"Foo","category":"nope"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/admin/algorithms", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Duplicate code -> 409.
func TestContract_CreateAlgorithm_409(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlgorithmEngine(&stubAlgorithmReader{createdErr: services.ErrAlgorithmExists})
	body := strings.NewReader(`{"code":"AES-256-GCM","name":"AES","category":"symmetric"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/admin/algorithms", body)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
