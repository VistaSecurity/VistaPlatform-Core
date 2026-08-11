package handlers

// Contract test for the compliance-engine tenant-facing framework HTTP surface.
//
// Fifth vertical slice for the spec-first API contract (ADR-0001), after the
// cbom-service/scopes pilot and the inventory-service infrastructure-assets,
// certificates, and crypto-configurations slices. This is the first slice for
// compliance-engine. It exercises the REAL gin handlers over httptest (with
// in-memory stub stores satisfying tenantFrameworkStore + frameworkLicenseStore,
// no database) and asserts that every response body conforms to the schema
// declared in api/openapi/compliance-engine.openapi.yaml.
//
// OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so we validate response bodies
// directly with santhosh-tekuri/jsonschema/v6 — same approach as the scopes
// and assets contract tests.
//
// If a handler's response shape drifts from the spec (a renamed field, a new
// required key, a wrong type), the matching test here fails. That is the
// guardrail: the spec cannot silently diverge from what the service returns.

import (
	"bytes"
	"encoding/json"
	"errors"
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
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"gopkg.in/yaml.v3"
)

const specBaseURI = "https://vistaplatform.local/compliance-engine.openapi.yaml"

// --- spec loading + response validation -----------------------------------

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// handlers -> internal -> compliance-engine -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "compliance-engine.openapi.yaml",
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

// stubTenantFrameworkStore satisfies tenantFrameworkStore — the Core,
// read-only tenant-framework surface. The authoring (custom-policies CRUD)
// half of this stub moved with its handlers to ee/policyauthoring.
type stubTenantFrameworkStore struct {
	publishedWithLicense    []models.PublishedFrameworkWithLicense
	publishedWithLicenseErr error
	published               []models.PlatformFramework
	publishedErr            error
	viewResult              *models.PlatformFramework
	viewErr                 error

	// tenant-authored framework READS (Core keeps these)
	tenantFramework     *models.TenantFramework
	tenantFrameworkErr  error
	tenantFrameworks    []models.TenantFramework
	tenantFrameworksErr error
}

func (s *stubTenantFrameworkStore) ListPublishedFrameworks(_ *uuid.UUID) ([]models.PlatformFramework, error) {
	return s.published, s.publishedErr
}

func (s *stubTenantFrameworkStore) ListPublishedFrameworksWithLicense(_ uuid.UUID) ([]models.PublishedFrameworkWithLicense, error) {
	return s.publishedWithLicense, s.publishedWithLicenseErr
}

func (s *stubTenantFrameworkStore) ViewFramework(_ uuid.UUID) (*models.PlatformFramework, error) {
	return s.viewResult, s.viewErr
}

// Tenant-framework reads — driven by the stub fields above.
func (s *stubTenantFrameworkStore) GetTenantFramework(_, _ uuid.UUID) (*models.TenantFramework, error) {
	return s.tenantFramework, s.tenantFrameworkErr
}

func (s *stubTenantFrameworkStore) ListTenantFrameworks(_ uuid.UUID) ([]models.TenantFramework, error) {
	return s.tenantFrameworks, s.tenantFrameworksErr
}

func (s *stubTenantFrameworkStore) ListControlMeasurements(_, _ uuid.UUID) ([]models.ControlMeasurement, error) {
	return nil, nil
}

// stubFrameworkLicenseStore satisfies frameworkLicenseStore.
type stubFrameworkLicenseStore struct {
	isLicensed          bool
	isLicensedErr       error
	licensed            []models.LicensedFrameworkResponse
	licensedErr         error
	available           []models.AvailableFrameworkResponse
	availableErr        error
	defaultFramework    *models.DefaultFrameworkResponse
	defaultFrameworkErr error
	subscribeErr        error
	cancelErr           error
	setDefaultErr       error
}

func (s *stubFrameworkLicenseStore) IsFrameworkLicensed(_, _ uuid.UUID) (bool, error) {
	return s.isLicensed, s.isLicensedErr
}

func (s *stubFrameworkLicenseStore) ListLicensedFrameworks(_ uuid.UUID) ([]models.LicensedFrameworkResponse, error) {
	return s.licensed, s.licensedErr
}

func (s *stubFrameworkLicenseStore) GetAvailableFrameworks(_ uuid.UUID) ([]models.AvailableFrameworkResponse, error) {
	return s.available, s.availableErr
}

func (s *stubFrameworkLicenseStore) GetDefaultFramework(_ uuid.UUID) (*models.DefaultFrameworkResponse, error) {
	return s.defaultFramework, s.defaultFrameworkErr
}

func (s *stubFrameworkLicenseStore) SubscribeFramework(_ uuid.UUID, _ models.ProvisionFrameworkInput, _ uuid.UUID) error {
	return s.subscribeErr
}

func (s *stubFrameworkLicenseStore) CancelSubscription(_, _ uuid.UUID) error { return s.cancelErr }

func (s *stubFrameworkLicenseStore) SetDefaultFramework(_, _ uuid.UUID) error {
	return s.setDefaultErr
}

// Unused-by-this-slice methods (present only to satisfy frameworkLicenseStore).
func (s *stubFrameworkLicenseStore) SelectFrameworks(_ uuid.UUID, _ []uuid.UUID, _ uuid.UUID, _ uuid.UUID) error {
	return nil
}

func (s *stubFrameworkLicenseStore) UnlockFrameworks(_ uuid.UUID, _ uuid.UUID) error {
	return nil
}

func (s *stubFrameworkLicenseStore) GetUserFrameworkPreference(_, _ uuid.UUID) (*uuid.UUID, error) {
	return nil, nil
}

func (s *stubFrameworkLicenseStore) SetUserFrameworkPreference(_, _, _ uuid.UUID) error {
	return nil
}

func (s *stubFrameworkLicenseStore) ClearUserFrameworkPreference(_, _ uuid.UUID) error {
	return nil
}

func (s *stubFrameworkLicenseStore) ListAllTenantSubscriptionsForAdmin(_ uuid.UUID) ([]models.LicensedFrameworkResponse, error) {
	return nil, nil
}

// --- test harness ----------------------------------------------------------

// newEngine mounts the in-scope routes on /api/v1/compliance-engine with a
// middleware that injects tenantID + userID as uuid.UUID (the way
// JWTMiddleware does in production — the handlers type-assert to uuid.UUID
// first, then fall back to string parsing).
func newEngine(tf *stubTenantFrameworkStore, fl *stubFrameworkLicenseStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})

	tenantHandlers := &TenantFrameworkHandlers{
		tenantFrameworkService:  tf,
		frameworkLicenseService: fl,
	}
	licenseHandlers := &FrameworkLicenseHandlers{
		frameworkLicenseService: fl,
	}

	grp.GET("/frameworks/published", tenantHandlers.ListPublishedFrameworks)
	grp.GET("/frameworks/published/:id", tenantHandlers.ViewFramework)
	grp.GET("/frameworks/licenses", licenseHandlers.ListLicensedFrameworks)
	grp.GET("/frameworks/available", licenseHandlers.GetAvailableFrameworks)
	grp.GET("/frameworks/default", licenseHandlers.GetDefaultFramework)
	grp.PUT("/frameworks/default", licenseHandlers.SetDefaultFramework)
	grp.POST("/frameworks/subscribe", licenseHandlers.SubscribeFramework)
	grp.DELETE("/frameworks/subscribe/:frameworkId", licenseHandlers.CancelSubscription)

	// Tenant frameworks — READS ONLY. The authoring routes are Enterprise
	// (ee/policyauthoring) and are covered by that package's contract test.
	grp.GET("/frameworks/tenant", tenantHandlers.ListTenantFrameworks)
	grp.GET("/frameworks/tenant/:id", tenantHandlers.GetTenantFramework)
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

// --- sample data ----------------------------------------------------------

func samplePlatformFramework() models.PlatformFramework {
	now := time.Now().UTC()
	return models.PlatformFramework{
		ID:                uuid.New(),
		Code:              "pci-dss-4-0",
		Name:              "PCI DSS 4.0",
		Version:           "4.0",
		Description:       "Payment Card Industry Data Security Standard",
		Organization:      "PCI Security Standards Council",
		Status:            "published",
		IsPlatformDefault: false,
		CreatedBy:         uuid.New(),
		CreatedAt:         now,
		UpdatedAt:         now,
		ControlsCount:     78,
	}
}

func samplePublishedWithLicense() models.PublishedFrameworkWithLicense {
	return models.PublishedFrameworkWithLicense{
		PlatformFramework: samplePlatformFramework(),
		IsLicensed:        true,
	}
}

func sampleLicensedFrameworkResponse() models.LicensedFrameworkResponse {
	now := time.Now().UTC().Format(time.RFC3339)
	return models.LicensedFrameworkResponse{
		ID:                  uuid.New().String(),
		TenantID:            uuid.New().String(),
		PlatformFrameworkID: uuid.New().String(),
		IsDefault:           true,
		SubscriptionStatus:  "active",
		ProvisionedBy:       "self_service",
		PurchasedAt:         now,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

func sampleAvailable() models.AvailableFrameworkResponse {
	pf := samplePlatformFramework()
	return models.AvailableFrameworkResponse{
		PlatformFramework: &pf,
		IsLicensed:        false,
		IsPlatformDefault: false,
	}
}

func sampleDefaultFramework() *models.DefaultFrameworkResponse {
	pf := samplePlatformFramework()
	return &models.DefaultFrameworkResponse{
		FrameworkID:        pf.ID.String(),
		FrameworkType:      "licensed",
		Framework:          &pf,
		SubscriptionStatus: "active",
	}
}

const aUUID = "11111111-1111-1111-1111-111111111111"

const tenantBase = "/api/v1/compliance-engine/frameworks/tenant"

// --- the contract tests ----------------------------------------------------

func TestContract_ListPublishedFrameworks_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubTenantFrameworkStore{
			publishedWithLicense: []models.PublishedFrameworkWithLicense{
				samplePublishedWithLicense(),
				samplePublishedWithLicense(),
			},
		},
		&stubFrameworkLicenseStore{},
	)
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/published", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PublishedFrameworkListResponse", w.Body.Bytes())
}

func TestContract_ViewPublishedFramework_200_licensed(t *testing.T) {
	sv := loadSpec(t)
	pf := samplePlatformFramework()
	eng := newEngine(
		&stubTenantFrameworkStore{viewResult: &pf},
		&stubFrameworkLicenseStore{isLicensed: true},
	)
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/published/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PublishedFrameworkViewResponse", w.Body.Bytes())
}

func TestContract_ViewPublishedFramework_200_unlicensed(t *testing.T) {
	sv := loadSpec(t)
	pf := samplePlatformFramework()
	// Framework Transparency: control + measurement detail is returned to ALL
	// tenants for a published framework, including unlicensed ones (the
	// strip-when-unlicensed gate was retired with per-framework billing,
	// ADR-0014). Seed a control so we can assert it survives.
	now := time.Now().UTC()
	pf.Controls = []models.PlatformFrameworkControl{{
		ID:               uuid.New(),
		FrameworkID:      pf.ID,
		ControlID:        "1.1",
		Title:            "Strong key sizes",
		Description:      "RSA keys must be at least 2048 bits.",
		BaselineSeverity: "High",
		CryptoRelevant:   true,
		CreatedAt:        now,
		UpdatedAt:        now,
	}}
	eng := newEngine(
		&stubTenantFrameworkStore{viewResult: &pf},
		&stubFrameworkLicenseStore{isLicensed: false},
	)
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/published/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PublishedFrameworkViewResponse", w.Body.Bytes())

	// The point of the feature: an unlicensed tenant still receives controls, with
	// licensed:false so the UI can mark the framework "available" not "activated".
	var resp struct {
		Framework struct {
			Controls []map[string]any `json:"controls"`
		} `json:"framework"`
		Licensed bool `json:"licensed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Licensed {
		t.Errorf("licensed = true, want false for an unlicensed tenant")
	}
	if len(resp.Framework.Controls) != 1 {
		t.Errorf("controls returned = %d, want 1 (controls must stay visible to unlicensed tenants)", len(resp.Framework.Controls))
	}
}

func TestContract_ViewPublishedFramework_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{}, &stubFrameworkLicenseStore{})
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/published/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ViewPublishedFramework_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubTenantFrameworkStore{viewErr: errors.New("published framework not found")},
		&stubFrameworkLicenseStore{},
	)
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/published/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListLicensedFrameworks_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubTenantFrameworkStore{},
		&stubFrameworkLicenseStore{
			licensed: []models.LicensedFrameworkResponse{sampleLicensedFrameworkResponse()},
		},
	)
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/licenses", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LicensedFrameworkListResponse", w.Body.Bytes())
}

func TestContract_GetAvailableFrameworks_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubTenantFrameworkStore{},
		&stubFrameworkLicenseStore{
			available: []models.AvailableFrameworkResponse{sampleAvailable()},
		},
	)
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/available", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AvailableFrameworkListResponse", w.Body.Bytes())
}

func TestContract_GetDefaultFramework_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubTenantFrameworkStore{},
		&stubFrameworkLicenseStore{defaultFramework: sampleDefaultFramework()},
	)
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/default", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DefaultFrameworkResponse", w.Body.Bytes())
}

// GetDefaultFramework returns the LegacyErrorWithDetails (extra `details` key)
// shape when the underlying service complains about a missing tenant row.
func TestContract_GetDefaultFramework_404_tenantMissing(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubTenantFrameworkStore{},
		&stubFrameworkLicenseStore{defaultFrameworkErr: errors.New("tenant not found")},
	)
	w := do(eng, http.MethodGet, "/api/v1/compliance-engine/frameworks/default", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyErrorWithDetails", w.Body.Bytes())
}

func TestContract_SetDefaultFramework_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{}, &stubFrameworkLicenseStore{})
	body := strings.NewReader(`{"framework_id":"` + aUUID + `"}`)
	w := do(eng, http.MethodPut, "/api/v1/compliance-engine/frameworks/default", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// Spec-quirk regression: SetDefaultFramework collapses every service error
// (including ones that morally are 404 or 500) to 400 with the raw service
// error string in `error`.
func TestContract_SetDefaultFramework_400_serviceError(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubTenantFrameworkStore{},
		&stubFrameworkLicenseStore{setDefaultErr: errors.New("framework not licensed")},
	)
	body := strings.NewReader(`{"framework_id":"` + aUUID + `"}`)
	w := do(eng, http.MethodPut, "/api/v1/compliance-engine/frameworks/default", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_SetDefaultFramework_400_missingField(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{}, &stubFrameworkLicenseStore{})
	body := strings.NewReader(`{}`)
	w := do(eng, http.MethodPut, "/api/v1/compliance-engine/frameworks/default", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_SubscribeFramework_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{}, &stubFrameworkLicenseStore{})
	body := strings.NewReader(`{"framework_id":"` + aUUID + `","set_as_default":true}`)
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/frameworks/subscribe", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// Spec-quirk regression: subscribe failures (already subscribed, tier limit,
// not published, DB error) collapse to 400 with the raw service error string.
func TestContract_SubscribeFramework_400_serviceError(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubTenantFrameworkStore{},
		&stubFrameworkLicenseStore{subscribeErr: errors.New("already subscribed")},
	)
	body := strings.NewReader(`{"framework_id":"` + aUUID + `"}`)
	w := do(eng, http.MethodPost, "/api/v1/compliance-engine/frameworks/subscribe", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CancelSubscription_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{}, &stubFrameworkLicenseStore{})
	w := do(eng, http.MethodDelete, "/api/v1/compliance-engine/frameworks/subscribe/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_CancelSubscription_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{}, &stubFrameworkLicenseStore{})
	w := do(eng, http.MethodDelete, "/api/v1/compliance-engine/frameworks/subscribe/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// TestContract_DriftIsCaught proves the guardrail actually validates: a body
// that drifts from the contract (a PublishedFramework missing required fields,
// plus an undeclared field that additionalProperties:false forbids) MUST be
// rejected. If this ever passes, the validator is rubber-stamping and the
// whole contract test is worthless.
func TestContract_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/PublishedFramework")
	if err != nil {
		t.Fatalf("compile PublishedFramework: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted PublishedFramework, but it passed — the guardrail is not actually checking")
	}
}

// =====================================================================
// Tenant frameworks — the Core READ surface. Authoring (create / update /
// delete of frameworks, controls, and measurement mappings) is the Enterprise
// custom_policies feature; its contract tests live in
// services/compliance-engine/ee/policyauthoring/contract_test.go.
// =====================================================================

func sampleTenantFramework() *models.TenantFramework {
	now := time.Now().UTC()
	return &models.TenantFramework{
		ID:            uuid.New(),
		TenantID:      uuid.New(),
		Name:          "Internal Crypto Standard",
		Version:       "1.0",
		Description:   "Org-internal cryptographic policy",
		CreatedBy:     uuid.New(),
		CreatedAt:     now,
		UpdatedAt:     now,
		ControlsCount: 2,
	}
}

func TestContract_ListTenantFrameworks_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{
		tenantFrameworks: []models.TenantFramework{*sampleTenantFramework()},
	}, &stubFrameworkLicenseStore{})
	w := do(eng, http.MethodGet, tenantBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantFrameworkListResponse", w.Body.Bytes())
}

func TestContract_GetTenantFramework_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{tenantFramework: sampleTenantFramework()}, &stubFrameworkLicenseStore{})
	w := do(eng, http.MethodGet, tenantBase+"/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantFrameworkResponse", w.Body.Bytes())
}

func TestContract_GetTenantFramework_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{}, &stubFrameworkLicenseStore{})
	w := do(eng, http.MethodGet, tenantBase+"/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantFramework_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubTenantFrameworkStore{tenantFrameworkErr: errors.New("framework not found")}, &stubFrameworkLicenseStore{})
	w := do(eng, http.MethodGet, tenantBase+"/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
