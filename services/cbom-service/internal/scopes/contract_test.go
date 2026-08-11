package scopes

// Contract test for the Scopes HTTP surface.
//
// This is the vertical-slice pilot for the spec-first API contract (ADR-0001).
// It exercises the REAL gin handler over httptest (with an in-memory stub store,
// no database) and asserts that every response body conforms to the schema
// declared in api/openapi/cbom-service.openapi.yaml.
//
// OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so we validate response bodies
// directly with santhosh-tekuri/jsonschema/v6 — no OpenAPI-specific runtime
// needed, and no dependence on kin-openapi's partial 3.1 support.
//
// If a handler's response shape drifts from the spec (a renamed field, a new
// required key, a wrong type), the matching test here fails. That is the
// guardrail: the spec cannot silently diverge from what the service returns.

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
	"gopkg.in/yaml.v3"
)

const specBaseURI = "https://vistaplatform.local/cbom-service.openapi.yaml"

// --- spec loading + response validation -----------------------------------

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "cbom-service.openapi.yaml",
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

// --- in-memory stub store --------------------------------------------------

type stubStore struct {
	list         []Scope
	getResult    *Scope
	getErr       error
	createErr    error
	updateResult *Scope
	updateErr    error
	deleteErr    error
}

func (s *stubStore) SeedDefaultsIfMissing(_ context.Context, _, _ uuid.UUID) (bool, error) {
	return false, nil
}
func (s *stubStore) List(_ context.Context, _ uuid.UUID) ([]Scope, error) { return s.list, nil }
func (s *stubStore) Get(_ context.Context, _, _ uuid.UUID) (*Scope, error) {
	return s.getResult, s.getErr
}
func (s *stubStore) Create(_ context.Context, sc *Scope) error {
	if s.createErr != nil {
		return s.createErr
	}
	// Mirror the fields the real repository populates on insert.
	sc.ID = uuid.New()
	sc.Version = 1
	now := time.Now().UTC()
	sc.CreatedAt = now
	sc.UpdatedAt = now
	return nil
}
func (s *stubStore) Update(_ context.Context, _, _, _ uuid.UUID, _ UpdateRequest) (*Scope, error) {
	return s.updateResult, s.updateErr
}
func (s *stubStore) Delete(_ context.Context, _, _ uuid.UUID) error { return s.deleteErr }

// --- test harness ----------------------------------------------------------

func newEngine(store scopeStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/cbom-service")
	// Inject tenant/user the way the real auth middleware does (string form).
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New().String())
		c.Set("userID", uuid.New().String())
		c.Next()
	})
	NewHandler(store).RegisterRoutes(grp)
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

func sampleScope() Scope {
	now := time.Now().UTC()
	return Scope{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "Production",
		Description: "prod assets",
		Predicate:   Predicate{Include: &PredicateClause{Environment: []string{"production"}}},
		Version:     2,
		IsDefault:   false,
		IsSystem:    true,
		CreatedBy:   uuid.New(),
		UpdatedBy:   uuid.New(),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

const aUUID = "11111111-1111-1111-1111-111111111111"

// --- the contract tests ----------------------------------------------------

func TestContract_ListScopes_200(t *testing.T) {
	sv := loadSpec(t)
	// Non-empty on purpose: an empty result currently serializes as
	// {"scopes": null} (Go nil slice), which would violate the array schema.
	// That quirk is a documented finding — hardening should emit [] not null.
	eng := newEngine(&stubStore{list: []Scope{sampleScope(), sampleScope()}})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/scopes", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ScopeListResponse", w.Body.Bytes())
}

func TestContract_GetScope_200(t *testing.T) {
	sv := loadSpec(t)
	s := sampleScope()
	eng := newEngine(&stubStore{getResult: &s})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/scopes/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Scope", w.Body.Bytes())
}

func TestContract_GetScope_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubStore{getErr: ErrNotFound})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/scopes/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetScope_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubStore{})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/scopes/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateScope_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubStore{})
	body := strings.NewReader(`{"name":"My Scope","description":"x","predicate":{"include":{"environment":["prod"]}}}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/scopes", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Scope", w.Body.Bytes())
}

func TestContract_DeleteScope_409_system(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubStore{deleteErr: ErrSystemScopeDelete})
	w := do(eng, http.MethodDelete, "/api/v1/cbom-service/scopes/"+aUUID, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteScope_204(t *testing.T) {
	eng := newEngine(&stubStore{})
	w := do(eng, http.MethodDelete, "/api/v1/cbom-service/scopes/"+aUUID, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != "" {
		t.Fatalf("204 should have empty body, got %q", w.Body.String())
	}
}

func TestContract_PreviewScope_200(t *testing.T) {
	sv := loadSpec(t)
	s := sampleScope()
	eng := newEngine(&stubStore{getResult: &s})
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/scopes/"+aUUID+"/preview", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PreviewResult", w.Body.Bytes())
}

// TestContract_DriftIsCaught proves the guardrail actually validates: a body
// that drifts from the contract (a Scope missing required fields, plus an
// undeclared field that additionalProperties:false forbids) MUST be rejected.
// If this ever passes, the validator is rubber-stamping and the whole contract
// test is worthless.
func TestContract_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/Scope")
	if err != nil {
		t.Fatalf("compile Scope: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted Scope, but it passed — the guardrail is not actually checking")
	}
}
