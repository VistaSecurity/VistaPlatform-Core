package cbom

// Contract test for the CBOM Artifacts HTTP surface.
//
// Second vertical slice in cbom-service (after the scopes pilot), and the
// first slice in this package. Mirrors services/cbom-service/internal/scopes/
// contract_test.go: stub stores wired into the real gin handler over httptest,
// every JSON response body validated against the schema declared in
// api/openapi/cbom-service.openapi.yaml.
//
// Binary responses (cyclonedx/spdx/pdf bytes) are intentionally NOT covered —
// they're not JSON, the spec documents that explicitly under x-quirks, and
// the relevant guardrail is the redirect/Content-Type behavior which is
// exercised by integration tests rather than the spec.

import (
	"bytes"
	"context"
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
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
	"gopkg.in/yaml.v3"
)

const specBaseURI = "https://vistaplatform.local/cbom-service.openapi.yaml"

// --- spec loading + response validation -----------------------------------

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// cbom -> internal -> cbom-service -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "cbom-service.openapi.yaml",
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

// --- in-memory stub stores -------------------------------------------------

type stubArtifactStore struct {
	list             []Artifact
	getResult        *Artifact
	getErr           error
	inlineContent    []byte
	inlineContentErr error
	softDeleteErr    error
}

func (s *stubArtifactStore) List(_ context.Context, _ uuid.UUID, _ *uuid.UUID, _ int) ([]Artifact, error) {
	return s.list, nil
}
func (s *stubArtifactStore) Get(_ context.Context, _, _ uuid.UUID) (*Artifact, error) {
	return s.getResult, s.getErr
}
func (s *stubArtifactStore) GetInlineContent(_ context.Context, _, _ uuid.UUID) ([]byte, error) {
	return s.inlineContent, s.inlineContentErr
}
func (s *stubArtifactStore) SoftDelete(_ context.Context, _, _ uuid.UUID) error {
	return s.softDeleteErr
}

type stubScopeGetter struct {
	result *scopes.Scope
	err    error
}

func (s *stubScopeGetter) Get(_ context.Context, _, _ uuid.UUID) (*scopes.Scope, error) {
	return s.result, s.err
}

type stubBuilder struct {
	out *BuildOutput
	err error
}

func (s *stubBuilder) Build(_ context.Context, _ *scopes.Scope, _ string) (*BuildOutput, error) {
	return s.out, s.err
}

type stubPersister struct {
	out   *Artifact
	err   error
	input *PersistInput
}

func (s *stubPersister) Persist(_ context.Context, in PersistInput) (*Artifact, error) {
	s.input = &in
	return s.out, s.err
}

type stubFeatureChecker struct {
	allowed bool
	err     error
	feature string
}

func (s *stubFeatureChecker) CheckFeatureAccess(_ uuid.UUID, feature string) (bool, error) {
	s.feature = feature
	return s.allowed, s.err
}

// --- test harness ----------------------------------------------------------

type handlerDeps struct {
	artifacts artifactStore
	scopes    *stubScopeGetter
	builder   *stubBuilder
	persister *stubPersister
	features  featureChecker
}

func newEngine(d handlerDeps) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/cbom-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New().String())
		c.Set("userID", uuid.New().String())
		c.Next()
	})
	h := &Handler{
		repo:      d.artifacts,
		builder:   d.builder,
		persister: d.persister,
		scopeRepo: d.scopes,
	}
	h.SetFeatureChecker(d.features)
	h.RegisterRoutes(grp)
	return r
}

func do(engine *gin.Engine, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// /cbom/generate requires an auth token to be extracted; provide one so
	// the handler reaches the builder/persister stubs.
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func sampleArtifact() Artifact {
	now := time.Now().UTC()
	return Artifact{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		ScopeID:              uuid.New(),
		ScopeVersion:         1,
		ScopeNameSnapshot:    "Production",
		Name:                 "Production — 2026-05-28",
		HasInlineContent:     true,
		ContentHash:          "deadbeef",
		SizeBytes:            1024,
		ComponentCount:       42,
		CycloneDXSpecVersion: "1.6",
		InputDataFreshnessAt: now,
		GeneratedAt:          now,
		GeneratedBy:          uuid.New(),
		Provenance: Provenance{
			GeneratorService: "cbom-service",
			GeneratorVersion: "phase-2.0",
		},
		Layers:    []Layer{},
		CreatedAt: now,
	}
}

func sampleScope() *scopes.Scope {
	now := time.Now().UTC()
	return &scopes.Scope{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		Name:      "Production",
		Version:   1,
		CreatedBy: uuid.New(),
		UpdatedBy: uuid.New(),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

const aUUID = "11111111-1111-1111-1111-111111111111"

// --- the contract tests ----------------------------------------------------

func TestContract_ListCBOMArtifacts_200(t *testing.T) {
	sv := loadSpec(t)
	// Non-empty on purpose: a nil slice serializes as `null`, which would
	// violate the array schema (mirrors the scopes null-on-empty finding).
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{list: []Artifact{sampleArtifact(), sampleArtifact()}},
	})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CBOMArtifactListResponse", w.Body.Bytes())
}

func TestContract_GetCBOMArtifact_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleArtifact()
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{getResult: &a},
	})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CBOMArtifact", w.Body.Bytes())
}

func TestContract_GetCBOMArtifact_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{getErr: ErrNotFound},
	})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCBOMArtifact_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
	})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteCBOMArtifact_204(t *testing.T) {
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
	})
	w := do(eng, http.MethodDelete, "/api/v1/cbom-service/cbom/artifacts/"+aUUID, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != "" {
		t.Fatalf("204 should have empty body, got %q", w.Body.String())
	}
}

func TestContract_DeleteCBOMArtifact_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{softDeleteErr: ErrNotFound},
	})
	w := do(eng, http.MethodDelete, "/api/v1/cbom-service/cbom/artifacts/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GenerateCBOMArtifact_202(t *testing.T) {
	sv := loadSpec(t)
	scope := sampleScope()
	persisted := sampleArtifact()
	persister := &stubPersister{out: &persisted}
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
		scopes:    &stubScopeGetter{result: scope},
		builder:   &stubBuilder{out: &BuildOutput{CanonicalBytes: []byte("{}"), ContentHash: "deadbeef"}},
		persister: persister,
		features:  &stubFeatureChecker{allowed: true},
	})
	body := strings.NewReader(`{"scope_id":"` + scope.ID.String() + `"}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "GenerateCBOMResponse", w.Body.Bytes())
	if persister.input == nil {
		t.Fatal("persister input was not captured")
	}
	if !persister.input.Sign || !persister.input.IncludeAttestation {
		t.Fatalf("entitled default generation should request signing+attestation, got sign=%v attestation=%v",
			persister.input.Sign, persister.input.IncludeAttestation)
	}
}

func TestGenerateCBOMArtifact_DefaultsUnsignedWithoutCBOMSigningEntitlement(t *testing.T) {
	scope := sampleScope()
	persisted := sampleArtifact()
	persister := &stubPersister{out: &persisted}
	features := &stubFeatureChecker{allowed: false}
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
		scopes:    &stubScopeGetter{result: scope},
		builder:   &stubBuilder{out: &BuildOutput{CanonicalBytes: []byte("{}"), ContentHash: "deadbeef"}},
		persister: persister,
		features:  features,
	})

	body := strings.NewReader(`{"scope_id":"` + scope.ID.String() + `"}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	if features.feature != FeatureCBOMSigning {
		t.Fatalf("checked feature %q, want %q", features.feature, FeatureCBOMSigning)
	}
	if persister.input == nil {
		t.Fatal("persister input was not captured")
	}
	if persister.input.Sign || persister.input.IncludeAttestation {
		t.Fatalf("unentitled default generation must stay unsigned/unattested, got sign=%v attestation=%v",
			persister.input.Sign, persister.input.IncludeAttestation)
	}
}

func TestGenerateCBOMArtifact_ExplicitPaidEvidenceWithoutEntitlementGets402(t *testing.T) {
	cases := []struct {
		name string
		body func(scopeID string) string
	}{
		{
			name: "sign",
			body: func(scopeID string) string {
				return `{"scope_id":"` + scopeID + `","sign":true}`
			},
		},
		{
			name: "include_attestation",
			body: func(scopeID string) string {
				return `{"scope_id":"` + scopeID + `","include_attestation":true}`
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := sampleScope()
			persisted := sampleArtifact()
			persister := &stubPersister{out: &persisted}
			eng := newEngine(handlerDeps{
				artifacts: &stubArtifactStore{},
				scopes:    &stubScopeGetter{result: scope},
				builder:   &stubBuilder{out: &BuildOutput{CanonicalBytes: []byte("{}"), ContentHash: "deadbeef"}},
				persister: persister,
				features:  &stubFeatureChecker{allowed: false},
			})

			w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", strings.NewReader(tc.body(scope.ID.String())))
			if w.Code != http.StatusPaymentRequired {
				t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
			}
			if persister.input != nil {
				t.Fatal("explicit paid evidence request should be rejected before persisting")
			}
		})
	}
}

func TestContract_GenerateCBOMArtifact_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
		scopes:    &stubScopeGetter{},
	})
	// Missing required scope_id triggers gin's binding:"required" path.
	body := strings.NewReader(`{}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GenerateCBOMArtifact_404_scopeMissing(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
		scopes:    &stubScopeGetter{err: scopes.ErrNotFound},
	})
	body := strings.NewReader(`{"scope_id":"` + aUUID + `"}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// The download endpoint's success bodies are binary and out of contract scope
// (see the header comment), but its edition refusal is JSON and must match the
// declared 402 — that response is what a client renders as an upgrade prompt.
//
// newEngine wires no ArtifactFormatter, which *is* the Core edition, so this
// also pins that the stock handler refuses the Enterprise formats. Note the
// stub store has no artifact loaded: the gate fires before any read, which is
// the documented ordering (x-quirks on the path).
func TestContract_DownloadCBOMArtifact_402_coreEdition(t *testing.T) {
	sv := loadSpec(t)
	for _, format := range []string{"spdx", "pdf"} {
		t.Run(format, func(t *testing.T) {
			eng := newEngine(handlerDeps{artifacts: &stubArtifactStore{}})
			w := do(eng, http.MethodGet,
				"/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format="+format, nil)
			if w.Code != http.StatusPaymentRequired {
				t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		})
	}
}

func TestContract_VerifyCBOMArtifact_200(t *testing.T) {
	sv := loadSpec(t)
	a := sampleArtifact()
	eng := newEngine(handlerDeps{
		// Returning ErrNotFound on GetInlineContent steers the handler down
		// the "bytes not loadable" branch — hash_valid stays false,
		// signature_checked stays false. Still a valid 200 + VerifyResponse,
		// which is exactly what the contract covers.
		artifacts: &stubArtifactStore{
			getResult:        &a,
			inlineContentErr: errors.New("no inline content"),
		},
	})
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/verify", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "VerifyResponse", w.Body.Bytes())
}

// TestContract_DriftIsCaught proves the guardrail actually validates: a body
// that drifts from the contract (a CBOMArtifact missing required fields, plus
// an undeclared field that additionalProperties:false forbids) MUST be
// rejected. If this ever passes, the validator is rubber-stamping.
func TestContract_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/CBOMArtifact")
	if err != nil {
		t.Fatalf("compile CBOMArtifact: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted CBOMArtifact, but it passed — the guardrail is not actually checking")
	}
}
