package handlers

// Contract test for the compliance scenarios + overrides read surface. Extends
// the compliance-engine spec-first contract (ADR-0001) and reuses the shared
// harness (loadSpec / assertConforms / do / specBaseURI / cBase / fUUID) from
// the framework + findings contract tests — only the scenario/override stubs +
// engine + cases live here.
//
// WorkspaceHandlers' scenarioService / overrideService fields are now the
// scenarioStore / overrideStore interfaces (the concrete services still satisfy
// them), so these tests drive the real handlers with in-memory stubs — no DB.

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
)

// --- stubs -----------------------------------------------------------------

type stubScenarioStore struct {
	list      []models.Scenario
	listErr   error
	byID      *models.Scenario
	byIDErr   error
	nameTaken bool
	created   *models.Scenario
	createErr error
	updated   *models.Scenario
	updateErr error
	deleteErr error

	gotTenant uuid.UUID // tenant the handler forwarded (regression pin for #528)
}

func (s *stubScenarioStore) CreateScenario(uuid.UUID, uuid.UUID, string, uuid.UUID, string, models.ScenarioFilters) (*models.Scenario, error) {
	return s.created, s.createErr
}
func (s *stubScenarioStore) UpdateScenario(_, _, _ uuid.UUID, _ string, _ models.ScenarioFilters) (*models.Scenario, error) {
	return s.updated, s.updateErr
}
func (s *stubScenarioStore) GetScenario(tenantID, _ uuid.UUID) (*models.Scenario, error) {
	s.gotTenant = tenantID
	return s.byID, s.byIDErr
}
func (s *stubScenarioStore) ListScenarios(uuid.UUID) ([]models.Scenario, error) {
	return s.list, s.listErr
}
func (s *stubScenarioStore) DeleteScenario(tenantID, _ uuid.UUID) error {
	s.gotTenant = tenantID
	return s.deleteErr
}
func (s *stubScenarioStore) CheckScenarioNameExists(uuid.UUID, string, *uuid.UUID) (bool, error) {
	return s.nameTaken, nil
}

type stubOverrideStore struct {
	list      []models.Override
	listErr   error
	created   *models.Override
	createErr error
	deleteErr error

	gotTenant uuid.UUID // tenant the handler forwarded (regression pin for #528)
}

func (s *stubOverrideStore) CreateOverride(uuid.UUID, uuid.UUID, *uuid.UUID, uuid.UUID, models.OverrideType, *string, *string, string, string) (*models.Override, error) {
	return s.created, s.createErr
}
func (s *stubOverrideStore) ListOverrides(uuid.UUID, *uuid.UUID) ([]models.Override, error) {
	return s.list, s.listErr
}
func (s *stubOverrideStore) DeleteOverride(tenantID, _ uuid.UUID) error {
	s.gotTenant = tenantID
	return s.deleteErr
}

func newWorkspaceEngine(sc *stubScenarioStore, ov *stubOverrideStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &WorkspaceHandlers{scenarioService: sc, overrideService: ov}
	grp.GET("/scenarios", h.ListScenarios)
	grp.GET("/scenarios/:id", h.GetScenario)
	grp.POST("/scenarios", h.CreateScenario)
	grp.PUT("/scenarios/:id", h.UpdateScenario)
	grp.DELETE("/scenarios/:id", h.DeleteScenario)
	grp.GET("/overrides", h.ListOverrides)
	grp.POST("/overrides", h.CreateOverride)
	grp.DELETE("/overrides/:id", h.DeleteOverride)
	return r
}

// ctxTenantForTest is the fixed context tenant used by the regression
// tests so they can assert the handler forwards THIS tenant into the store.
var ctxTenantForTest = uuid.MustParse("11111111-1111-1111-1111-111111111111")

func newWorkspaceEngineTenant(sc *stubScenarioStore, ov *stubOverrideStore, tenantID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", tenantID)
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &WorkspaceHandlers{scenarioService: sc, overrideService: ov}
	grp.GET("/scenarios/:id", h.GetScenario)
	grp.PUT("/scenarios/:id", h.UpdateScenario)
	grp.DELETE("/scenarios/:id", h.DeleteScenario)
	grp.DELETE("/overrides/:id", h.DeleteOverride)
	return r
}

func sampleScenario() models.Scenario {
	now := time.Now().UTC()
	return models.Scenario{
		ID:               uuid.New(),
		TenantID:         uuid.New(),
		Name:             "Prod TLS posture",
		FrameworkID:      uuid.New(),
		FrameworkVersion: "1.0",
		Filters:          models.ScenarioFilters{Environment: "production", Severity: "high"},
		CreatedBy:        uuid.New(),
		UpdatedBy:        uuid.New(),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func sampleOverride() models.Override {
	now := time.Now().UTC()
	from, to := "high", "medium"
	return models.Override{
		ID:            uuid.New(),
		TenantID:      uuid.New(),
		ControlID:     uuid.New(),
		OverrideType:  models.OverrideType("severity"),
		SeverityFrom:  &from,
		SeverityTo:    &to,
		Rationale:     "Compensating control in place",
		FrameworkType: "platform",
		CreatedBy:     uuid.New(),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// --- the contract tests ----------------------------------------------------

func TestContract_ListScenarios_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{list: []models.Scenario{sampleScenario()}}, &stubOverrideStore{})
	w := do(eng, http.MethodGet, cBase+"/scenarios", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ScenarioListResponse", w.Body.Bytes())
}

func TestContract_GetScenario_200(t *testing.T) {
	sv := loadSpec(t)
	sc := sampleScenario()
	eng := newWorkspaceEngine(&stubScenarioStore{byID: &sc}, &stubOverrideStore{})
	w := do(eng, http.MethodGet, cBase+"/scenarios/"+fUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ScenarioResponse", w.Body.Bytes())
}

func TestContract_GetScenario_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{}, &stubOverrideStore{})
	w := do(eng, http.MethodGet, cBase+"/scenarios/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetScenario_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{byIDErr: errors.New("not found")}, &stubOverrideStore{})
	w := do(eng, http.MethodGet, cBase+"/scenarios/"+fUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListOverrides_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{}, &stubOverrideStore{list: []models.Override{sampleOverride()}})
	w := do(eng, http.MethodGet, cBase+"/overrides", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "OverrideListResponse", w.Body.Bytes())
}

// --- scenario + override mutations ------------------------------------------

func TestContract_CreateScenario_201(t *testing.T) {
	sv := loadSpec(t)
	sc := sampleScenario()
	eng := newWorkspaceEngine(&stubScenarioStore{created: &sc}, &stubOverrideStore{})
	body := `{"name":"Prod TLS","framework_id":"` + fUUID + `","framework_version":"1.0","filters":{"environment":"production"}}`
	w := do(eng, http.MethodPost, cBase+"/scenarios", strings.NewReader(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ScenarioMutationResponse", w.Body.Bytes())
}

func TestContract_CreateScenario_409_nameTaken(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{nameTaken: true}, &stubOverrideStore{})
	body := `{"name":"dup","framework_id":"` + fUUID + `","framework_version":"1.0"}`
	w := do(eng, http.MethodPost, cBase+"/scenarios", strings.NewReader(body))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateScenario_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{}, &stubOverrideStore{})
	w := do(eng, http.MethodPost, cBase+"/scenarios", strings.NewReader(`{"name":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateScenario_200(t *testing.T) {
	sv := loadSpec(t)
	sc := sampleScenario()
	eng := newWorkspaceEngine(&stubScenarioStore{updated: &sc}, &stubOverrideStore{})
	w := do(eng, http.MethodPut, cBase+"/scenarios/"+fUUID, strings.NewReader(`{"name":"renamed","filters":{}}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ScenarioMutationResponse", w.Body.Bytes())
}

func TestContract_DeleteScenario_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{}, &stubOverrideStore{})
	w := do(eng, http.MethodDelete, cBase+"/scenarios/"+fUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_CreateOverride_201(t *testing.T) {
	sv := loadSpec(t)
	ov := sampleOverride()
	eng := newWorkspaceEngine(&stubScenarioStore{}, &stubOverrideStore{created: &ov})
	body := `{"control_id":"` + fUUID + `","override_type":"severity","rationale":"compensating control"}`
	w := do(eng, http.MethodPost, cBase+"/overrides", strings.NewReader(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "OverrideMutationResponse", w.Body.Bytes())
}

func TestContract_CreateOverride_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{}, &stubOverrideStore{})
	w := do(eng, http.MethodPost, cBase+"/overrides", strings.NewReader(`{"control_id":"`+fUUID+`"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteOverride_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newWorkspaceEngine(&stubScenarioStore{}, &stubOverrideStore{})
	w := do(eng, http.MethodDelete, cBase+"/overrides/"+fUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_Scenario_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/Scenario")
	if err != nil {
		t.Fatalf("compile Scenario: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + fUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted Scenario, but it passed — the guardrail is not actually checking")
	}
}

// Regression for: scenario/override by-id handlers must scope to the
// caller's tenant (from context), not just the path id — otherwise tenant A
// can read/delete tenant B's rows. newWorkspaceEngine sets a random context
// tenant; we assert the store received exactly that tenant.
func TestContract_GetScenario_scopesToContextTenant(t *testing.T) {
	samp := sampleScenario()
	sc := &stubScenarioStore{byID: &samp}
	eng := newWorkspaceEngineTenant(sc, &stubOverrideStore{}, ctxTenantForTest)
	w := do(eng, http.MethodGet, cBase+"/scenarios/"+uuid.New().String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if sc.gotTenant != ctxTenantForTest {
		t.Fatalf("GetScenario tenant = %s, want context tenant %s (#528)", sc.gotTenant, ctxTenantForTest)
	}
}

func TestContract_DeleteScenario_scopesToContextTenant(t *testing.T) {
	sc := &stubScenarioStore{}
	eng := newWorkspaceEngineTenant(sc, &stubOverrideStore{}, ctxTenantForTest)
	w := do(eng, http.MethodDelete, cBase+"/scenarios/"+uuid.New().String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if sc.gotTenant != ctxTenantForTest {
		t.Fatalf("DeleteScenario tenant = %s, want context tenant %s (#528)", sc.gotTenant, ctxTenantForTest)
	}
}

func TestContract_DeleteOverride_scopesToContextTenant(t *testing.T) {
	ov := &stubOverrideStore{}
	eng := newWorkspaceEngineTenant(&stubScenarioStore{}, ov, ctxTenantForTest)
	w := do(eng, http.MethodDelete, cBase+"/overrides/"+uuid.New().String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ov.gotTenant != ctxTenantForTest {
		t.Fatalf("DeleteOverride tenant = %s, want context tenant %s (#528)", ov.gotTenant, ctxTenantForTest)
	}
}
