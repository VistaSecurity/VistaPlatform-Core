package handlers

// Contract test for the alert-rules HTTP surface
// (`/api/v1/audit-service/alert-rules`) — the admin-ui audit alerting page's
// rule CRUD. First audit-service sub-slice beyond activity-logs.
//
// The handlers depend on *services.AlertRuleService via the AlertRuleHandler.service
// field. This slice landed a behaviour-preserving field→interface refactor first
// (the field is now the narrow alertRuleService interface the concrete service
// still satisfies — see alert_rule_handlers.go), so the real gin handlers run over
// httptest with an in-memory stub — no database — and their bodies are asserted
// against api/openapi/audit-service.openapi.yaml.
//
// Reuses loadSpec / specValidator.assertConforms / do / base / aUUID from
// activity_log_contract_test.go (same package).

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
)

var errAlertRule = context.DeadlineExceeded

// --- in-memory stub ---------------------------------------------------------

type stubAlertRuleService struct {
	rules     []models.AlertRule
	total     int
	rulesErr  error
	rule      *models.AlertRule
	ruleErr   error
	createErr error
	updateErr error
	deleteErr error

	// gotUpdate captures the rule passed to UpdateAlertRule so tests can
	// assert the handler's merge semantics.
	gotUpdate *models.AlertRule
}

func (s *stubAlertRuleService) CreateAlertRule(_ context.Context, rule *models.AlertRule) error {
	if s.createErr == nil {
		rule.ID = uuid.New()
	}
	return s.createErr
}
func (s *stubAlertRuleService) GetAlertRules(context.Context, models.AlertRuleFilters) ([]models.AlertRule, int, error) {
	return s.rules, s.total, s.rulesErr
}
func (s *stubAlertRuleService) GetAlertRuleByID(context.Context, uuid.UUID, *uuid.UUID) (*models.AlertRule, error) {
	return s.rule, s.ruleErr
}
func (s *stubAlertRuleService) UpdateAlertRule(_ context.Context, _ uuid.UUID, rule *models.AlertRule, _ *uuid.UUID) error {
	s.gotUpdate = rule
	return s.updateErr
}
func (s *stubAlertRuleService) DeleteAlertRule(context.Context, uuid.UUID, *uuid.UUID) error {
	return s.deleteErr
}

// --- harness ----------------------------------------------------------------

// newAlertRuleEngine wires the real alert-rule handlers under /api/v1/audit-service
// with a platform-user context (the way RequirePlatformAuth does), so the tenant
// access-scoping branches are bypassed.
func newAlertRuleEngine(svc alertRuleService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AlertRuleHandler{service: svc}
	grp := r.Group("/api/v1/audit-service")
	grp.Use(func(c *gin.Context) {
		c.Set("userType", "platform")
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.POST("/alert-rules", h.CreateAlertRule)
	grp.GET("/alert-rules", h.GetAlertRules)
	grp.GET("/alert-rules/:id", h.GetAlertRuleByID)
	grp.PUT("/alert-rules/:id", h.UpdateAlertRule)
	grp.DELETE("/alert-rules/:id", h.DeleteAlertRule)
	return r
}

func sampleAlertRule() models.AlertRule {
	now := time.Now().UTC()
	return models.AlertRule{
		ID:          uuid.New(),
		TenantID:    &testTenantID,
		Name:        "Failed logins spike",
		Description: "Too many failed logins in a short window",
		RuleType:    "threshold",
		IsEnabled:   true,
		Severity:    "high",
		Conditions: models.AlertConditions{
			EventTypes: []string{"auth.login.failed"},
			TimeWindow: "5m",
			Threshold:  10,
		},
		Actions: models.AlertActions{
			SendEmail:       true,
			EmailRecipients: []string{"secops@example.com"},
			NotifyAdmins:    true,
		},
		CreatedBy: uuid.New(),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// minimalAlertRule leaves tenant_id unset (platform rule) and the config blobs
// at their zero values.
func minimalAlertRule() models.AlertRule {
	now := time.Now().UTC()
	return models.AlertRule{
		ID:          uuid.New(),
		Name:        "Anomaly baseline",
		Description: "",
		RuleType:    "anomaly",
		IsEnabled:   false,
		Severity:    "low",
		CreatedBy:   uuid.New(),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// --- list -------------------------------------------------------------------

func TestContract_GetAlertRules_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{rules: []models.AlertRule{sampleAlertRule(), minimalAlertRule()}, total: 2})
	w := do(eng, http.MethodGet, base+"/alert-rules?page=1&page_size=20", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertRuleListResponse", w.Body.Bytes())
}

// Empty result → nil slice → `{"rules": null, ...}`.
func TestContract_GetAlertRules_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{rules: nil, total: 0})
	w := do(eng, http.MethodGet, base+"/alert-rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertRuleListResponse", w.Body.Bytes())
}

func TestContract_GetAlertRules_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{rulesErr: errAlertRule})
	w := do(eng, http.MethodGet, base+"/alert-rules", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- create -----------------------------------------------------------------

func TestContract_CreateAlertRule_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{})
	body := `{"name":"Failed logins","rule_type":"threshold","severity":"high","is_enabled":true}`
	w := do(eng, http.MethodPost, base+"/alert-rules", strings.NewReader(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CreateAlertRuleResponse", w.Body.Bytes())
}

// Malformed JSON → binding 400.
func TestContract_CreateAlertRule_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{})
	w := do(eng, http.MethodPost, base+"/alert-rules", strings.NewReader(`{not json`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateAlertRule_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{createErr: errAlertRule})
	w := do(eng, http.MethodPost, base+"/alert-rules", strings.NewReader(`{"name":"x","rule_type":"threshold"}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- get by id --------------------------------------------------------------

func TestContract_GetAlertRuleByID_200(t *testing.T) {
	sv := loadSpec(t)
	r := sampleAlertRule()
	eng := newAlertRuleEngine(&stubAlertRuleService{rule: &r})
	w := do(eng, http.MethodGet, base+"/alert-rules/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertRule", w.Body.Bytes())
}

func TestContract_GetAlertRuleByID_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{})
	w := do(eng, http.MethodGet, base+"/alert-rules/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetAlertRuleByID_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{ruleErr: errAlertRule})
	w := do(eng, http.MethodGet, base+"/alert-rules/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- update -----------------------------------------------------------------

func TestContract_UpdateAlertRule_200(t *testing.T) {
	sv := loadSpec(t)
	r := sampleAlertRule()
	eng := newAlertRuleEngine(&stubAlertRuleService{rule: &r})
	w := do(eng, http.MethodPut, base+"/alert-rules/"+aUUID, strings.NewReader(`{"is_enabled":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AuditMessageResponse", w.Body.Bytes())
}

//: a partial body must merge onto the existing rule, not overwrite every
// column from a zero-valued struct. Toggling is_enabled alone must preserve
// name/rule_type/severity/conditions, and must not let the body reassign
// server-owned fields (tenant_id, created_by).
func TestUpdateAlertRule_PartialBody_PreservesExistingFields(t *testing.T) {
	r := sampleAlertRule()
	otherTenant := uuid.New()
	stub := &stubAlertRuleService{rule: &r}
	eng := newAlertRuleEngine(stub)

	// Partial body: toggle is_enabled off and try to smuggle a tenant_id/created_by.
	body := `{"is_enabled":false,"tenant_id":"` + otherTenant.String() + `","created_by":"` + uuid.New().String() + `"}`
	w := do(eng, http.MethodPut, base+"/alert-rules/"+aUUID, strings.NewReader(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	got := stub.gotUpdate
	if got == nil {
		t.Fatal("UpdateAlertRule was not called")
	}
	if got.IsEnabled {
		t.Error("is_enabled should have been toggled to false")
	}
	if got.Name != r.Name {
		t.Errorf("name = %q, want preserved %q", got.Name, r.Name)
	}
	if got.RuleType != r.RuleType {
		t.Errorf("rule_type = %q, want preserved %q", got.RuleType, r.RuleType)
	}
	if got.Severity != r.Severity {
		t.Errorf("severity = %q, want preserved %q", got.Severity, r.Severity)
	}
	if got.Conditions.Threshold != r.Conditions.Threshold {
		t.Errorf("conditions.threshold = %d, want preserved %d", got.Conditions.Threshold, r.Conditions.Threshold)
	}
	// Server-owned fields must not be reassignable from the body.
	if got.TenantID == nil || *got.TenantID != *r.TenantID {
		t.Errorf("tenant_id = %v, want preserved %v (body must not reassign it)", got.TenantID, r.TenantID)
	}
	if got.CreatedBy != r.CreatedBy {
		t.Errorf("created_by = %v, want preserved %v (body must not reassign it)", got.CreatedBy, r.CreatedBy)
	}
}

func TestContract_UpdateAlertRule_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{})
	w := do(eng, http.MethodPut, base+"/alert-rules/not-a-uuid", strings.NewReader(`{"is_enabled":false}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Existing-rule lookup fails → 404 (before the body is applied).
func TestContract_UpdateAlertRule_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{ruleErr: errAlertRule})
	w := do(eng, http.MethodPut, base+"/alert-rules/"+aUUID, strings.NewReader(`{"is_enabled":false}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateAlertRule_500(t *testing.T) {
	sv := loadSpec(t)
	r := sampleAlertRule()
	eng := newAlertRuleEngine(&stubAlertRuleService{rule: &r, updateErr: errAlertRule})
	w := do(eng, http.MethodPut, base+"/alert-rules/"+aUUID, strings.NewReader(`{"is_enabled":false}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- delete -----------------------------------------------------------------

func TestContract_DeleteAlertRule_200(t *testing.T) {
	sv := loadSpec(t)
	r := sampleAlertRule()
	eng := newAlertRuleEngine(&stubAlertRuleService{rule: &r})
	w := do(eng, http.MethodDelete, base+"/alert-rules/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AuditMessageResponse", w.Body.Bytes())
}

func TestContract_DeleteAlertRule_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{})
	w := do(eng, http.MethodDelete, base+"/alert-rules/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteAlertRule_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertRuleEngine(&stubAlertRuleService{ruleErr: errAlertRule})
	w := do(eng, http.MethodDelete, base+"/alert-rules/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteAlertRule_500(t *testing.T) {
	sv := loadSpec(t)
	r := sampleAlertRule()
	eng := newAlertRuleEngine(&stubAlertRuleService{rule: &r, deleteErr: errAlertRule})
	w := do(eng, http.MethodDelete, base+"/alert-rules/"+aUUID, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift guard ------------------------------------------------------------

func TestContract_AlertRule_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/AlertRule")
	if err != nil {
		t.Fatalf("compile AlertRule: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted AlertRule, but it passed — the guardrail is not actually checking")
	}
}
