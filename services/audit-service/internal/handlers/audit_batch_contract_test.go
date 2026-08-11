package handlers

// Contract tests for the remaining audit-service admin-ui surfaces (ADR-0001):
// retention-policies, alerts, analytics, compliance-reports. Batched into one
// slice because they share the audit-service spec, the handlers package, and
// the activity-logs harness — they don't conflict with each other.
//
// The SIEM-integration cases that used to live here moved with the feature to
// ee/siemexport/handlers_contract_test.go when SIEM export was carved out of
// the Core build; the schemas they assert stay in the shared spec.
//
// Each handler had a behaviour-preserving field→interface refactor first (see the
// per-handler *Service interfaces), so the real gin handlers run over httptest
// with in-memory stubs — no database, no network — and their bodies are asserted
// against api/openapi/audit-service.openapi.yaml.
//
// Reuses loadSpec / specValidator.assertConforms / do / base / aUUID from
// activity_log_contract_test.go (same package). UI consumer: admin-ui audit-api.ts.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

var errAudit = context.DeadlineExceeded

// =============================== retention ===================================

type stubRetentionService struct {
	policies    []services.RetentionPolicy
	policiesErr error
	policy      *services.RetentionPolicy
	policyErr   error
	createErr   error
	updateErr   error
}

func (s *stubRetentionService) GetRetentionPolicies(context.Context) ([]services.RetentionPolicy, error) {
	return s.policies, s.policiesErr
}
func (s *stubRetentionService) GetRetentionPolicyByID(context.Context, uuid.UUID) (*services.RetentionPolicy, error) {
	return s.policy, s.policyErr
}
func (s *stubRetentionService) CreateRetentionPolicy(context.Context, *services.RetentionPolicy) error {
	return s.createErr
}
func (s *stubRetentionService) UpdateRetentionPolicy(context.Context, *services.RetentionPolicy) error {
	return s.updateErr
}

func newRetentionEngine(svc retentionService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &RetentionHandler{service: svc}
	g := r.Group(base)
	g.GET("/retention-policies", h.GetRetentionPolicies)
	g.POST("/retention-policies", h.CreateRetentionPolicy)
	g.GET("/retention-policies/:id", h.GetRetentionPolicyByID)
	g.PUT("/retention-policies/:id", h.UpdateRetentionPolicy)
	return r
}

func sampleRetentionPolicy() services.RetentionPolicy {
	now := time.Now().UTC()
	cold := 90
	return services.RetentionPolicy{
		ID:                  uuid.New(),
		TenantID:            &testTenantID,
		PolicyName:          "SOC2 default",
		ComplianceFramework: strPtr("soc2"),
		HotStorageDays:      30,
		ColdStorageDays:     &cold,
		TotalRetentionDays:  365,
		IsActive:            true,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

const retentionBody = `{"policy_name":"X","hot_storage_days":30,"total_retention_days":365,"is_active":true}`

func TestContract_GetRetentionPolicies_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{policies: []services.RetentionPolicy{sampleRetentionPolicy()}})
	w := do(eng, http.MethodGet, base+"/retention-policies", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetentionPolicyListResponse", w.Body.Bytes())
}

func TestContract_GetRetentionPolicies_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{policies: nil})
	w := do(eng, http.MethodGet, base+"/retention-policies", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetentionPolicyListResponse", w.Body.Bytes())
}

func TestContract_GetRetentionPolicies_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{policiesErr: errAudit})
	w := do(eng, http.MethodGet, base+"/retention-policies", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetRetentionPolicyByID_200(t *testing.T) {
	sv := loadSpec(t)
	p := sampleRetentionPolicy()
	eng := newRetentionEngine(&stubRetentionService{policy: &p})
	w := do(eng, http.MethodGet, base+"/retention-policies/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetentionPolicyResponse", w.Body.Bytes())
}

func TestContract_GetRetentionPolicyByID_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{})
	w := do(eng, http.MethodGet, base+"/retention-policies/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetRetentionPolicyByID_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{policyErr: errAudit})
	w := do(eng, http.MethodGet, base+"/retention-policies/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateRetentionPolicy_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{})
	w := do(eng, http.MethodPost, base+"/retention-policies", strings.NewReader(retentionBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetentionPolicyResponse", w.Body.Bytes())
}

func TestContract_CreateRetentionPolicy_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{})
	w := do(eng, http.MethodPost, base+"/retention-policies", strings.NewReader(`{bad`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateRetentionPolicy_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{createErr: errAudit})
	w := do(eng, http.MethodPost, base+"/retention-policies", strings.NewReader(retentionBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateRetentionPolicy_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{})
	w := do(eng, http.MethodPut, base+"/retention-policies/"+aUUID, strings.NewReader(retentionBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetentionPolicyResponse", w.Body.Bytes())
}

func TestContract_UpdateRetentionPolicy_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{})
	w := do(eng, http.MethodPut, base+"/retention-policies/not-a-uuid", strings.NewReader(retentionBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateRetentionPolicy_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newRetentionEngine(&stubRetentionService{updateErr: errAudit})
	w := do(eng, http.MethodPut, base+"/retention-policies/"+aUUID, strings.NewReader(retentionBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// ================================ alerts =====================================

type stubAlertService struct {
	alerts    []services.Alert
	alertsErr error
	ackErr    error
}

func (s *stubAlertService) GetRules(context.Context) []services.AlertRule { return nil }
func (s *stubAlertService) GetAlerts(context.Context, string, int) ([]services.Alert, error) {
	return s.alerts, s.alertsErr
}
func (s *stubAlertService) AcknowledgeAlert(context.Context, uuid.UUID, uuid.UUID) error {
	return s.ackErr
}

func newAlertEngine(svc alertService, withUser bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AlertHandler{service: svc}
	g := r.Group(base)
	if withUser {
		g.Use(func(c *gin.Context) { c.Set("userID", uuid.New()); c.Next() })
	}
	g.GET("/alerts", h.GetAlerts)
	g.POST("/alerts/:id/acknowledge", h.AcknowledgeAlert)
	return r
}

func sampleAlert() services.Alert {
	now := time.Now().UTC()
	return services.Alert{
		ID:           uuid.New(),
		RuleID:       uuid.New(),
		RuleName:     "Failed logins",
		Severity:     "high",
		Message:      "10 failed logins in 5m",
		EventCount:   10,
		SampleEvents: []map[string]interface{}{{"ip": "10.0.0.1"}},
		TriggeredAt:  now,
		Status:       "open",
	}
}

func TestContract_GetAlerts_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertService{alerts: []services.Alert{sampleAlert()}}, true)
	w := do(eng, http.MethodGet, base+"/alerts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertListResponse", w.Body.Bytes())
}

func TestContract_GetAlerts_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertService{alerts: nil}, true)
	w := do(eng, http.MethodGet, base+"/alerts?status=resolved", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AlertListResponse", w.Body.Bytes())
}

func TestContract_GetAlerts_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertService{alertsErr: errAudit}, true)
	w := do(eng, http.MethodGet, base+"/alerts", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_AcknowledgeAlert_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertService{}, true)
	w := do(eng, http.MethodPost, base+"/alerts/"+aUUID+"/acknowledge", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AuditMessageResponse", w.Body.Bytes())
}

func TestContract_AcknowledgeAlert_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertService{}, true)
	w := do(eng, http.MethodPost, base+"/alerts/not-a-uuid/acknowledge", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// No userID in context → 401.
func TestContract_AcknowledgeAlert_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertService{}, false)
	w := do(eng, http.MethodPost, base+"/alerts/"+aUUID+"/acknowledge", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_AcknowledgeAlert_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAlertEngine(&stubAlertService{ackErr: errAudit}, true)
	w := do(eng, http.MethodPost, base+"/alerts/"+aUUID+"/acknowledge", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// =============================== analytics ===================================

type stubAnalyticsService struct {
	summary     *services.UserActivitySummary
	summaryErr  error
	analysis    *services.AccessPatternAnalysis
	analysisErr error
	gaps        *services.ComplianceGapAnalysis
	gapsErr     error
}

func (s *stubAnalyticsService) GetUserActivitySummary(context.Context, uuid.UUID, *uuid.UUID, int) (*services.UserActivitySummary, error) {
	return s.summary, s.summaryErr
}
func (s *stubAnalyticsService) GetAccessPatternAnalysis(context.Context, *uuid.UUID, int) (*services.AccessPatternAnalysis, error) {
	return s.analysis, s.analysisErr
}
func (s *stubAnalyticsService) GetComplianceGapAnalysis(context.Context, string, *uuid.UUID, int) (*services.ComplianceGapAnalysis, error) {
	return s.gaps, s.gapsErr
}

// newAnalyticsEngine sets a platform-user context so the tenant-scoping 403
// branches are bypassed (pass userType="tenant" without a tenantID to hit 403).
func newAnalyticsEngine(svc analyticsService, userType string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AnalyticsHandler{service: svc}
	g := r.Group(base)
	g.Use(func(c *gin.Context) { c.Set("userType", userType); c.Next() })
	g.GET("/analytics/user-activity", h.GetUserActivity)
	g.GET("/analytics/access-patterns", h.GetAccessPatterns)
	g.GET("/analytics/compliance-gaps", h.GetComplianceGaps)
	g.GET("/analytics/dashboard", h.GetDashboardMetrics)
	return r
}

func TestContract_UserActivityAnalytics_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{summary: &services.UserActivitySummary{}}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/user-activity?user_id="+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AnalyticsSummaryResponse", w.Body.Bytes())
}

func TestContract_UserActivityAnalytics_400_noUserID(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/user-activity", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Tenant user without a tenant in context → 403.
func TestContract_UserActivityAnalytics_403(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{}, "tenant")
	w := do(eng, http.MethodGet, base+"/analytics/user-activity?user_id="+aUUID, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UserActivityAnalytics_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{summaryErr: errAudit}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/user-activity?user_id="+aUUID, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_AccessPatternsAnalytics_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{analysis: &services.AccessPatternAnalysis{}}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/access-patterns", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AnalyticsAnalysisResponse", w.Body.Bytes())
}

func TestContract_AccessPatternsAnalytics_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{analysisErr: errAudit}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/access-patterns", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ComplianceGapsAnalytics_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{gaps: &services.ComplianceGapAnalysis{}}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/compliance-gaps?framework=soc2", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AnalyticsAnalysisResponse", w.Body.Bytes())
}

func TestContract_ComplianceGapsAnalytics_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{gapsErr: errAudit}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/compliance-gaps", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DashboardAnalytics_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{analysis: &services.AccessPatternAnalysis{}}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/dashboard", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AnalyticsDashboardResponse", w.Body.Bytes())
}

func TestContract_DashboardAnalytics_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newAnalyticsEngine(&stubAnalyticsService{analysisErr: errAudit}, "platform")
	w := do(eng, http.MethodGet, base+"/analytics/dashboard", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// =========================== compliance-reports ==============================

type stubComplianceService struct {
	summary     *services.ComplianceSummary
	summaryErr  error
	validateErr error
}

func (s *stubComplianceService) GetComplianceSummary(context.Context, *uuid.UUID, time.Time, time.Time) (*services.ComplianceSummary, error) {
	return s.summary, s.summaryErr
}
func (s *stubComplianceService) ValidateRetentionPolicies(context.Context) error {
	return s.validateErr
}

type stubComplianceReportService struct {
	report    *services.ComplianceReport
	reportErr error
}

func (s *stubComplianceReportService) gen() (*services.ComplianceReport, error) {
	return s.report, s.reportErr
}
func (s *stubComplianceReportService) GenerateSOC2Report(context.Context, *uuid.UUID, time.Time, time.Time) (*services.ComplianceReport, error) {
	return s.gen()
}
func (s *stubComplianceReportService) GenerateISO27001Report(context.Context, *uuid.UUID, time.Time, time.Time) (*services.ComplianceReport, error) {
	return s.gen()
}
func (s *stubComplianceReportService) GenerateGDPRReport(context.Context, *uuid.UUID, time.Time, time.Time) (*services.ComplianceReport, error) {
	return s.gen()
}
func (s *stubComplianceReportService) GenerateHIPAAReport(context.Context, *uuid.UUID, time.Time, time.Time) (*services.ComplianceReport, error) {
	return s.gen()
}
func (s *stubComplianceReportService) GeneratePCIDSSReport(context.Context, *uuid.UUID, time.Time, time.Time) (*services.ComplianceReport, error) {
	return s.gen()
}

func newComplianceEngine(svc complianceService, reportSvc complianceReportService, userType string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &ComplianceHandler{service: svc, reportService: reportSvc}
	g := r.Group(base)
	g.Use(func(c *gin.Context) { c.Set("userType", userType); c.Next() })
	g.GET("/compliance-reports/summary", h.GetComplianceSummary)
	g.GET("/compliance-reports/validate-retention", h.ValidateRetentionPolicies)
	g.GET("/compliance-reports/templates", h.GetComplianceReportTemplates)
	g.POST("/compliance-reports/generate", h.GenerateComplianceReport)
	return r
}

func TestContract_ComplianceSummary_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{summary: &services.ComplianceSummary{}}, nil, "platform")
	w := do(eng, http.MethodGet, base+"/compliance-reports/summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ComplianceSummaryResponse", w.Body.Bytes())
}

func TestContract_ComplianceSummary_403(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{}, nil, "tenant")
	w := do(eng, http.MethodGet, base+"/compliance-reports/summary", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ComplianceSummary_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{summaryErr: errAudit}, nil, "platform")
	w := do(eng, http.MethodGet, base+"/compliance-reports/summary", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ValidateRetention_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{}, nil, "platform")
	w := do(eng, http.MethodGet, base+"/compliance-reports/validate-retention", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AuditMessageResponse", w.Body.Bytes())
}

func TestContract_ValidateRetention_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{validateErr: errAudit}, nil, "platform")
	w := do(eng, http.MethodGet, base+"/compliance-reports/validate-retention", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ComplianceTemplates_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{}, nil, "platform")
	w := do(eng, http.MethodGet, base+"/compliance-reports/templates", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ComplianceTemplatesResponse", w.Body.Bytes())
}

func TestContract_GenerateComplianceReport_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{}, &stubComplianceReportService{report: &services.ComplianceReport{}}, "platform")
	body := `{"framework":"soc2","start_date":"2026-01-01T00:00:00Z","end_date":"2026-02-01T00:00:00Z"}`
	w := do(eng, http.MethodPost, base+"/compliance-reports/generate", strings.NewReader(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ComplianceReportResponse", w.Body.Bytes())
}

// Missing required fields → binding 400.
func TestContract_GenerateComplianceReport_400_binding(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{}, &stubComplianceReportService{}, "platform")
	w := do(eng, http.MethodPost, base+"/compliance-reports/generate", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Unsupported framework → 400.
func TestContract_GenerateComplianceReport_400_framework(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{}, &stubComplianceReportService{report: &services.ComplianceReport{}}, "platform")
	body := `{"framework":"bogus","start_date":"2026-01-01T00:00:00Z","end_date":"2026-02-01T00:00:00Z"}`
	w := do(eng, http.MethodPost, base+"/compliance-reports/generate", strings.NewReader(body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// No report service wired → 500.
func TestContract_GenerateComplianceReport_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newComplianceEngine(&stubComplianceService{}, nil, "platform")
	body := `{"framework":"soc2","start_date":"2026-01-01T00:00:00Z","end_date":"2026-02-01T00:00:00Z"}`
	w := do(eng, http.MethodPost, base+"/compliance-reports/generate", strings.NewReader(body))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// =============================== drift guards ================================

func TestContract_RetentionPolicy_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/RetentionPolicy")
	if err != nil {
		t.Fatalf("compile RetentionPolicy: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted RetentionPolicy, but it passed")
	}
}
