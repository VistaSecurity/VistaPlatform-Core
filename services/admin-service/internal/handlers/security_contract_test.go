package handlers

// Contract test for the security/compliance read surface (admin-ui Security
// page): /admin/security/events, /dashboard-stats, /compliance,
// /compliance/:framework.
//
// These handlers used a package-global *security.Service; this slice introduces
// a securityProvider interface (the global→injected-interface refactor —
// *security.Service satisfies it) so the real gin handlers run over httptest
// with an in-memory stub — no DB — and their `{ data, meta }` envelope bodies
// are asserted against api/openapi/admin-service.openapi.yaml.
//
// The spec-loading / assertConforms / doRequest harness and apiBase const
// are shared with tenant_billing_contract_test.go (same package, same spec) and
// reused here rather than redefined.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/security"
)

// --- in-memory stub securityProvider ----------------------------------------

type stubSecurityProvider struct {
	events        []security.SecurityEvent
	total         int
	eventsErr     error
	stats         map[string]interface{}
	statsErr      error
	framework     *security.ComplianceFrameworkStatus
	frameworkErr  error
	frameworks    []security.ComplianceFrameworkStatus
	frameworksErr error
}

func (s *stubSecurityProvider) GetSecurityEvents(map[string]interface{}, int, int) ([]security.SecurityEvent, int, error) {
	return s.events, s.total, s.eventsErr
}
func (s *stubSecurityProvider) GetSecurityDashboardStats(string) (map[string]interface{}, error) {
	return s.stats, s.statsErr
}
func (s *stubSecurityProvider) GetComplianceFrameworkStatus(string) (*security.ComplianceFrameworkStatus, error) {
	return s.framework, s.frameworkErr
}
func (s *stubSecurityProvider) GetAllComplianceFrameworks() ([]security.ComplianceFrameworkStatus, error) {
	return s.frameworks, s.frameworksErr
}

// --- engine -----------------------------------------------------------------

func securityEngine(svc securityProvider) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase)
	grp.GET("/admin/security/events", GetSecurityEvents(svc))
	grp.GET("/admin/security/dashboard-stats", GetSecurityDashboardStats(svc))
	grp.GET("/admin/security/compliance", GetAllComplianceFrameworks(svc))
	grp.GET("/admin/security/compliance/:framework", GetComplianceFrameworkStatus(svc))
	return r
}

const securityBase = apiBase + "/admin/security"

// --- sample data ------------------------------------------------------------

func sampleSecurityEvent() security.SecurityEvent {
	now := time.Now().UTC()
	corr := "corr-1"
	desc := "Suspicious login"
	return security.SecurityEvent{
		ID:                uuid.New(),
		EventID:           "evt-1",
		CorrelationID:     &corr,
		EventType:         "auth.failed",
		Severity:          "high",
		Category:          "authentication",
		Title:             "Repeated failed logins",
		Description:       &desc,
		ServiceName:       "auth-service",
		ThreatScore:       8.5,
		IsAnomaly:         true,
		RiskLevel:         "high",
		Status:            "open",
		Metadata:          map[string]interface{}{"attempts": 5},
		Tags:              []string{"bruteforce"},
		RequiresAttention: true,
		Timestamp:         now,
		DetectedAt:        now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// minimalSecurityEvent leaves all omitempty fields unset (absent).
func minimalSecurityEvent() security.SecurityEvent {
	now := time.Now().UTC()
	return security.SecurityEvent{
		ID:          uuid.New(),
		EventID:     "evt-2",
		EventType:   "system.info",
		Severity:    "info",
		Category:    "system",
		Title:       "Heartbeat",
		ServiceName: "admin-service",
		ThreatScore: 0,
		RiskLevel:   "low",
		Status:      "closed",
		Timestamp:   now,
		DetectedAt:  now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func sampleFramework() security.ComplianceFrameworkStatus {
	now := time.Now().UTC()
	ver := "1.0"
	return security.ComplianceFrameworkStatus{
		ID:                       uuid.New(),
		FrameworkName:            "SOC2",
		FrameworkVersion:         &ver,
		OverallStatus:            "compliant",
		ComplianceScore:          92.5,
		LastAssessedAt:           &now,
		TotalRequirements:        100,
		CompliantRequirements:    92,
		NonCompliantRequirements: 5,
		PendingRequirements:      3,
		Findings:                 []string{"MFA gap"},
		CreatedAt:                now,
		UpdatedAt:                now,
	}
}

// --- events -----------------------------------------------------------------

func TestContract_GetSecurityEvents_200(t *testing.T) {
	sv := loadSpec(t)
	eng := securityEngine(&stubSecurityProvider{
		events: []security.SecurityEvent{sampleSecurityEvent(), minimalSecurityEvent()},
		total:  2,
	})
	w := doRequest(eng, http.MethodGet, securityBase+"/events", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SecurityEventListResponse", w.Body.Bytes())
}

// No events → nil slice → `{"data": null, "meta": {...}}`.
func TestContract_GetSecurityEvents_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := securityEngine(&stubSecurityProvider{events: nil, total: 0})
	w := doRequest(eng, http.MethodGet, securityBase+"/events", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SecurityEventListResponse", w.Body.Bytes())
}

// Nil provider → 503.
func TestContract_GetSecurityEvents_503(t *testing.T) {
	sv := loadSpec(t)
	eng := securityEngine(nil)
	w := doRequest(eng, http.MethodGet, securityBase+"/events", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- dashboard stats --------------------------------------------------------

func TestContract_GetSecurityDashboardStats_200(t *testing.T) {
	sv := loadSpec(t)
	eng := securityEngine(&stubSecurityProvider{stats: map[string]interface{}{
		"total_events": 42, "by_severity": map[string]interface{}{"high": 3},
	}})
	w := doRequest(eng, http.MethodGet, securityBase+"/dashboard-stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SecurityDashboardResponse", w.Body.Bytes())
}

// --- compliance -------------------------------------------------------------

func TestContract_GetAllComplianceFrameworks_200(t *testing.T) {
	sv := loadSpec(t)
	eng := securityEngine(&stubSecurityProvider{frameworks: []security.ComplianceFrameworkStatus{sampleFramework()}})
	w := doRequest(eng, http.MethodGet, securityBase+"/compliance", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ComplianceFrameworkListResponse", w.Body.Bytes())
}

func TestContract_GetAllComplianceFrameworks_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := securityEngine(&stubSecurityProvider{frameworks: nil})
	w := doRequest(eng, http.MethodGet, securityBase+"/compliance", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ComplianceFrameworkListResponse", w.Body.Bytes())
}

func TestContract_GetComplianceFrameworkStatus_200(t *testing.T) {
	sv := loadSpec(t)
	f := sampleFramework()
	eng := securityEngine(&stubSecurityProvider{framework: &f})
	w := doRequest(eng, http.MethodGet, securityBase+"/compliance/SOC2", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ComplianceFrameworkResponse", w.Body.Bytes())
}

// Nil status (not found) → 404.
func TestContract_GetComplianceFrameworkStatus_404(t *testing.T) {
	sv := loadSpec(t)
	eng := securityEngine(&stubSecurityProvider{framework: nil})
	w := doRequest(eng, http.MethodGet, securityBase+"/compliance/NOPE", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift guards -----------------------------------------------------------

func TestContract_SecurityEvent_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/SecurityEvent")
	if err != nil {
		t.Fatalf("compile SecurityEvent: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"x","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted SecurityEvent, but it passed — the guardrail is not actually checking")
	}
}

func TestContract_ComplianceFrameworkStatus_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/ComplianceFrameworkStatus")
	if err != nil {
		t.Fatalf("compile ComplianceFrameworkStatus: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"x","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted ComplianceFrameworkStatus, but it passed — the guardrail is not actually checking")
	}
}
