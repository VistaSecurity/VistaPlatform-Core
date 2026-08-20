package handlers

// Contract test for the security read surface (admin-ui Security ▸ Dashboard):
// /admin/security/events and /admin/security/dashboard-stats.
//
// These handlers used a package-global *security.Service; this slice introduces
// a securityProvider interface (the global→injected-interface refactor —
// *security.Service satisfies it) so the real gin handlers run over httptest
// with an in-memory stub — no DB — and their `{ data, meta }` envelope bodies
// are asserted against api/openapi/admin-service.openapi.yaml.
//
// The /admin/security/compliance routes are GONE (they read
// public.compliance_framework_status, which no code, seed or job ever writes).
// TestContract_ComplianceFrameworkSchemas_AreGone below is the ratchet that
// stops the schemas — and therefore the routes — from creeping back in.
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
	events    []security.SecurityEvent
	total     int
	eventsErr error
	stats     map[string]interface{}
	statsErr  error
}

func (s *stubSecurityProvider) GetSecurityEvents(map[string]interface{}, int, int) ([]security.SecurityEvent, int, error) {
	return s.events, s.total, s.eventsErr
}
func (s *stubSecurityProvider) GetSecurityDashboardStats(string) (map[string]interface{}, error) {
	return s.stats, s.statsErr
}

// --- engine -----------------------------------------------------------------

func securityEngine(svc securityProvider) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase)
	grp.GET("/admin/security/events", GetSecurityEvents(svc))
	grp.GET("/admin/security/dashboard-stats", GetSecurityDashboardStats(svc))
	return r
}

const securityBase = apiBase + "/admin/security"

// --- sample data ------------------------------------------------------------

func sampleSecurityEvent() security.SecurityEvent {
	now := time.Now().UTC()
	desc := "invalid credentials"
	email := "operator@example.com"
	ip := "203.0.113.9"
	ua := "Mozilla/5.0"
	req := "req-1"
	resType := "user"
	resID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	return security.SecurityEvent{
		ID:                uuid.New(),
		EventType:         "auth.login",
		Category:          "authentication",
		Action:            "login",
		ResourceType:      &resType,
		ResourceID:        &resID,
		Description:       &desc,
		Success:           false,
		RequiresAttention: true,
		UserID:            &userID,
		UserEmail:         &email,
		UserType:          "platform",
		TenantID:          &tenantID,
		SourceIP:          &ip,
		UserAgent:         &ua,
		RequestID:         &req,
		Metadata:          map[string]interface{}{"attempts": 5},
		Tags:              []string{"bruteforce"},
		ComplianceTags:    []string{"soc2"},
		Timestamp:         now,
		CreatedAt:         now,
	}
}

// minimalSecurityEvent leaves all omitempty fields unset (absent).
func minimalSecurityEvent() security.SecurityEvent {
	now := time.Now().UTC()
	return security.SecurityEvent{
		ID:        uuid.New(),
		EventType: "config.update",
		Category:  "config",
		Action:    "update_settings",
		Success:   true,
		UserType:  "platform",
		Timestamp: now,
		CreatedAt: now,
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

// The stat keys the dashboard tiles and breakdown panels actually read. If the
// service stops emitting one, the tile silently renders 0 — which is exactly the
// failure mode this whole change exists to remove — so pin the key set here.
func TestContract_GetSecurityDashboardStats_200(t *testing.T) {
	sv := loadSpec(t)
	eng := securityEngine(&stubSecurityProvider{stats: map[string]interface{}{
		"total_events":       42,
		"failed_events":      3,
		"requires_attention": 1,
		"failed_logins":      2,
		"events_by_category": map[string]int{"authentication": 40, "config": 2},
		"events_by_outcome":  map[string]int{"succeeded": 39, "failed": 3},
	}})
	w := doRequest(eng, http.MethodGet, securityBase+"/dashboard-stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SecurityDashboardResponse", w.Body.Bytes())
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

// SecurityEvent must not regain the public.security_events fields. Those columns
// live in a table with zero writers; re-declaring them here is how a permanently
// empty panel gets rebuilt. If a real producer ever appears, delete this test
// deliberately rather than letting it rot.
func TestContract_SecurityEvent_HasNoProducerlessFields(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/SecurityEvent")
	if err != nil {
		t.Fatalf("compile SecurityEvent: %v", err)
	}
	for _, field := range []string{"severity", "threat_score", "is_anomaly", "risk_level", "status", "service_name"} {
		body, err := jsonschema.UnmarshalJSON(strings.NewReader(`{
			"id":"11111111-1111-1111-1111-111111111111","event_type":"a","category":"b","action":"c",
			"success":true,"requires_attention":false,"user_type":"platform",
			"timestamp":"2020-01-01T00:00:00Z","created_at":"2020-01-01T00:00:00Z",
			"` + field + `":"anything"}`))
		if err != nil {
			t.Fatalf("unmarshal probe body for %q: %v", field, err)
		}
		if err := sch.Validate(body); err == nil {
			t.Fatalf("SecurityEvent accepted %q — that field came from the producerless public.security_events table and must not return", field)
		}
	}
}

// The compliance-framework surface is deleted, not deprecated: no schema, no
// route, no handler. Compiling the schema must FAIL.
func TestContract_ComplianceFrameworkSchemas_AreGone(t *testing.T) {
	sv := loadSpec(t)
	for _, name := range []string{"ComplianceFrameworkStatus", "ComplianceFrameworkResponse", "ComplianceFrameworkListResponse"} {
		if _, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/" + name); err == nil {
			t.Fatalf("schema %s still resolves in admin-service.openapi.yaml — the producerless compliance-framework surface is back", name)
		}
	}
}
