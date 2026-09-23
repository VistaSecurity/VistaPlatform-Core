package handlers

// Contract tests for the CORE half of the admin-service "tail" admin-ui
// surfaces (ADR-0001): platform settings and system logs.
//
// The per-tenant stats, dashboard, and monitoring/metrics cases that used to sit
// in this file moved to ee/msp/admin_tail_contract_test.go with the handlers
// they cover — they are cross-tenant aggregates, i.e. MSP. Their guarded
// `api-contract` Makefile line runs them from there.
//
// Refactors landed first so the real handlers run with no DB and no network:
//   - platform settings → platformSettingsStore (repo extraction)
//
// Reuses loadSpec / doRequest / apiBase from contract_harness_test.go.
// UI consumers: platform-api.ts, status-api.ts.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var errAdminTail = context.DeadlineExceeded

// =============================== settings ====================================

type stubPlatformSettingsStore struct {
	list      []platformSettingKV
	listErr   error
	upsertErr error
	// securityManage is what HasPlatformPermission answers for
	// platform.security.manage; permErr fails the lookup.
	securityManage bool
	permErr        error
	permAsked      []string
	upserted       []string
}

func (s *stubPlatformSettingsStore) ListSettings(context.Context) ([]platformSettingKV, error) {
	return s.list, s.listErr
}
func (s *stubPlatformSettingsStore) UpsertSetting(_ context.Context, key string, _ []byte, _ uuid.UUID) error {
	s.upserted = append(s.upserted, key)
	return s.upsertErr
}
func (s *stubPlatformSettingsStore) HasPlatformPermission(_ context.Context, _ uuid.UUID, perm string) (bool, error) {
	s.permAsked = append(s.permAsked, perm)
	if s.permErr != nil {
		return false, s.permErr
	}
	return perm == "platform.security.manage" && s.securityManage, nil
}

func newSettingsEngine(store platformSettingsStore, withUser bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group(apiBase)
	if withUser {
		g.Use(func(c *gin.Context) { c.Set("userID", uuid.NewString()); c.Next() })
	}
	g.GET("/admin/settings", getPlatformSettingsWithStore(store))
	g.PUT("/admin/settings", updatePlatformSettingsWithStore(store))
	return r
}

func TestContract_GetPlatformSettings_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newSettingsEngine(&stubPlatformSettingsStore{list: nil}, true)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/settings", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformSettings", w.Body.Bytes())
}

func TestContract_UpdatePlatformSettings_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newSettingsEngine(&stubPlatformSettingsStore{}, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(`{"platform_name":"Acme"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdatePlatformSettingsResponse", w.Body.Bytes())
}

// No userID in context → 401.
func TestContract_UpdatePlatformSettings_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newSettingsEngine(&stubPlatformSettingsStore{}, false)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(`{"platform_name":"Acme"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Malformed JSON body → 400.
func TestContract_UpdatePlatformSettings_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newSettingsEngine(&stubPlatformSettingsStore{}, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(`{bad`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// The four authentication-policy fields are now ENFORCED (auth-service lockout,
// password floor, session lifetime), so a value the enforcement layer would
// clamp must be rejected here instead. Saving a number that is not the number in
// force is the exact failure this whole change removes.
func TestContract_UpdatePlatformSettings_RejectsOutOfRangePolicy(t *testing.T) {
	sv := loadSpec(t)
	for name, body := range map[string]string{
		// Below the built-in password floor of 8 — the old handler allowed 4,
		// which the validator then silently raised back to 8.
		"password_min_length too low":  `{"password_min_length":4}`,
		"password_min_length too high": `{"password_min_length":200}`,
		// 0 attempts would lock an account over a request that has not happened.
		"max_login_attempts zero":     `{"max_login_attempts":0}`,
		"max_login_attempts too high": `{"max_login_attempts":5000}`,
		"lockout_duration zero":       `{"lockout_duration_minutes":0}`,
		"lockout_duration too high":   `{"lockout_duration_minutes":999999}`,
		"session_timeout too short":   `{"session_timeout_minutes":1}`,
		"session_timeout too long":    `{"session_timeout_minutes":999999}`,
	} {
		t.Run(name, func(t *testing.T) {
			eng := newSettingsEngine(&stubPlatformSettingsStore{securityManage: true}, true)
			w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %s; body=%s", w.Code, body, w.Body.String())
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		})
	}
}

// In-range values are accepted, so the guard above is a range check and not a
// blanket rejection.
func TestContract_UpdatePlatformSettings_AcceptsInRangePolicy(t *testing.T) {
	eng := newSettingsEngine(&stubPlatformSettingsStore{securityManage: true}, true)
	body := `{"password_min_length":14,"max_login_attempts":3,"lockout_duration_minutes":60,"session_timeout_minutes":90}`
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// maintenance_mode is gone, not deprecated. It was a response field pinned to a
// constant false that no PUT branch wrote and no service read; persisting it
// alone would only have made the false belief durable. This is the ratchet
// against it reappearing on either side of the contract.
func TestContract_PlatformSettings_HasNoMaintenanceMode(t *testing.T) {
	sv := loadSpec(t)

	// The handler must not emit it.
	eng := newSettingsEngine(&stubPlatformSettingsStore{list: nil}, true)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/settings", nil)
	if strings.Contains(w.Body.String(), "maintenance_mode") {
		t.Fatalf("GET /admin/settings still returns maintenance_mode: %s", w.Body.String())
	}

	// And the contract must not permit it. PlatformSettings is the RESPONSE
	// schema and is additionalProperties:false, so it is the half of the contract
	// that can reject an extra key. (PlatformSettingsInput is deliberately open —
	// it is a partial-merge body — so probing it would prove nothing.)
	//
	// The probe is the REAL response body with the key injected, not a bare
	// {"maintenance_mode":false}: that minimal object fails validation on the
	// missing required fields whatever additionalProperties says, so it would
	// "pass" this test even with the field restored to the schema.
	var settings map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil {
		t.Fatalf("unmarshal settings response: %v", err)
	}
	settings["maintenance_mode"] = false
	withField, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal probe: %v", err)
	}

	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/PlatformSettings")
	if err != nil {
		t.Fatalf("compile PlatformSettings: %v", err)
	}
	probe, err := jsonschema.UnmarshalJSON(strings.NewReader(string(withField)))
	if err != nil {
		t.Fatalf("unmarshal probe: %v", err)
	}
	if err := sch.Validate(probe); err == nil {
		t.Fatal("PlatformSettings still accepts maintenance_mode — a control nothing enforces is back on the contract")
	}
}

// Upsert failure on a provided field → 500.
func TestContract_UpdatePlatformSettings_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newSettingsEngine(&stubPlatformSettingsStore{upsertErr: errAdminTail}, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(`{"platform_name":"Acme"}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// ===================== security-gated settings keys ===========================
//
// The keys in securityGatedSettingKeys decide how staff authenticate or where
// their reset/invite email goes, so writing any of them needs
// platform.security.manage on top of the route's platform.settings. The
// real-router half (seeded roles, real platform_user_has_permission) is
// TestIntegration_StaffSSOTakeover_RealRouter in internal/api.

// One body per gated key, each the smallest write of that key alone.
var securityGatedBodies = map[string]string{
	"admin_ui_base_url":                 `{"admin_ui_base_url":"https://admin.example.test"}`,
	"email_config":                      `{"email_config":{"smtp_host":"smtp.example.test","smtp_port":"587"}}`,
	"password_min_length":               `{"password_min_length":12}`,
	"session_timeout_minutes":           `{"session_timeout_minutes":60}`,
	"max_login_attempts":                `{"max_login_attempts":5}`,
	"lockout_duration_minutes":          `{"lockout_duration_minutes":15}`,
	"admin_email_verification_required": `{"admin_email_verification_required":false}`,
}

// Every gated key has a body above, and every body names a gated key — so the
// table below cannot silently stop covering a key that was added to the list.
func TestSecurityGatedBodies_CoverEveryGatedKey(t *testing.T) {
	if len(securityGatedBodies) != len(securityGatedSettingKeys) {
		t.Fatalf("securityGatedBodies has %d entries, securityGatedSettingKeys has %d", len(securityGatedBodies), len(securityGatedSettingKeys))
	}
	for _, k := range securityGatedSettingKeys {
		if _, ok := securityGatedBodies[k]; !ok {
			t.Errorf("no test body for gated key %q", k)
		}
	}
}

func TestContract_UpdatePlatformSettings_403_GatedKeyWithoutSecurityManage(t *testing.T) {
	sv := loadSpec(t)
	for key, body := range securityGatedBodies {
		t.Run(key, func(t *testing.T) {
			store := &stubPlatformSettingsStore{securityManage: false}
			eng := newSettingsEngine(store, true)
			w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(body))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "SecurityManageRequiredError", w.Body.Bytes())
			var got struct {
				RequiredPermission string   `json:"required_permission"`
				Fields             []string `json:"fields"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.RequiredPermission != "platform.security.manage" || len(got.Fields) != 1 || got.Fields[0] != key {
				t.Fatalf("403 body = %s, want required_permission platform.security.manage and fields [%s]", w.Body.String(), key)
			}
			if len(store.upserted) != 0 {
				t.Fatalf("a refused request still wrote %v", store.upserted)
			}
		})
	}
}

func TestContract_UpdatePlatformSettings_200_GatedKeyWithSecurityManage(t *testing.T) {
	for key, body := range securityGatedBodies {
		t.Run(key, func(t *testing.T) {
			store := &stubPlatformSettingsStore{securityManage: true}
			eng := newSettingsEngine(store, true)
			w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(body))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			if len(store.upserted) != 1 || store.upserted[0] != key {
				t.Fatalf("upserted %v, want [%s]", store.upserted, key)
			}
		})
	}
}

// A request mixing an ungated key with a gated one is refused WHOLE: the
// ungated key must not be saved either.
func TestContract_UpdatePlatformSettings_403_MixedBodyWritesNothing(t *testing.T) {
	store := &stubPlatformSettingsStore{securityManage: false}
	eng := newSettingsEngine(store, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings",
		strings.NewReader(`{"platform_name":"Acme","admin_ui_base_url":"https://elsewhere.example.test"}`))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if len(store.upserted) != 0 {
		t.Fatalf("a refused request still wrote %v", store.upserted)
	}
}

// Ungated keys (tenant-facing sign-up gates, branding) never consult the
// permission, so a stock platform_admin keeps them.
func TestContract_UpdatePlatformSettings_UngatedKeysNeedNoSecurityManage(t *testing.T) {
	store := &stubPlatformSettingsStore{securityManage: false}
	eng := newSettingsEngine(store, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings",
		strings.NewReader(`{"platform_name":"Acme","registration_enabled":true,"email_verification_required":true,"block_personal_email_domains":false,"admin_ui_base_url":""}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(store.permAsked) != 0 {
		t.Fatalf("an ungated write consulted permissions %v", store.permAsked)
	}
}

func TestContract_UpdatePlatformSettings_500_PermissionLookupFails(t *testing.T) {
	store := &stubPlatformSettingsStore{permErr: errAdminTail}
	eng := newSettingsEngine(store, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/settings", strings.NewReader(`{"max_login_attempts":5}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	if len(store.upserted) != 0 {
		t.Fatalf("a failed permission check still wrote %v", store.upserted)
	}
}

// The audit record of a gated write never carries the SMTP password.
func TestSecuritySettingsAuditValues_OmitsSMTPPassword(t *testing.T) {
	s := PlatformSettings{EmailConfig: &EmailConfig{SMTPHost: "smtp.example.test", SMTPPassword: "hunter2-not-real"}}
	got := securitySettingsAuditValues(s, []string{"email_config"})
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "hunter2-not-real") {
		t.Fatalf("audit values leak the SMTP password: %s", b)
	}
	if !strings.Contains(string(b), `"smtp_password_changed":true`) {
		t.Fatalf("audit values should record the rotation as a boolean: %s", b)
	}
}

// =============================== system logs =================================

func newSystemLogsEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group(apiBase)
	g.GET("/admin/monitoring/logs", GetSystemLogs(nil)) // placeholder ignores db
	return r
}

func TestContract_GetSystemLogs_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newSystemLogsEngine()
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/monitoring/logs", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SystemLogsResponse", w.Body.Bytes())
}
