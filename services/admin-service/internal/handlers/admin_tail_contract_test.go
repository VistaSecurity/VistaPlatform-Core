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
}

func (s *stubPlatformSettingsStore) ListSettings(context.Context) ([]platformSettingKV, error) {
	return s.list, s.listErr
}
func (s *stubPlatformSettingsStore) UpsertSetting(context.Context, string, []byte, uuid.UUID) error {
	return s.upsertErr
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
			eng := newSettingsEngine(&stubPlatformSettingsStore{}, true)
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
	eng := newSettingsEngine(&stubPlatformSettingsStore{}, true)
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
