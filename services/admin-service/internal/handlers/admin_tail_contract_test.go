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
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
