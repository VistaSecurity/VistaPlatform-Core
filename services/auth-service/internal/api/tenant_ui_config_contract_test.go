package api

// Contract test for the tenant + platform UI-config surface (app shell + Settings).
// Extends the auth-service spec-first contract (ADR-0001) and reuses the shared
// harness (loadSpec / assertConforms / do / aTenantID) from
// cross_cutter_contract_test.go.
//
// GetTenantUIConfig / UpdateTenantUIConfig / GetPublicPlatformUIConfig were
// refactored to depend on the tenantUIConfigStore interface (via the *WithStore
// variants; the *sql.DB-backed repo is the production impl), so these tests drive
// the real handlers with an in-memory stub — no database.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type stubTenantUIConfigStore struct {
	platformJSON []byte
	platformErr  error
	tenantJSON   []byte
	tenantErr    error
	updateErr    error
}

func (s *stubTenantUIConfigStore) GetPlatformUIConfigJSON(_ context.Context) ([]byte, error) {
	if s.platformErr != nil {
		return nil, s.platformErr
	}
	if s.platformJSON == nil {
		return nil, sql.ErrNoRows // no platform default -> handler treats as empty (non-fatal)
	}
	return s.platformJSON, nil
}

func (s *stubTenantUIConfigStore) GetTenantUIConfigJSON(_ context.Context, _ uuid.UUID) ([]byte, error) {
	if s.tenantErr != nil {
		return nil, s.tenantErr
	}
	if s.tenantJSON == nil {
		return []byte("{}"), nil
	}
	return s.tenantJSON, nil
}

func (s *stubTenantUIConfigStore) UpdateTenantUIConfigJSON(_ context.Context, _ uuid.UUID, _ []byte) error {
	return s.updateErr
}

func newUIConfigEngine(store tenantUIConfigStore, authenticated bool, tenantID, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if store == nil {
		store = &stubTenantUIConfigStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", tenantID)
		}
		if role != "" {
			c.Set("role", role)
		}
		c.Next()
	})
	grp.GET("/tenant/ui-config", GetTenantUIConfigWithStore(store))
	grp.PUT("/tenant/ui-config", UpdateTenantUIConfigWithStore(store))
	grp.GET("/platform/ui-config", GetPublicPlatformUIConfigWithStore(store))
	return r
}

// --- GET /tenant/ui-config --------------------------------------------------

func TestContract_GetTenantUIConfig_200_defaults(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{}, true, aTenantID, "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ui-config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UIConfigResponse", w.Body.Bytes())
}

func TestContract_GetTenantUIConfig_200_populated(t *testing.T) {
	sv := loadSpec(t)
	store := &stubTenantUIConfigStore{
		platformJSON: []byte(`{"theme":"dark","palette":"blue"}`),
		tenantJSON:   []byte(`{"accent_color":"#abcdef","enhancements":{"shadows":true},"custom_css":".x{}"}`),
	}
	eng := newUIConfigEngine(store, true, aTenantID, "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ui-config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UIConfigResponse", w.Body.Bytes())
}

func TestContract_GetTenantUIConfig_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{}, false, aTenantID, "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ui-config", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantUIConfig_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{tenantErr: sql.ErrNoRows}, true, aTenantID, "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ui-config", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantUIConfig_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{tenantErr: errors.New("db down")}, true, aTenantID, "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ui-config", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- GET /platform/ui-config (unauthenticated) ------------------------------

func TestContract_GetPublicPlatformUIConfig_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{platformJSON: []byte(`{"theme":"dark","palette":"slate"}`)}, false, "", "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/platform/ui-config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UIConfigResponse", w.Body.Bytes())
}

// --- PUT /tenant/ui-config (platform_admin only) ----------------------------

func TestContract_UpdateTenantUIConfig_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{}, true, aTenantID, "platform_admin")
	body := strings.NewReader(`{"theme":"dark","palette":"blue","layout":"default"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ui-config", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateUIConfigResponse", w.Body.Bytes())
}

func TestContract_UpdateTenantUIConfig_403_notPlatformAdmin(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{}, true, aTenantID, "tenant_admin")
	body := strings.NewReader(`{"theme":"dark"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ui-config", body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantUIConfig_401(t *testing.T) {
	sv := loadSpec(t)
	// platform_admin role present but no tenant context -> 401.
	eng := newUIConfigEngine(&stubTenantUIConfigStore{}, false, aTenantID, "platform_admin")
	body := strings.NewReader(`{"theme":"dark"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ui-config", body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantUIConfig_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{}, true, aTenantID, "platform_admin")
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ui-config", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantUIConfig_400_invalidPalette(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{}, true, aTenantID, "platform_admin")
	body := strings.NewReader(`{"palette":"rainbow"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ui-config", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantUIConfig_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{tenantErr: sql.ErrNoRows}, true, aTenantID, "platform_admin")
	body := strings.NewReader(`{"theme":"dark"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ui-config", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateTenantUIConfig_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newUIConfigEngine(&stubTenantUIConfigStore{updateErr: errors.New("db down")}, true, aTenantID, "platform_admin")
	body := strings.NewReader(`{"theme":"dark"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/ui-config", body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
