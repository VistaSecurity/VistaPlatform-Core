package api

// Contract test for the tenant org-details surface (Settings → Organization →
// Overview). Extends the auth-service spec-first contract (ADR-0001) and
// reuses the shared harness (loadSpec / assertConforms / do / aTenantID) from
// cross_cutter_contract_test.go.
//
// updateCurrentTenantHandler depends directly on *sql.DB (it isn't behind a
// store interface like the branding/ui-config handlers), so these tests drive
// the real handler with sqlmock — same approach as api_tokens_contract_test.go.
// getCurrentTenantHandler is deliberately not covered here: it predates the
// API contract and has no operationId in the spec yet.

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

func newTenantOrgEngine(t *testing.T, authenticated bool) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", aTenantID)
		}
		c.Next()
	})
	// RequirePermission("settings.update") is deliberately not mounted here:
	// it's generic router middleware with no handler-specific behavior, so
	// covering it is out of scope for this handler-level contract test.
	grp.PUT("/tenant", updateCurrentTenantHandler(db))
	return r, mock
}

// --- PUT /tenant -------------------------------------------------------------

func TestContract_UpdateCurrentTenant_200(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newTenantOrgEngine(t, true)
	mock.ExpectExec(`^UPDATE tenants SET`).WillReturnResult(sqlmock.NewResult(0, 1))

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant", strings.NewReader(`{"name":"Acme Corp"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_UpdateCurrentTenant_200_multipleFields(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newTenantOrgEngine(t, true)
	mock.ExpectExec(`^UPDATE tenants SET`).WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"name":"Acme Corp","domain":"acme.example.com","billing_email":"[email protected]","custom_branding":{"logo_url":"https://cdn.example.com/logo.png"},"ui_config":{"theme":"dark"},"settings":{"timezone":"UTC"}}`
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant", strings.NewReader(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_UpdateCurrentTenant_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newTenantOrgEngine(t, true)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateCurrentTenant_400_noFields(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newTenantOrgEngine(t, true)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateCurrentTenant_401(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newTenantOrgEngine(t, false)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant", strings.NewReader(`{"name":"Acme Corp"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateCurrentTenant_404(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newTenantOrgEngine(t, true)
	mock.ExpectExec(`^UPDATE tenants SET`).WillReturnResult(sqlmock.NewResult(0, 0))

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant", strings.NewReader(`{"name":"Acme Corp"}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateCurrentTenant_500(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newTenantOrgEngine(t, true)
	mock.ExpectExec(`^UPDATE tenants SET`).WillReturnError(errors.New("db down"))

	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant", strings.NewReader(`{"name":"Acme Corp"}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
