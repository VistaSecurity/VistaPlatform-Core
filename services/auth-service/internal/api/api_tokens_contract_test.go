package api

// Contract test for the API-tokens surface (Settings → API Tokens; consumed
// programmatically by mcp-service clients). Extends the auth-service
// spec-first contract (ADR-0001) and reuses the shared harness (loadSpec /
// assertConforms / do) from cross_cutter_contract_test.go.
//
// The apitokens handlers depend only on *apitokens.Service (a thin *sql.DB
// wrapper), so the 200/201 paths are driven with sqlmock — no real database.
// The internal /api-tokens/exchange endpoint is HMAC service-to-service only
// and deliberately unspecced (see the spec's api-tokens section comment).

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/apitokens"
)

const apiTokensBase = "/api/v1/auth-service/api-tokens"

func newAPITokensEngine(t *testing.T, authenticated bool) (*gin.Engine, sqlmock.Sqlmock) {
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
			c.Set("userID", "44444444-4444-4444-4444-444444444444")
		}
		c.Next()
	})
	// Exchange deps (auth service, jwt service) are not exercised by the
	// specced routes — nil is safe here.
	h := apitokens.NewHandlers(apitokens.NewService(db, db), nil, nil)
	grp.GET("/api-tokens", h.ListTokens)
	grp.POST("/api-tokens", h.CreateToken)
	grp.DELETE("/api-tokens/:id", h.RevokeToken)
	return r, mock
}

var apiTokenCols = []string{"id", "tenant_id", "user_id", "name", "token_prefix", "permissions",
	"expires_at", "last_used_at", "revoked_at", "created_at"}

// --- POST /api-tokens --------------------------------------------------------

func TestContract_CreateApiToken_201(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAPITokensEngine(t, true)
	// RLS Phase 3: the active-count read and the INSERT each run inside their own
	// WithTenantTx (Begin → set_tenant_context → op → Commit).
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM api_tokens")).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO api_tokens")).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	w := do(eng, http.MethodPost, apiTokensBase, strings.NewReader(`{"name":"contract test token","permissions":["assets.read"],"expires_in_days":30}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "APITokenCreateResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"plaintext_token":"qvpat_`) {
		t.Fatalf("plaintext token missing or unprefixed: %s", w.Body.String())
	}
}

func TestContract_CreateApiToken_400_MissingName(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAPITokensEngine(t, true)
	w := do(eng, http.MethodPost, apiTokensBase, strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateApiToken_400_WritePermission(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAPITokensEngine(t, true)
	w := do(eng, http.MethodPost, apiTokensBase, strings.NewReader(`{"name":"x","permissions":["assets.manage"]}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateApiToken_401(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAPITokensEngine(t, false)
	w := do(eng, http.MethodPost, apiTokensBase, strings.NewReader(`{"name":"x"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateApiToken_409_Cap(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAPITokensEngine(t, true)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM api_tokens")).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(apitokens.MaxActiveTokensPerUser))
	mock.ExpectCommit()
	w := do(eng, http.MethodPost, apiTokensBase, strings.NewReader(`{"name":"one too many"}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- GET /api-tokens ---------------------------------------------------------

func TestContract_ListApiTokens_200(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAPITokensEngine(t, true)
	now := time.Now().UTC()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("FROM api_tokens")).
		WillReturnRows(sqlmock.NewRows(apiTokenCols).AddRow(
			"55555555-5555-5555-5555-555555555555", aTenantID, "44444444-4444-4444-4444-444444444444",
			"ci token", "qvpat_AbCd", []byte(`["assets.read","compliance.read"]`),
			now.Add(90*24*time.Hour), nil, nil, now))
	mock.ExpectCommit()

	w := do(eng, http.MethodGet, apiTokensBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "APITokenListResponse", w.Body.Bytes())
}

func TestContract_ListApiTokens_200_Empty(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAPITokensEngine(t, true)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("FROM api_tokens")).
		WillReturnRows(sqlmock.NewRows(apiTokenCols))
	mock.ExpectCommit()
	w := do(eng, http.MethodGet, apiTokensBase, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "APITokenListResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"tokens":[]`) {
		t.Fatalf("empty list must serialize as [], got %s", w.Body.String())
	}
}

func TestContract_ListApiTokens_401(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAPITokensEngine(t, false)
	w := do(eng, http.MethodGet, apiTokensBase, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- DELETE /api-tokens/{id} -------------------------------------------------

func TestContract_RevokeApiToken_200(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAPITokensEngine(t, true)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE api_tokens SET revoked_at")).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	w := do(eng, http.MethodDelete, apiTokensBase+"/"+uuid.NewString(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "APITokenRevokeResponse", w.Body.Bytes())
}

func TestContract_RevokeApiToken_404(t *testing.T) {
	sv := loadSpec(t)
	eng, mock := newAPITokensEngine(t, true)
	// Revoke runs in WithTenantTx; the not-found sentinel returns before Commit,
	// so the deferred Rollback fires.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE api_tokens SET revoked_at")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS")).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectRollback()
	w := do(eng, http.MethodDelete, apiTokensBase+"/"+uuid.NewString(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RevokeApiToken_400_BadID(t *testing.T) {
	sv := loadSpec(t)
	eng, _ := newAPITokensEngine(t, true)
	w := do(eng, http.MethodDelete, apiTokensBase+"/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
