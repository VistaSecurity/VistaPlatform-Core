package handlers

// Tests for the force_password_change enforcement.
//
// The seeded default platform admin ships with a PUBLISHED password and
// force_password_change = true. These tests pin the server-side contract:
//
//   1. Login with the flag set → 200, but the access token carries the
//      pwd_change_required claim, which the shared auth middleware turns into
//      403 on every route except change-password / me / logout. A UI redirect
//      alone would not be enforcement; the token itself is limited.
//   2. Login with the flag clear → a normal token with no such claim.
//   3. ChangePassword → clears the flag in SQL, revokes outstanding refresh
//      tokens, and re-issues an UNRESTRICTED cookie session so the browser
//      continues without a re-login.
//
// DB access is mocked with sqlmock; password hashing/verification uses the
// real Argon2id service so the handler path is exercised end-to-end.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	adminauth "github.com/vistasecurity/vistaplatform/admin-service/internal/auth"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

const fpcTestJWTSecret = "force-password-change-test-secret"

// loginUserColumns matches the SELECT in handlers.Login.
var loginUserColumns = []string{
	"id", "email", "first_name", "last_name", "role_id", "role_name",
	"is_active", "email_verified", "force_password_change",
	"last_login_at", "created_at", "updated_at", "password_hash",
}

func newLoginRouter(db *sql.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/auth/login", Login(db, fpcTestJWTSecret, adminauth.NewPlatformRefreshTokenService(db)))
	return r
}

// doLogin posts credentials and returns the decoded response body.
func doLogin(t *testing.T, r *gin.Engine, email, password string) (int, map[string]any) {
	t.Helper()
	body := `{"email":"` + email + `","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// parseClaims decodes (without re-verifying) the pwd_change_required claim.
func tokenHasPwdChangeClaim(t *testing.T, tokenString string) bool {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(fpcTestJWTSecret), nil
	})
	if err != nil {
		t.Fatalf("failed to parse access token: %v", err)
	}
	v, ok := claims["pwd_change_required"].(bool)
	return ok && v
}

// expectLoginQueries wires the sqlmock expectations for a successful Login.
func expectLoginQueries(mock sqlmock.Sqlmock, userID uuid.UUID, email, passwordHash string, forceChange bool) {
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pu.id, pu.email, pu.first_name, pu.last_name, pu.role_id, pr.name as role_name")).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows(loginUserColumns).AddRow(
			userID, email, "Platform", "Admin", uuid.New(), "super_admin",
			true, true, forceChange,
			nil, now, now, passwordHash,
		))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE platform_users SET last_login_at")).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO platform_refresh_tokens")).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
}

// middlewareRouter simulates any downstream service protected by the shared
// JWT middleware, with a normal route plus the three allowlisted ones.
func middlewareRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sharedmw.RequireJWTAuth(sharedmw.AuthConfig{JWTSecret: fpcTestJWTSecret}))
	ok := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	r.GET("/api/v1/admin-service/admin/tenants", ok)
	r.GET("/api/v1/admin-service/admin/auth/me", ok)
	r.POST("/api/v1/admin-service/admin/auth/change-password", ok)
	r.POST("/api/v1/admin-service/admin/auth/logout", ok)
	return r
}

func hitWithBearer(r *gin.Engine, method, path, token string) int {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestLogin_ForcePasswordChange_IssuesLimitedSession(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	const password = "Seed3dAdm!nPwd"
	hash, err := platformPasswordService.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	userID := uuid.New()
	expectLoginQueries(mock, userID, "su_admin@vistaplatform.invalid", hash, true)

	code, resp := doLogin(t, newLoginRouter(db), "su_admin@vistaplatform.invalid", password)
	if code != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (resp: %v)", code, resp)
	}
	if fc, _ := resp["force_password_change"].(bool); !fc {
		t.Fatalf("force_password_change = %v, want true", resp["force_password_change"])
	}
	accessToken, _ := resp["access_token"].(string)
	if accessToken == "" {
		t.Fatal("no access_token in response")
	}
	if !tokenHasPwdChangeClaim(t, accessToken) {
		t.Fatal("access token missing pwd_change_required claim — the session is NOT limited")
	}

	// The limited token must be rejected on a normal route and accepted only on
	// the change-password / me / logout allowlist.
	mw := middlewareRouter()
	if got := hitWithBearer(mw, http.MethodGet, "/api/v1/admin-service/admin/tenants", accessToken); got != http.StatusForbidden {
		t.Errorf("normal route with limited token: status = %d, want 403", got)
	}
	if got := hitWithBearer(mw, http.MethodGet, "/api/v1/admin-service/admin/auth/me", accessToken); got != http.StatusOK {
		t.Errorf("/auth/me with limited token: status = %d, want 200", got)
	}
	if got := hitWithBearer(mw, http.MethodPost, "/api/v1/admin-service/admin/auth/change-password", accessToken); got != http.StatusOK {
		t.Errorf("/auth/change-password with limited token: status = %d, want 200", got)
	}
	if got := hitWithBearer(mw, http.MethodPost, "/api/v1/admin-service/admin/auth/logout", accessToken); got != http.StatusOK {
		t.Errorf("/auth/logout with limited token: status = %d, want 200", got)
	}
}

func TestLogin_NoForcePasswordChange_IssuesNormalSession(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	const password = "N0rmalAdm!nPwd"
	hash, err := platformPasswordService.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	expectLoginQueries(mock, uuid.New(), "admin@example.com", hash, false)

	code, resp := doLogin(t, newLoginRouter(db), "admin@example.com", password)
	if code != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (resp: %v)", code, resp)
	}
	if fc, _ := resp["force_password_change"].(bool); fc {
		t.Fatal("force_password_change = true, want false")
	}
	accessToken, _ := resp["access_token"].(string)
	if tokenHasPwdChangeClaim(t, accessToken) {
		t.Fatal("normal login token unexpectedly carries pwd_change_required")
	}

	// Full access everywhere.
	mw := middlewareRouter()
	if got := hitWithBearer(mw, http.MethodGet, "/api/v1/admin-service/admin/tenants", accessToken); got != http.StatusOK {
		t.Errorf("normal route with normal token: status = %d, want 200", got)
	}
}

func TestChangePassword_ClearsFlagAndRotatesSession(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	const currentPassword = "Seed3dAdm!nPwd"
	const newPassword = "Br@ndNewPassw0rd"
	currentHash, err := platformPasswordService.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	userID := uuid.New()

	// SELECT hash + identity for re-issuing the session.
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pu.password_hash, pu.email, pr.name")).
		WithArgs(userID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"password_hash", "email", "name"}).
			AddRow(currentHash, "su_admin@vistaplatform.invalid", "super_admin"))
	// UPDATE must clear force_password_change (literal in the SQL).
	mock.ExpectExec(`UPDATE\s+platform_users\s+SET password_hash = \$1,\s+force_password_change = false`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// All refresh tokens minted under the old password are revoked...
	mock.ExpectExec(regexp.QuoteMeta("UPDATE platform_refresh_tokens")).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// ...and a fresh one is stored for the rotated session.
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO platform_refresh_tokens")).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Simulate AuthMiddleware + StringifyUserID having authenticated a limited session.
	r.Use(func(c *gin.Context) { c.Set("userID", userID.String()) })
	r.POST("/admin/auth/change-password", ChangePassword(db, fpcTestJWTSecret, adminauth.NewPlatformRefreshTokenService(db)))

	body := `{"current_password":"` + currentPassword + `","new_password":"` + newPassword + `","confirm_password":"` + newPassword + `"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/auth/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("change-password status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}

	// The rotated cookie session must be UNRESTRICTED.
	var newAccessToken string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "platform_access_token" {
			newAccessToken = ck.Value
		}
	}
	if newAccessToken == "" {
		t.Fatal("no rotated platform_access_token cookie after password change")
	}
	if tokenHasPwdChangeClaim(t, newAccessToken) {
		t.Fatal("rotated token still carries pwd_change_required — session not unrestricted")
	}
	mw := middlewareRouter()
	if got := hitWithBearer(mw, http.MethodGet, "/api/v1/admin-service/admin/tenants", newAccessToken); got != http.StatusOK {
		t.Errorf("normal route with rotated token: status = %d, want 200", got)
	}
}
