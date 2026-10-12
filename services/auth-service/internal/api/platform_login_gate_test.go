package api

// -- auth-service does not sign platform accounts in. refresh_tokens.user_id
// has a foreign key to users, so the platform branch Login used to carry could
// never persist its refresh token on a real database (a 500), and the sqlmock
// tests never saw it. The tenant sign-in paths now refuse platform credentials
// with a stable 403 code and the admin console address, and mint nothing.
//
// Every test drives the REAL SetupRouter over sqlmock. sqlmock fails the request
// on any query that was not expected, so "no INSERT INTO refresh_tokens" and
// "no token pair" are enforced by the absence of an expectation as well as by
// the assertions.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
)

const platformLoginSecret = "test-secret-for-platform-login-gate"
const seededPlatformPassword = "PlatformAdm!n2026"
const platformAdminURL = "https://admin.example.test"

func newPlatformLoginRouter(t *testing.T, db *sql.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: platformLoginSecret, JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on these paths
	t.Cleanup(func() { _ = rdb.Close() })
	return SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})
}

func newPlatformMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.MatchExpectationsInOrder(false)
	return db, mock
}

func expectTenantUserMiss(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`FROM users\s+WHERE lower\(email\) = \$1 AND deleted_at IS NULL`).
		WillReturnError(sql.ErrNoRows)
}

func hashSeededPassword(t *testing.T) string {
	t.Helper()
	hash, err := passwordsvc.NewPasswordService().HashPassword(seededPlatformPassword)
	if err != nil {
		t.Fatalf("hash seeded password: %v", err)
	}
	return hash
}

func expectPlatformLookup(mock sqlmock.Sqlmock, id uuid.UUID, email, hash string) {
	mock.ExpectQuery(`FROM platform_users pu[\s\S]*WHERE lower\(pu\.email\) = \$1 AND pu\.deleted_at IS NULL AND pu\.is_active = true`).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_hash"}).AddRow(id, hash))
	mock.ExpectQuery(`SELECT locked_until FROM platform_users WHERE id = \$1`).
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"locked_until"}).AddRow(nil))
}

func postPlatformLogin(router *gin.Engine, email, password string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/login",
		strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func assertPlatformRefusal(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	if body["code"] != auth.PlatformAccountCode {
		t.Fatalf("code = %v, want %s; body=%s", body["code"], auth.PlatformAccountCode, w.Body.String())
	}
	if body["admin_url"] != platformAdminURL {
		t.Fatalf("admin_url = %v, want %s; body=%s", body["admin_url"], platformAdminURL, w.Body.String())
	}
	for _, k := range []string{"access_token", "refresh_token", "user"} {
		if _, present := body[k]; present {
			t.Fatalf("a refused platform sign-in leaked %q: %s", k, w.Body.String())
		}
	}
	for _, c := range w.Result().Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			t.Fatalf("a refused platform sign-in set cookie %q", c.Name)
		}
	}
}

// Correct platform credentials: 403 + stable code + admin URL, no session, no
// refresh-token INSERT. Mutation: restore the old branch (mint + store) and the
// unexpected INSERT / the 200 fails this.
func TestPlatformLogin_CorrectCredentialsAreRefusedWithAdminConsolePointer(t *testing.T) {
	t.Setenv("ADMIN_UI_BASE_URL", platformAdminURL)
	db, mock := newPlatformMock(t)
	userID := uuid.New()
	email := "su_admin@vistaplatform.invalid"
	expectTenantUserMiss(mock)
	expectPlatformLookup(mock, userID, email, hashSeededPassword(t))
	mock.ExpectExec(`UPDATE platform_users SET failed_login_attempts = 0`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`FROM platform_settings WHERE setting_key = 'admin_ui_base_url'`).
		WillReturnError(sql.ErrNoRows)

	w := postPlatformLogin(newPlatformLoginRouter(t, db), email, seededPlatformPassword)
	assertPlatformRefusal(t, w)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// A wrong password for a platform account answers exactly what a wrong password
// for a tenant user (or an unknown address) answers: 401, no code, no URL.
func TestPlatformLogin_WrongPasswordIsIndistinguishableFromUnknownAddress(t *testing.T) {
	t.Setenv("ADMIN_UI_BASE_URL", platformAdminURL)
	db, mock := newPlatformMock(t)
	userID := uuid.New()
	email := "su_admin@vistaplatform.invalid"
	expectTenantUserMiss(mock)
	expectPlatformLookup(mock, userID, email, hashSeededPassword(t))
	mock.ExpectQuery(`FROM platform_settings`).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE platform_users\s+SET failed_login_attempts = failed_login_attempts \+ 1`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	router := newPlatformLoginRouter(t, db)

	wrong := postPlatformLogin(router, email, "not-the-password")

	expectTenantUserMiss(mock)
	mock.ExpectQuery(`FROM platform_users pu`).WillReturnError(sql.ErrNoRows)
	unknown := postPlatformLogin(router, "nobody@vistaplatform.invalid", "not-the-password")

	if wrong.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d, unknown address = %d; want both 401", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Fatalf("bodies differ:\n wrong:   %s\n unknown: %s", wrong.Body.String(), unknown.Body.String())
	}
	if strings.Contains(wrong.Body.String(), auth.PlatformAccountCode) || strings.Contains(wrong.Body.String(), platformAdminURL) {
		t.Fatalf("an unauthenticated caller learned the address is a platform account: %s", wrong.Body.String())
	}
}

// A soft-deleted or deactivated operator is not a platform account here: the
// lookup must carry both filters (the unmet expectation fails the test if either
// is dropped) and the answer is the ordinary 401.
func TestPlatformLogin_SoftDeletedOperatorIsAnUnknownAddress(t *testing.T) {
	db, mock := newPlatformMock(t)
	email := "removed_admin@vistaplatform.invalid"
	expectTenantUserMiss(mock)
	mock.ExpectQuery(`FROM platform_users pu[\s\S]*WHERE lower\(pu\.email\) = \$1 AND pu\.deleted_at IS NULL AND pu\.is_active = true`).
		WithArgs(email).
		WillReturnError(sql.ErrNoRows)

	w := postPlatformLogin(newPlatformLoginRouter(t, db), email, seededPlatformPassword)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("deleted operator login status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the platform lookup did not carry both the deleted_at and is_active filters: %v", err)
	}
}

// POST /auth/refresh with a platform refresh token: same 403, nothing rotated.
func TestPlatformRefresh_IsRefusedWithAdminConsolePointer(t *testing.T) {
	t.Setenv("ADMIN_UI_BASE_URL", platformAdminURL)
	db, mock := newPlatformMock(t)
	userID := uuid.New()
	jwtService := auth.NewJWTService(platformLoginSecret, time.Hour, time.Hour)
	_, refreshToken, err := jwtService.GenerateTokensWithPasswordChange(
		userID, uuid.Nil, "su_admin@vistaplatform.invalid", "super_admin", time.Hour, false)
	if err != nil {
		t.Fatalf("mint refresh token: %v", err)
	}
	mock.ExpectQuery(`FROM users\s+WHERE id = \$1`).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`FROM platform_users WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(userID))
	mock.ExpectQuery(`FROM platform_settings WHERE setting_key = 'admin_ui_base_url'`).
		WillReturnError(sql.ErrNoRows)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/refresh",
		strings.NewReader(`{"refresh_token":"`+refreshToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	newPlatformLoginRouter(t, db).ServeHTTP(w, req)
	assertPlatformRefusal(t, w)
}
