package api

// C1/H1 (v1.0.0 security audit) — auth-service authenticates platform_users as
// a fallback when the tenant lookup misses, and that fallback was missing two
// controls admin-service's own platform login has always had:
//
//   - force_password_change was neither SELECTed nor honoured. The seed ships
// the PUBLISHED super-admin accounts with the flag set; admin-service
//     answers that with a limited pwd_change_required session, auth-service
//     answered with an unrestricted super_admin token. The claim had exactly one
//     enforcement site in this service and zero issuance sites, so the gate was
//     unreachable from here.
//   - deleted_at / is_active were not filtered, so a platform administrator
//     deleted in admin-ui (a soft delete that does not clear is_active) kept a
//     working login on the public tenant host.
//
// Every test here drives the REAL SetupRouter. A test that exercised
// AuthService.Login or the JWT helper in isolation would stay green through the
// deletion of the router wiring that actually makes the limited session bite.

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

// newPlatformLoginRouter builds the real router over a sqlmock database.
// rateLimiter is nil, matching select_tier_gate_test.go, so /auth/login does not
// reach Redis.
func newPlatformLoginRouter(t *testing.T, db *sql.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWTSecret: platformLoginSecret, JWTExpiry: time.Hour}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	t.Cleanup(func() { _ = rdb.Close() })
	return SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})
}

// expectTenantUserMiss makes AuthService.GetUserByEmail return ErrUserNotFound,
// which is what routes Login into the platform_users branch.
func expectTenantUserMiss(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`FROM users\s+WHERE email = \$1 AND deleted_at IS NULL`).
		WillReturnError(sql.ErrNoRows)
}

// platformUserRow is the shape getPlatformUserByEmail scans.
func platformUserRow(id uuid.UUID, email, hash string, forcePasswordChange bool) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "email", "password_hash", "first_name", "last_name",
		"is_active", "email_verified", "force_password_change",
		"last_login_at", "created_at", "role_name",
	}).AddRow(id, email, hash, "Super", "Admin", true, true, forcePasswordChange,
		nil, time.Now(), "super_admin")
}

// expectSuccessfulPlatformLogin mocks everything the platform branch touches
// after the lookup: lockout probe, counter reset, session-policy read, last-login
// stamp and the refresh-token insert.
func expectSuccessfulPlatformLogin(mock sqlmock.Sqlmock, userID uuid.UUID) {
	mock.ExpectQuery(`SELECT locked_until FROM platform_users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"locked_until"}).AddRow(nil))
	mock.ExpectExec(`UPDATE platform_users SET failed_login_attempts = 0`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`FROM platform_settings`).
		WillReturnError(sql.ErrNoRows) // no operator policy → built-in default TTL
	mock.ExpectExec(`UPDATE platform_users SET last_login_at`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`INSERT INTO refresh_tokens`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
}

// hashSeededPassword produces a real Argon2id hash so VerifyPassword succeeds
// against the published seed password.
func hashSeededPassword(t *testing.T) string {
	t.Helper()
	hash, err := passwordsvc.NewPasswordService().HashPassword(seededPlatformPassword)
	if err != nil {
		t.Fatalf("hash seeded password: %v", err)
	}
	return hash
}

func postPlatformLogin(t *testing.T, router *gin.Engine, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/login",
		strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func accessTokenFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v; body=%s", err, w.Body.String())
	}
	if body.AccessToken == "" {
		t.Fatalf("login returned no access token; body=%s", w.Body.String())
	}
	return body.AccessToken
}

// replayOnProtectedRoute presents the token to GET /auth/sessions — an
// authenticated route that is NOT on the password-change allowlist, so a limited
// session must be refused there.
func replayOnProtectedRoute(router *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth-service/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestPlatformLogin_ForcedPasswordChangeYieldsLimitedSession is the C1 proof.
// The seeded super-admin authenticates, but the token it gets back is limited:
// replayed against a normal authenticated route the real router refuses it with
// password_change_required.
//
// Mutation: drop `forcePasswordChange` from the
// GenerateTokensWithPasswordChange call in AuthService.Login (or drop
// force_password_change from getPlatformUserByEmail's SELECT) and the replay
// returns something other than 403/password_change_required.
func TestPlatformLogin_ForcedPasswordChangeYieldsLimitedSession(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)

	userID := uuid.New()
	email := "su_admin@vistaplatform.invalid"
	expectTenantUserMiss(mock)
	mock.ExpectQuery(`FROM platform_users pu`).
		WithArgs(email).
		WillReturnRows(platformUserRow(userID, email, hashSeededPassword(t), true))
	expectSuccessfulPlatformLogin(mock, userID)

	router := newPlatformLoginRouter(t, db)
	w := postPlatformLogin(t, router, email, seededPlatformPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	// Both halves of the pair must carry the claim. The refresh token's copy is
	// belt-and-braces — RefreshToken re-reads force_password_change from the
	// database — but a pair where only one half is limited is a shape nobody
	// should be able to introduce silently.
	var pair struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pair); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	refreshClaims, err := auth.NewJWTService(platformLoginSecret, time.Hour, time.Hour).
		ValidateToken(pair.RefreshToken)
	if err != nil {
		t.Fatalf("validate issued refresh token: %v", err)
	}
	if !refreshClaims.PasswordChangeRequired {
		t.Fatal("issued REFRESH token does not carry pwd_change_required")
	}

	token := accessTokenFrom(t, w)

	// The claim must be in the token...
	claims, err := auth.NewJWTService(platformLoginSecret, time.Hour, time.Hour).ValidateToken(token)
	if err != nil {
		t.Fatalf("validate issued token: %v", err)
	}
	if !claims.PasswordChangeRequired {
		t.Fatal("issued access token does not carry pwd_change_required — the seeded super-admin got an UNRESTRICTED platform session (C1)")
	}

	// ...and it must actually bite on the real router.
	replay := replayOnProtectedRoute(router, token)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("limited session reached GET /auth/sessions with status %d, want 403; body=%s",
			replay.Code, replay.Body.String())
	}
	if !strings.Contains(replay.Body.String(), "password_change_required") {
		t.Fatalf("403 body does not name the gate: %s", replay.Body.String())
	}
}

// TestPlatformLogin_CleanAccountGetsUnrestrictedSession pins the other polarity.
// Without it, a change that stamped pwd_change_required on EVERY platform login
// — locking every operator out of the platform — would look like a pass.
func TestPlatformLogin_CleanAccountGetsUnrestrictedSession(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)

	userID := uuid.New()
	email := "rotated_admin@vistaplatform.invalid"
	expectTenantUserMiss(mock)
	mock.ExpectQuery(`FROM platform_users pu`).
		WithArgs(email).
		WillReturnRows(platformUserRow(userID, email, hashSeededPassword(t), false))
	expectSuccessfulPlatformLogin(mock, userID)

	router := newPlatformLoginRouter(t, db)
	w := postPlatformLogin(t, router, email, seededPlatformPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	claims, err := auth.NewJWTService(platformLoginSecret, time.Hour, time.Hour).
		ValidateToken(accessTokenFrom(t, w))
	if err != nil {
		t.Fatalf("validate issued token: %v", err)
	}
	if claims.PasswordChangeRequired {
		t.Fatal("an operator with no forced rotation received a LIMITED session")
	}
}

// TestPlatformLogin_RefreshKeepsTheLimitedSessionLimited closes the laundering
// route: if only the access token carried the claim, one refresh would hand back
// an unrestricted pair and the whole gate would be cosmetic.
//
// This one drives AuthService.RefreshToken rather than the route, because the
// route cannot complete today for a platform user at all: the platform branch
// of RefreshToken returns an AuthResponse with a nil User and the handler
// dereferences it (handlers.go — `authResponse.User.PasswordHash = ""`), so the
// request panics into a 500. That is a pre-existing bug, reported separately;
// asserting a 200 here would be asserting someone else's fix.
//
// Mutation: drop `forcePasswordChange` from the refresh branch's
// GenerateTokensWithPasswordChange call, or stop passing it out of
// getPlatformUserByID — this goes red.
func TestPlatformLogin_RefreshKeepsTheLimitedSessionLimited(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)

	userID := uuid.New()
	email := "su_admin@vistaplatform.invalid"

	// Mint the limited refresh token exactly as Login does.
	jwtService := auth.NewJWTService(platformLoginSecret, time.Hour, time.Hour)
	_, refreshToken, err := jwtService.GenerateTokensWithPasswordChange(
		userID, uuid.Nil, email, "super_admin", time.Hour, true)
	if err != nil {
		t.Fatalf("mint refresh token: %v", err)
	}

	// RefreshToken: tenant lookup misses, platform lookup hits, then rotation.
	mock.ExpectQuery(`FROM users\s+WHERE id = \$1`).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`FROM platform_users pu`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "email", "first_name", "last_name",
			"is_active", "email_verified", "force_password_change",
			"last_login_at", "created_at", "role_name",
		}).AddRow(userID, email, "Super", "Admin", true, true, true, nil, time.Now(), "super_admin"))
	mock.ExpectQuery(`FROM platform_settings`).WillReturnError(sql.ErrNoRows)
	// ValidateAndRotateToken: find, revoke old, insert new.
	created := time.Now().Add(-time.Minute)
	mock.ExpectQuery(`FROM refresh_tokens`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "family_id", "expires_at", "is_revoked", "last_used_at", "created_at"}).
			AddRow(uuid.New(), uuid.New(), time.Now().Add(time.Hour), false, created, created))
	mock.ExpectExec(`UPDATE refresh_tokens`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`INSERT INTO refresh_tokens`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rdb.Close() })
	svc := auth.NewAuthService(db, db, rdb, jwtService)

	resp, err := svc.RefreshToken(refreshToken, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	claims, err := jwtService.ValidateToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("validate refreshed token: %v", err)
	}
	if !claims.PasswordChangeRequired {
		t.Fatal("refresh laundered a LIMITED platform session into an unrestricted one")
	}
	// The refreshed token must also still be refused by the real router.
	router := newPlatformLoginRouter(t, db)
	replay := replayOnProtectedRoute(router, resp.AccessToken)
	if replay.Code != http.StatusForbidden || !strings.Contains(replay.Body.String(), "password_change_required") {
		t.Fatalf("refreshed limited session reached GET /auth/sessions: status %d body=%s",
			replay.Code, replay.Body.String())
	}
}

// TestPlatformLogin_SoftDeletedOperatorIsRefused is the H1 wiring proof.
// DeletePlatformUser only stamps deleted_at — it does not clear is_active — so
// the login lookup is the only thing standing between a removed administrator
// and a working session on the public tenant host.
//
// The expectation requires BOTH filters in the SQL text. Delete either from
// getPlatformUserByEmail and the query no longer matches, leaving an unmet
// expectation that fails this test. (The status alone would not: an unmatched
// query errors, and Login maps any lookup error to the same 401.)
func TestPlatformLogin_SoftDeletedOperatorIsRefused(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)

	email := "removed_admin@vistaplatform.invalid"
	expectTenantUserMiss(mock)
	// The row exists in platform_users but is soft-deleted, so the filtered
	// query matches nothing.
	mock.ExpectQuery(`FROM platform_users pu[\s\S]*WHERE pu\.email = \$1 AND pu\.deleted_at IS NULL AND pu\.is_active = true`).
		WithArgs(email).
		WillReturnError(sql.ErrNoRows)

	router := newPlatformLoginRouter(t, db)
	w := postPlatformLogin(t, router, email, seededPlatformPassword)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("deleted operator login status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the platform-user lookup did not carry both the deleted_at and is_active filters: %v", err)
	}
}
