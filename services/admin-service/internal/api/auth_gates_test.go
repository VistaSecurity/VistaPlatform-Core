package api

// Platform-admin sign-in and recovery gates (pentest-readiness review, edge +
// session slice). admin-service holds the cross-tenant control plane, so its
// front door is the highest-value login in the product.
//
// Every test drives the REAL router from NewServerWithConnections: deleting the
// line in the handler that closes the gap — or the route wiring that hands the
// handler its dependencies — turns the test red. A test that called
// handlers.Login or handlers.ResetPassword directly would stay green through
// deletion of the wiring (see select_tier_gate_test.go in auth-service).
//
//   - POST /auth/login must not tell an unauthenticated caller whether an address
//     is a deleted, deactivated or role-less platform administrator.
//   - ...and an unknown address must cost a password verification, so response
//     time does not separate it from a real account.
//   - POST /auth/reset-password must end every session minted under the old
//     password.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
)

func newAuthGateServer(t *testing.T) (*Server, sqlmock.Sqlmock) {
	t.Helper()
	return newAuthGateServerCfg(t, &config.Config{Environment: "test", JWTSecret: "auth-gate-test-secret"})
}

func newAuthGateServerCfg(t *testing.T, cfg *config.Config) (*Server, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	mock.MatchExpectationsInOrder(false)
	t.Cleanup(func() { _ = db.Close() })
	srv := NewServerWithConnections(cfg, db, db, EditionHooks{})
	return srv, mock
}

func postAdmin(srv *Server, path, body string) *httptest.ResponseRecorder {
	return postAdminFrom(srv, path, body, "")
}

// postAdminFrom posts from a chosen source address ("" keeps httptest's default).
func postAdminFrom(srv *Server, path, body, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin-service"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	return w
}

func adminErr(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return b.Error
}

func argon(t *testing.T, pw string) string {
	t.Helper()
	h, err := passwordsvc.NewPasswordService().HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// expectNoActiveAccount makes the main login lookup miss and the fallback
// lookup return the given row (or no row when exists is false).
func expectNoActiveAccount(mock sqlmock.Sqlmock, exists bool, hash string, active, hasRole bool, deleted bool) {
	mock.ExpectQuery(`FROM platform_users pu\s+JOIN platform_roles pr`).WillReturnError(sql.ErrNoRows)
	rows := sqlmock.NewRows([]string{"exists", "password_hash", "is_active", "has_role", "deleted_at"})
	if exists {
		var del interface{}
		if deleted {
			del = time.Now()
		}
		rows.AddRow(true, hash, active, hasRole, del)
	}
	mock.ExpectQuery(`SELECT true, pu.password_hash, pu.is_active`).WillReturnRows(rows)
}

func TestAdminLogin_AccountStateNotDisclosedWithoutThePassword(t *testing.T) {
	const right = "Right-Passw0rd!"
	cases := []struct {
		name            string
		active, hasRole bool
		deleted         bool
		wantWithRight   string
	}{
		{"deleted", true, true, true, "Account has been deleted"},
		{"inactive", false, true, false, "Account is inactive"},
		{"roleless", true, false, false, "User account is missing a role. Please contact an administrator."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash := argon(t, right)

			srv, mock := newAuthGateServer(t)
			expectNoActiveAccount(mock, true, hash, tc.active, tc.hasRole, tc.deleted)
			w := postAdmin(srv, "/auth/login", `{"email":"admin@example.com","password":"Wrong-Passw0rd!"}`)
			if w.Code != http.StatusUnauthorized || adminErr(t, w) != "Invalid credentials" {
				t.Fatalf("%s account + wrong password => %d %q; want the same 401 \"Invalid credentials\" an unknown address gets", tc.name, w.Code, adminErr(t, w))
			}

			// Whoever proved the password may be told why sign-in is refused.
			srv, mock = newAuthGateServer(t)
			expectNoActiveAccount(mock, true, hash, tc.active, tc.hasRole, tc.deleted)
			w = postAdmin(srv, "/auth/login", `{"email":"admin@example.com","password":"`+right+`"}`)
			if w.Code != http.StatusUnauthorized || adminErr(t, w) != tc.wantWithRight {
				t.Fatalf("%s account + right password => %d %q; want %q", tc.name, w.Code, adminErr(t, w), tc.wantWithRight)
			}
		})
	}
}

func TestAdminLogin_UnknownAddress_SpendsAPasswordVerification(t *testing.T) {
	srv, mock := newAuthGateServer(t)
	expectNoActiveAccount(mock, false, "", false, false, false)

	svc := passwordsvc.NewPasswordService()
	h, _ := svc.HashPassword("calibration-Passw0rd!")
	t0 := time.Now()
	_, _ = svc.VerifyPassword("calibration-Passw0rd!", h)
	oneVerify := time.Since(t0)

	start := time.Now()
	w := postAdmin(srv, "/auth/login", `{"email":"nobody@example.com","password":"Whatever-Passw0rd!"}`)
	elapsed := time.Since(start)
	if w.Code != http.StatusUnauthorized || adminErr(t, w) != "Invalid credentials" {
		t.Fatalf("unknown address => %d %q", w.Code, adminErr(t, w))
	}
	if elapsed < oneVerify/2 {
		t.Fatalf("unknown address answered in %v; one password verification costs %v — response time distinguishes unknown addresses from real accounts", elapsed, oneVerify)
	}
}

func TestAdminResetPassword_EndsEverySessionOfTheUser(t *testing.T) {
	srv, mock := newAuthGateServer(t)
	userID := uuid.New()
	token := "reset-token-for-test"
	sum := sha256.Sum256([]byte(token))

	mock.ExpectQuery(`FROM platform_users\s+WHERE password_reset_token = \$1`).
		WithArgs(hex.EncodeToString(sum[:])).
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_reset_expires"}).AddRow(userID, time.Now().Add(time.Hour)))
	mock.ExpectQuery(`FROM platform_settings`).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE platform_users\s+SET password_hash = \$1`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE platform_refresh_tokens\s+SET is_revoked = true`).
		WithArgs(userID).WillReturnResult(sqlmock.NewResult(0, 3))

	w := postAdmin(srv, "/auth/reset-password",
		`{"token":"`+token+`","new_password":"Brand-New-Passw0rd!","confirm_password":"Brand-New-Passw0rd!"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("reset => %d %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the reset did not revoke the user's refresh tokens: %v", err)
	}
}

// ---- D7: sign-in throttling ------------------------------------------------
//
// The platform-admin login had no rate limiter; its only brake was account
// lockout, which is also a lock-out denial of service. These tests pin that the
// limiter sits in front of the handler on the REAL route, charges the address
// before the account, and is per-account across addresses.

func loginBody(email string) string {
	return `{"email":"` + email + `","password":"Whatever-Passw0rd!"}`
}

// expectUnknownAddresses queues n misses of the two-step unknown-address lookup.
func expectUnknownAddresses(mock sqlmock.Sqlmock, n int) {
	for i := 0; i < n; i++ {
		expectNoActiveAccount(mock, false, "", false, false, false)
	}
}

func TestAdminLogin_SingleSourceFloodIsRefusedBeforeTheHandler(t *testing.T) {
	// LoginRateLimit 2 => 2 per account, 4 per address.
	srv, mock := newAuthGateServerCfg(t, &config.Config{Environment: "test", JWTSecret: "auth-gate-test-secret", LoginRateLimit: 2})
	const ipLimit = 4
	expectUnknownAddresses(mock, ipLimit)

	// Spraying a different account each time: only the per-address limit can stop it.
	for i := 1; i <= ipLimit; i++ {
		w := postAdminFrom(srv, "/auth/login", loginBody(fmt.Sprintf("spray%d@example.com", i)), "198.51.100.7:4000")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d => %d %s; want 401 (within the limit)", i, w.Code, w.Body.String())
		}
	}
	w := postAdminFrom(srv, "/auth/login", loginBody("spray99@example.com"), "198.51.100.7:4000")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d from one address => %d %s; want 429", ipLimit+1, w.Code, w.Body.String())
	}
	if ra, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Fatalf("429 carried Retry-After %q; want a positive number of seconds", w.Header().Get("Retry-After"))
	}
	// The refused attempt must not have reached the handler's database lookups.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected lookups not all consumed by the allowed attempts: %v", err)
	}
	// ...and another address is unaffected.
	expectUnknownAddresses(mock, 1)
	if w := postAdminFrom(srv, "/auth/login", loginBody("spray1@example.com"), "198.51.100.8:4000"); w.Code != http.StatusUnauthorized {
		t.Fatalf("a different address => %d; want 401 (the limit is per address)", w.Code)
	}
}

func TestAdminLogin_PerAccountLimitHoldsAcrossAddresses(t *testing.T) {
	srv, mock := newAuthGateServerCfg(t, &config.Config{Environment: "test", JWTSecret: "auth-gate-test-secret", LoginRateLimit: 2})
	expectUnknownAddresses(mock, 2)
	// A fresh source address every time, so only the PER-ACCOUNT limit can stop it.
	for i := 1; i <= 2; i++ {
		w := postAdminFrom(srv, "/auth/login", loginBody("Victim@Example.com"), fmt.Sprintf("203.0.113.%d:5000", i))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d => %d %s; want 401", i, w.Code, w.Body.String())
		}
	}
	// Different letter case, yet another address: still the same account.
	w := postAdminFrom(srv, "/auth/login", loginBody("victim@example.com"), "203.0.113.200:5000")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd attempt on one account from a fresh address => %d %s; want 429", w.Code, w.Body.String())
	}
}

// A request refused for its ADDRESS must not be charged to the account it names:
// otherwise one noisy source burns the real administrator's budget and the
// limiter becomes the lock-out.
func TestAdminLogin_RefusedAddressDoesNotBurnTheAccountBudget(t *testing.T) {
	srv, mock := newAuthGateServerCfg(t, &config.Config{Environment: "test", JWTSecret: "auth-gate-test-secret", LoginRateLimit: 2})
	const ipLimit = 4
	expectUnknownAddresses(mock, ipLimit)
	for i := 1; i <= ipLimit; i++ { // fill the attacker's address bucket on other accounts
		postAdminFrom(srv, "/auth/login", loginBody(fmt.Sprintf("spray%d@example.com", i)), "198.51.100.7:4000")
	}
	for i := 0; i < 6; i++ { // now flood the victim from the exhausted address
		w := postAdminFrom(srv, "/auth/login", loginBody("admin@example.com"), "198.51.100.7:4000")
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("flood attempt %d => %d; want 429 from the address limiter", i, w.Code)
		}
	}
	// The real administrator, from elsewhere, still has their whole budget.
	expectUnknownAddresses(mock, 1)
	w := postAdminFrom(srv, "/auth/login", loginBody("admin@example.com"), "192.0.2.50:4000")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("the real administrator => %d %s; want 401 (not throttled by someone else's flood)", w.Code, w.Body.String())
	}
}

func TestAdminStaffSSOAuthorize_IsThrottledPerAddress(t *testing.T) {
	srv, _ := newAuthGateServerCfg(t, &config.Config{Environment: "test", JWTSecret: "auth-gate-test-secret", LoginRateLimit: 2})
	const ipLimit = 4
	get := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin-service/admin/sso/example/authorize", nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, req)
		return w
	}
	for i := 1; i <= ipLimit; i++ {
		if w := get("198.51.100.9:1"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d throttled early", i)
		}
	}
	if w := get("198.51.100.9:1"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d => %d; want 429", ipLimit+1, w.Code)
	}
}
