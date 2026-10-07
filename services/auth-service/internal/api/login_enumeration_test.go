package api

// Account-enumeration and per-account brute-force gates on the unauthenticated
// sign-in surface (pentest-readiness review, edge + session slice).
//
// Every test drives the REAL SetupRouter, so deleting the line in a handler or in
// Login that closes the gap turns the test red. Testing AuthService.Login or the
// handler in isolation would stay green through exactly that deletion (see
// select_tier_gate_test.go for the pattern).
//
// What is pinned:
//
//   - POST /auth/methods must not return the tenant UUID of a registered address
//     unless a tenant SSO method needs it (the response used to differ for known
//     vs unknown emails in every edition, including Core).
//   - POST /auth/login must answer a deactivated account that is given the WRONG
//     password exactly like an unknown address (it used to answer 403 "inactive"
//     before looking at the password).
//   - An SSO-only account (NULL password hash) must answer like a wrong password,
//     not 500.
//   - Login must spend a password verification on an unknown address so response
//     time does not distinguish it from a real account.
//   - POST /auth/authenticate (the email-first flow's password step) must honour
//     the same per-email rate limit POST /auth/login does.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/middleware"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
)

const enumTestSecret = "test-secret-for-login-enumeration"

// minimalFakeRedis is the smallest in-process stand-in for the Redis commands
// the sign-in surface uses: SET [NX] [EX|PX], GET, DEL, INCR, PTTL and the
// MULTI/EXEC wrapper of a TxPipeline. It never dials.
type minimalFakeRedis struct {
	mu   sync.Mutex
	vals map[string]string
}

func (f *minimalFakeRedis) DialHook(redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("minimalFakeRedis never dials")
	}
}

func (f *minimalFakeRedis) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.apply(cmd)
		return cmd.Err()
	}
}

func (f *minimalFakeRedis) ProcessPipelineHook(redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(_ context.Context, cmds []redis.Cmder) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, cmd := range cmds {
			f.apply(cmd)
		}
		return nil
	}
}

func (f *minimalFakeRedis) apply(cmd redis.Cmder) {
	args := cmd.Args()
	switch strings.ToLower(cmd.Name()) {
	case "multi":
		cmd.(*redis.StatusCmd).SetVal("OK")
	case "exec":
		cmd.(*redis.SliceCmd).SetVal(nil)
	case "set":
		key := fmt.Sprint(args[1])
		nx := false
		for _, a := range args[3:] {
			if strings.EqualFold(fmt.Sprint(a), "nx") {
				nx = true
			}
		}
		_, exists := f.vals[key]
		written := !nx || !exists
		if written {
			if b, ok := args[2].([]byte); ok {
				f.vals[key] = string(b)
			} else {
				f.vals[key] = fmt.Sprint(args[2])
			}
		}
		switch c := cmd.(type) {
		case *redis.BoolCmd:
			c.SetVal(written)
		case *redis.StatusCmd:
			c.SetVal("OK")
		}
	case "get":
		v, ok := f.vals[fmt.Sprint(args[1])]
		if !ok {
			cmd.SetErr(redis.Nil)
			return
		}
		cmd.(*redis.StringCmd).SetVal(v)
	case "del":
		delete(f.vals, fmt.Sprint(args[1]))
		cmd.(*redis.IntCmd).SetVal(1)
	case "incr":
		n, _ := strconv.ParseInt(f.vals[fmt.Sprint(args[1])], 10, 64)
		n++
		f.vals[fmt.Sprint(args[1])] = strconv.FormatInt(n, 10)
		cmd.(*redis.IntCmd).SetVal(n)
	case "pttl":
		cmd.(*redis.DurationCmd).SetVal(time.Minute)
	default:
		cmd.SetErr(fmt.Errorf("minimalFakeRedis: unsupported command %q", cmd.Name()))
	}
}

func newEnumerationRouter(t *testing.T, limiterLoginLimit int) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rdb := redis.NewClient(&redis.Options{Addr: "fake-redis.invalid:6379"})
	rdb.AddHook(&minimalFakeRedis{vals: map[string]string{}})
	t.Cleanup(func() { _ = rdb.Close() })

	var limiter *middleware.RateLimiter
	if limiterLoginLimit > 0 {
		limiter = middleware.NewRateLimiter(rdb, 1000, time.Minute, limiterLoginLimit)
	}
	cfg := &config.Config{JWTSecret: enumTestSecret, JWTExpiry: time.Hour}
	return SetupRouter(cfg, db, db, rdb, limiter, EditionHooks{}), mock
}

var enumUserColumns = []string{
	"id", "tenant_id", "email", "password_hash", "first_name", "last_name",
	"is_active", "email_verified", "last_login_at", "avatar_url", "timezone", "preferences",
	"created_at", "updated_at", "deleted_at",
}

// expectTenantUser queues the GetUserByEmail row. passwordHash == "" yields a
// NULL password_hash (an SSO-only account).
func expectTenantUser(mock sqlmock.Sqlmock, passwordHash string, active bool) {
	var hash interface{}
	if passwordHash != "" {
		hash = passwordHash
	}
	now := time.Now()
	mock.ExpectQuery(`FROM users\s+WHERE email = \$1 AND deleted_at IS NULL`).
		WillReturnRows(sqlmock.NewRows(enumUserColumns).AddRow(
			uuid.New(), uuid.New(), "person@example.com", hash, "P", "Q",
			active, true, nil, nil, nil, nil, now, now, nil))
}

func postJSON(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	return postJSONFrom(router, path, body, "")
}

func postJSONFrom(router *gin.Engine, path, body, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func hashFor(t *testing.T, password string) string {
	t.Helper()
	h, err := passwordsvc.NewPasswordService().HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}

func errorOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return body.Error
}

// A registered address in a build with no SSO must look exactly like an
// unregistered one: no tenant UUID in the response.
func TestAuthMethods_NeverEchoesTenantIDWithoutSSO(t *testing.T) {
	router, mock := newEnumerationRouter(t, 0)
	mock.ExpectQuery(`SELECT id, tenant_id FROM users`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id"}).AddRow(uuid.New(), uuid.New()))

	w := postJSON(router, "/api/v1/auth-service/auth/methods", `{"email":"registered@example.com"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TenantID != "" {
		t.Fatalf("tenant_id = %q for a registered email with no SSO method; this is an account-existence oracle that also leaks the tenant UUID", resp.TenantID)
	}
}

// A deactivated account given a WRONG password must not announce itself.
func TestLogin_DeactivatedAccountWrongPassword_LooksLikeUnknownAddress(t *testing.T) {
	router, mock := newEnumerationRouter(t, 0)
	expectTenantUser(mock, hashFor(t, "Right-Passw0rd!"), false)
	mock.ExpectQuery(`SELECT locked_until FROM users WHERE id = \$1`).
		WillReturnRows(sqlmock.NewRows([]string{"locked_until"}).AddRow(nil))

	w := postJSON(router, "/api/v1/auth-service/auth/login",
		`{"email":"person@example.com","password":"Wrong-Passw0rd!"}`)
	if w.Code != http.StatusUnauthorized || errorOf(t, w) != "Invalid email or password" {
		t.Fatalf("deactivated account + wrong password => %d %q; want 401 \"Invalid email or password\" (indistinguishable from an unknown address)", w.Code, errorOf(t, w))
	}
}

// ...but a caller who proved the password may be told why sign-in is refused.
func TestLogin_DeactivatedAccountRightPassword_StillTold(t *testing.T) {
	router, mock := newEnumerationRouter(t, 0)
	expectTenantUser(mock, hashFor(t, "Right-Passw0rd!"), false)
	mock.ExpectQuery(`SELECT locked_until FROM users WHERE id = \$1`).
		WillReturnRows(sqlmock.NewRows([]string{"locked_until"}).AddRow(nil))
	mock.ExpectExec(`UPDATE users SET failed_login_attempts = 0`).WillReturnResult(sqlmock.NewResult(0, 1))

	w := postJSON(router, "/api/v1/auth-service/auth/login",
		`{"email":"person@example.com","password":"Right-Passw0rd!"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("deactivated account + right password => %d; want 403", w.Code)
	}
}

// An account with no password (SSO-only) must answer as a wrong password.
func TestLogin_SSOOnlyAccount_IsInvalidCredentialsNotServerError(t *testing.T) {
	router, mock := newEnumerationRouter(t, 0)
	expectTenantUser(mock, "", true)
	mock.ExpectQuery(`SELECT locked_until FROM users WHERE id = \$1`).
		WillReturnRows(sqlmock.NewRows([]string{"locked_until"}).AddRow(nil))

	w := postJSON(router, "/api/v1/auth-service/auth/login",
		`{"email":"person@example.com","password":"Whatever-Passw0rd!"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("SSO-only account => %d %s; want 401 (a 500 tells the caller the account exists)", w.Code, w.Body.String())
	}
}

// An unknown address must cost a password verification, so response time does
// not separate it from a real account.
func TestLogin_UnknownAddress_SpendsAPasswordVerification(t *testing.T) {
	router, mock := newEnumerationRouter(t, 0)
	mock.ExpectQuery(`FROM users\s+WHERE email = \$1 AND deleted_at IS NULL`).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`FROM platform_users pu`).WillReturnError(sql.ErrNoRows)

	// What one verification costs on this machine, measured the way the handler
	// will pay it (Argon2id at the production parameters).
	svc := passwordsvc.NewPasswordService()
	h, err := svc.HashPassword("calibration-Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	_, _ = svc.VerifyPassword("calibration-Passw0rd!", h)
	oneVerify := time.Since(t0)

	start := time.Now()
	w := postJSON(router, "/api/v1/auth-service/auth/login",
		`{"email":"nobody@example.com","password":"Whatever-Passw0rd!"}`)
	elapsed := time.Since(start)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown address => %d; want 401", w.Code)
	}
	// Generous floor (half of one verification) so a loaded CI box cannot fail
	// the correct code, while the unfixed path (sub-millisecond under sqlmock)
	// is far below it.
	if elapsed < oneVerify/2 {
		t.Fatalf("unknown address answered in %v but one password verification costs %v: the response time distinguishes unknown addresses from real accounts", elapsed, oneVerify)
	}
}

// POST /auth/authenticate must apply the per-email limit /auth/login applies.
func TestAuthenticate_HonoursPerEmailRateLimit(t *testing.T) {
	const loginLimit = 2
	router, mock := newEnumerationRouter(t, loginLimit)

	// initiate resolves the email to list its methods.
	mock.ExpectQuery(`SELECT id, tenant_id FROM users`).WillReturnError(sql.ErrNoRows)
	init := postJSONFrom(router, "/api/v1/auth-service/auth/initiate",
		`{"email":"victim@example.com"}`, "198.51.100.1:5000")
	if init.Code != http.StatusOK {
		t.Fatalf("initiate => %d %s", init.Code, init.Body.String())
	}
	var session struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(init.Body.Bytes(), &session); err != nil || session.SessionID == "" {
		t.Fatalf("no session_id in %s (%v)", init.Body.String(), err)
	}

	body := `{"session_id":"` + session.SessionID + `","method":"password","credentials":{"password":"Guess-Passw0rd!"}}`
	for i := 1; i <= loginLimit; i++ {
		mock.ExpectQuery(`FROM users\s+WHERE email = \$1 AND deleted_at IS NULL`).WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery(`FROM platform_users pu`).WillReturnError(sql.ErrNoRows)
	}
	// A different source address each time, so only the PER-ACCOUNT limit (not the
	// IP-keyed middleware limit) can be what stops the last attempt.
	for i := 1; i <= loginLimit; i++ {
		w := postJSONFrom(router, "/api/v1/auth-service/auth/authenticate", body,
			fmt.Sprintf("203.0.113.%d:6000", i))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d => %d %s; want 401 (within the limit)", i, w.Code, w.Body.String())
		}
	}
	w := postJSONFrom(router, "/api/v1/auth-service/auth/authenticate", body, "203.0.113.200:6000")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d against one account from a fresh address => %d %s; want 429 from the per-account limiter", loginLimit+1, w.Code, w.Body.String())
	}
}

// The password-reset routes must be classified as login-class endpoints by the
// REAL router: strict per-IP limit, and fail-closed when the limiter errors.
func TestPasswordResetRoutes_GetTheLoginClassIPLimit(t *testing.T) {
	const loginLimit = 2
	router, _ := newEnumerationRouter(t, loginLimit)
	for _, path := range []string{
		"/api/v1/auth-service/auth/reset-password",
		"/api/v1/auth-service/auth/forgot-password",
	} {
		// Same source address; an unparseable body makes the handler answer 400,
		// so only the IP-keyed middleware can produce a 429.
		for i := 1; i <= loginLimit; i++ {
			w := postJSONFrom(router, path, `{`, "203.0.113.50:7000")
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s attempt %d => %d; want 400 (within the limit)", path, i, w.Code)
			}
		}
		w := postJSONFrom(router, path, `{`, "203.0.113.50:7000")
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("%s attempt %d from one address => %d; want 429 (the route was classified with the default 100/min limit)", path, loginLimit+1, w.Code)
		}
	}
}
