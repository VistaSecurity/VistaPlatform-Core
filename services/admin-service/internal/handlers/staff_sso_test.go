package handlers

import (
	"database/sql/driver"
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
)

func TestAdminCallbackRedirectURI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
	c.Request.Host = "admin.demo.example.com"
	c.Request.Header.Set("X-Forwarded-Proto", "https")

	got := adminCallbackRedirectURI(c, "google")
	want := "https://admin.demo.example.com/api/v1/admin-service/admin/sso/google/callback"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Without HTTPS forwarding it falls back to http (dev).
	c.Request.Header.Del("X-Forwarded-Proto")
	if got := adminCallbackRedirectURI(c, "microsoft"); !strings.HasPrefix(got, "http://") {
		t.Fatalf("expected http:// fallback, got %q", got)
	}
}

func TestStaffStateToken(t *testing.T) {
	a, b := staffStateToken(), staffStateToken()
	if a == "" || a == b {
		t.Fatal("expected non-empty, unique state tokens")
	}
	if strings.ContainsAny(a, "+/=") {
		t.Fatalf("state token must be URL-safe: %q", a)
	}
}

type expiryWithin struct {
	start time.Time
	ttl   time.Duration
}

func (m expiryWithin) Match(v driver.Value) bool {
	expiry, ok := v.(time.Time)
	if !ok {
		return false
	}
	min := m.start.Add(m.ttl - time.Minute)
	max := m.start.Add(m.ttl + time.Minute)
	return !expiry.Before(min) && !expiry.After(max)
}

func TestStaffSsoCallback_UsesConfiguredSessionTTLForRefreshSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	InitializeCookieDomain("")
	previousSecureCookies := enforceSecureCookies
	enforceSecureCookies = false
	previousSigner := platformSigner
	platformSigner = nil
	t.Cleanup(func() {
		enforceSecureCookies = previousSecureCookies
		platformSigner = previousSigner
	})

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "authorization_code" {
				t.Fatalf("grant_type = %q, want authorization_code", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"idp-access-token"}`))
		case "/userinfo":
			if got := r.Header.Get("Authorization"); got != "Bearer idp-access-token" {
				t.Fatalf("Authorization = %q, want Bearer idp-access-token", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"email":"Admin@Example.COM","email_verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const jwtSecret = "staff-sso-session-ttl-test-secret"
	const configuredSessionMinutes = 14 * 24 * 60
	configuredTTL := time.Duration(configuredSessionMinutes) * time.Minute
	userID := uuid.New()
	start := time.Now()

	providerAuthor := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, client_id, client_secret_encrypted, token_url, userinfo_url, updated_by FROM platform_sso_providers")).
		WithArgs("google").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "client_id", "client_secret_encrypted", "token_url", "userinfo_url", "updated_by",
		}).AddRow(uuid.NewString(), "client-id", "client-secret", idp.URL+"/token", idp.URL+"/userinfo", providerAuthor.String()))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pu.id, pr.id, pr.name, pu.force_password_change FROM platform_users pu")).
		WithArgs("admin@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "role_id", "name", "force_password_change"}).
			AddRow(userID, uuid.New(), "super_admin", false))
	// The provider's last writer is an active super administrator, so the
	// super-admin gate lets this sign-in through.
	mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS (")).
		WithArgs(providerAuthor, "super_admin").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT setting_value FROM platform_settings WHERE setting_key = $1")).
		WithArgs("session_timeout_minutes").
		WillReturnRows(sqlmock.NewRows([]string{"setting_value"}).AddRow([]byte("20160")))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO platform_refresh_tokens")).
		WithArgs(userID, sqlmock.AnyArg(), sqlmock.AnyArg(), expiryWithin{start: start, ttl: configuredTTL}, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE platform_users SET last_login_at = now() WHERE id = $1")).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	r := gin.New()
	r.GET("/admin/sso/:provider/callback", StaffSsoCallback(db, jwtSecret, adminauth.NewPlatformRefreshTokenService(db)))

	req := httptest.NewRequest(http.MethodGet, "/admin/sso/google/callback?state=sso-state&code=auth-code", nil)
	req.Host = "admin.example.com"
	req.AddCookie(&http.Cookie{Name: "admin_sso_state", Value: "sso-state"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Fatalf("redirect Location = %q, want /", got)
	}

	cookies := map[string]*http.Cookie{}
	for _, ck := range w.Result().Cookies() {
		cookies[ck.Name] = ck
	}
	refreshCookie := cookies["platform_refresh_token"]
	if refreshCookie == nil || refreshCookie.Value == "" {
		t.Fatal("missing platform_refresh_token cookie")
	}
	if refreshCookie.MaxAge != int(configuredTTL.Seconds()) {
		t.Fatalf("platform_refresh_token MaxAge = %d, want %d", refreshCookie.MaxAge, int(configuredTTL.Seconds()))
	}
	if csrfCookie := cookies["platform_csrf_token"]; csrfCookie == nil || csrfCookie.MaxAge != int(configuredTTL.Seconds()) {
		t.Fatalf("platform_csrf_token MaxAge = %v, want %d", csrfCookie, int(configuredTTL.Seconds()))
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(refreshCookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	}, jwt.WithAudience("crypto-inventory"), jwt.WithIssuer("crypto-inventory-auth"))
	if err != nil || !token.Valid {
		t.Fatalf("refresh token did not validate: token valid=%v err=%v", token != nil && token.Valid, err)
	}
	if typ, _ := claims["type"].(string); typ != "refresh" {
		t.Fatalf("refresh token type = %q, want refresh", typ)
	}
	expUnix, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("refresh token missing exp: %v", err)
	}
	remaining := time.Until(expUnix.Time)
	if remaining < configuredTTL-time.Minute || remaining > configuredTTL+time.Minute {
		t.Fatalf("refresh token TTL = %v, want approximately %v", remaining, configuredTTL)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

// CreatePlatformIdentityProvider rejects an invalid purpose before any DB use.
func TestCreatePlatformIdentityProvider_invalidPurpose_400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", uuid.NewString()); c.Next() })
	r.POST("/p", CreatePlatformIdentityProvider(nil))

	w := httptest.NewRecorder()
	body := `{"provider_type":"google","purpose":"bogus","client_id":"x","client_secret":"y","auth_url":"a","token_url":"t"}`
	req := httptest.NewRequest(http.MethodPost, "/p", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid purpose, got %d", w.Code)
	}
}

// Every provider write records its author, so a write with no authenticated
// caller is refused before the DB is touched.
func TestPlatformIdentityProviderWrites_401WithoutCaller(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/p", CreatePlatformIdentityProvider(nil))
	r.PUT("/p/:id", UpdatePlatformIdentityProvider(nil))
	r.DELETE("/p/:id", DeletePlatformIdentityProvider(nil))
	body := `{"provider_type":"google","purpose":"admin_login","client_id":"x","client_secret":"y","auth_url":"a","token_url":"t"}`
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/p"},
		{http.MethodPut, "/p/" + uuid.NewString()},
		{http.MethodDelete, "/p/" + uuid.NewString()},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: status = %d, want 401", tc.method, tc.path, w.Code)
		}
	}
}

// staffCallbackHarness drives StaffSsoCallback against a fake IdP whose
// userinfo endpoint returns userinfoJSON. It returns the redirect Location.
func staffCallbackHarness(t *testing.T, userinfoJSON string, expect func(mock sqlmock.Sqlmock, tokenURL, userinfoURL string)) (string, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = w.Write([]byte(`{"access_token":"idp-access-token"}`))
		case "/userinfo":
			_, _ = w.Write([]byte(userinfoJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	expect(mock, idp.URL+"/token", idp.URL+"/userinfo")

	r := gin.New()
	r.GET("/admin/sso/:provider/callback", StaffSsoCallback(db, "staff-sso-gate-test-secret", adminauth.NewPlatformRefreshTokenService(db)))
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/google/callback?state=s&code=c", nil)
	req.AddCookie(&http.Cookie{Name: "admin_sso_state", Value: "s"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", w.Code)
	}
	return w.Header().Get("Location"), mock
}

func expectStaffProviderRow(mock sqlmock.Sqlmock, tokenURL, userinfoURL string, updatedBy interface{}) {
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, client_id, client_secret_encrypted, token_url, userinfo_url, updated_by FROM platform_sso_providers")).
		WithArgs("google").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "client_id", "client_secret_encrypted", "token_url", "userinfo_url", "updated_by",
		}).AddRow(uuid.NewString(), "client-id", "client-secret", tokenURL, userinfoURL, updatedBy))
}

// Gate 1: without an explicit email_verified=true the callback refuses before
// it looks up any platform user — for every shape an IdP could send.
func TestStaffSsoCallback_RefusesUnverifiedEmail(t *testing.T) {
	for name, ui := range map[string]string{
		"missing":      `{"email":"admin@example.com"}`,
		"false":        `{"email":"admin@example.com","email_verified":false}`,
		"string false": `{"email":"admin@example.com","email_verified":"false"}`,
		"number 1":     `{"email":"admin@example.com","email_verified":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			loc, mock := staffCallbackHarness(t, ui, func(mock sqlmock.Sqlmock, tokenURL, userinfoURL string) {
				expectStaffProviderRow(mock, tokenURL, userinfoURL, uuid.NewString())
			})
			if loc != "/login?error=sso_email_unverified" {
				t.Fatalf("Location = %q, want /login?error=sso_email_unverified", loc)
			}
			// No platform_users lookup was attempted (sqlmock fails an
			// unexpected query, and every expectation was consumed).
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Gate 2: a super administrator is refused when the provider's last writer is
// not (or no longer) an active super administrator, or is unknown.
func TestStaffSsoCallback_SuperAdminNeedsSuperAdminAuthoredProvider(t *testing.T) {
	userID := uuid.New()
	author := uuid.New()
	t.Run("author not a super admin", func(t *testing.T) {
		loc, mock := staffCallbackHarness(t, `{"email":"root@example.com","email_verified":true}`, func(mock sqlmock.Sqlmock, tokenURL, userinfoURL string) {
			expectStaffProviderRow(mock, tokenURL, userinfoURL, author.String())
			mock.ExpectQuery(regexp.QuoteMeta("SELECT pu.id, pr.id, pr.name, pu.force_password_change FROM platform_users pu")).
				WithArgs("root@example.com").
				WillReturnRows(sqlmock.NewRows([]string{"id", "role_id", "name", "force_password_change"}).AddRow(userID, uuid.New(), "super_admin", false))
			mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS (")).
				WithArgs(author, "super_admin").
				WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		})
		if loc != "/login?error=sso_super_admin_untrusted_provider" {
			t.Fatalf("Location = %q, want /login?error=sso_super_admin_untrusted_provider", loc)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no recorded author", func(t *testing.T) {
		loc, mock := staffCallbackHarness(t, `{"email":"root@example.com","email_verified":true}`, func(mock sqlmock.Sqlmock, tokenURL, userinfoURL string) {
			expectStaffProviderRow(mock, tokenURL, userinfoURL, nil)
			mock.ExpectQuery(regexp.QuoteMeta("SELECT pu.id, pr.id, pr.name, pu.force_password_change FROM platform_users pu")).
				WithArgs("root@example.com").
				WillReturnRows(sqlmock.NewRows([]string{"id", "role_id", "name", "force_password_change"}).AddRow(userID, uuid.New(), "super_admin", false))
		})
		if loc != "/login?error=sso_super_admin_untrusted_provider" {
			t.Fatalf("Location = %q, want /login?error=sso_super_admin_untrusted_provider", loc)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}
