package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

// accessTokenWithJTI mints a minimal signed access token carrying a jti, so the
// session-bound CSRF cookie can be derived from it.
func accessTokenWithJTI(t *testing.T) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ID:        "csrf-cookie-test-jti",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	s, err := tok.SignedString([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Verifies the server side of the CSRF double-submit contract: the csrf_token
// cookie the frontend reads and echoes back must be JS-readable (not HttpOnly),
// scoped to Path=/, SameSite=Strict, and Secure in production. A regression on
// these attributes would silently weaken CSRF/session protection. See.
func TestSetAuthCookies_CSRFCookieAttributes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &AuthHandlers{
		config: &config.Config{
			CookieSecure: true,
			CookieDomain: "",
			JWTExpiry:    time.Hour,
		},
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.setAuthCookies(c, accessTokenWithJTI(t), "refresh-jwt")

	cookies := (&http.Response{Header: w.Header()}).Cookies()

	var csrf, access *http.Cookie
	for _, ck := range cookies {
		switch ck.Name {
		case "csrf_token":
			csrf = ck
		case "access_token":
			access = ck
		}
	}

	if csrf == nil {
		t.Fatal("csrf_token cookie was not set")
	}
	if csrf.HttpOnly {
		t.Error("csrf_token must NOT be HttpOnly (the frontend has to read it for double-submit)")
	}
	if csrf.Path != "/" {
		t.Errorf("csrf_token Path = %q, want \"/\"", csrf.Path)
	}
	if csrf.SameSite != http.SameSiteStrictMode {
		t.Errorf("csrf_token SameSite = %v, want Strict", csrf.SameSite)
	}
	if !csrf.Secure {
		t.Error("csrf_token must be Secure when CookieSecure is enabled (production)")
	}
	if csrf.Value == "" {
		t.Error("csrf_token must carry a value")
	}

	// Sanity: the access token, by contrast, must be HttpOnly.
	if access == nil {
		t.Fatal("access_token cookie was not set")
	}
	if !access.HttpOnly {
		t.Error("access_token must be HttpOnly")
	}
}

// The JS-readable csrf_token cookie is the frontend's "a session exists" signal:
// on a 401 it only attempts a silent refresh when this cookie is present. Tying
// its MaxAge to the short access-token expiry made the signal vanish exactly
// when the refresh was due — every request 401'd, no refresh was attempted, no
// session-expired redirect fired, and the user was left on "Couldn't load …"
// cards. It must outlive the access token and match the refresh token.
func TestSetAuthCookies_CSRFCookieOutlivesAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &AuthHandlers{
		config: &config.Config{JWTExpiry: 15 * time.Minute},
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.setAuthCookies(c, accessTokenWithJTI(t), "refresh-jwt")

	got := map[string]int{}
	for _, ck := range (&http.Response{Header: w.Header()}).Cookies() {
		got[ck.Name] = ck.MaxAge
	}

	if got["access_token"] != int((15 * time.Minute).Seconds()) {
		t.Errorf("access_token MaxAge = %d, want %d", got["access_token"], int((15 * time.Minute).Seconds()))
	}
	if got["refresh_token"] != refreshCookieMaxAge {
		t.Errorf("refresh_token MaxAge = %d, want %d", got["refresh_token"], refreshCookieMaxAge)
	}
	if got["csrf_token"] != refreshCookieMaxAge {
		t.Errorf("csrf_token MaxAge = %d, want %d (the refresh-token lifetime, NOT the access-token expiry)",
			got["csrf_token"], refreshCookieMaxAge)
	}
}

// Same invariant on the SSO path, which sets the cookies through a standalone
// helper rather than the AuthHandlers method.
func TestSetAuthCookiesResponseWriter_CSRFCookieOutlivesAccessToken(t *testing.T) {
	w := httptest.NewRecorder()
	setAuthCookiesResponseWriter(w, &config.Config{}, 900, accessTokenWithJTI(t), "refresh-jwt")

	got := map[string]int{}
	for _, ck := range (&http.Response{Header: w.Header()}).Cookies() {
		got[ck.Name] = ck.MaxAge
	}

	if got["access_token"] != 900 {
		t.Errorf("access_token MaxAge = %d, want 900", got["access_token"])
	}
	if got["csrf_token"] != refreshCookieMaxAge {
		t.Errorf("csrf_token MaxAge = %d, want %d (the refresh-token lifetime)", got["csrf_token"], refreshCookieMaxAge)
	}
}
