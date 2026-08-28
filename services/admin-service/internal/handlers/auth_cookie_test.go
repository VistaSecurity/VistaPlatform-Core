package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func platformAccessTokenWithJTI(t *testing.T) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ID:        "platform-csrf-cookie-test-jti",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	s, err := tok.SignedString([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSetPlatformAuthCookies_RefreshAndCSRFCookiesUseSessionLifetime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	InitializeCookieDomain("")
	enforceSecureCookies = false

	fourteenDays := int((14 * 24 * time.Hour).Seconds())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/admin/auth/login", nil)
	setPlatformAuthCookies(c, platformAccessTokenWithJTI(t), 3600, fourteenDays, "refresh-jwt", "test-key")

	got := map[string]int{}
	for _, ck := range (&http.Response{Header: w.Header()}).Cookies() {
		got[ck.Name] = ck.MaxAge
	}

	if got["platform_access_token"] != 3600 {
		t.Errorf("platform_access_token MaxAge = %d, want 3600", got["platform_access_token"])
	}
	if got["platform_refresh_token"] != fourteenDays {
		t.Errorf("platform_refresh_token MaxAge = %d, want %d", got["platform_refresh_token"], fourteenDays)
	}
	if got["platform_csrf_token"] != fourteenDays {
		t.Errorf("platform_csrf_token MaxAge = %d, want %d (the policy session lifetime)", got["platform_csrf_token"], fourteenDays)
	}
}
