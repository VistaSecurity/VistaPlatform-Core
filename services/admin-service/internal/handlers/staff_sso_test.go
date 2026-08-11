package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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

// CreatePlatformIdentityProvider rejects an invalid purpose before any DB use.
func TestCreatePlatformIdentityProvider_invalidPurpose_400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
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
