package api

//: logout / change-password must denylist the live ACCESS token (by jti,
// TTL = remaining lifetime), not just refresh tokens, so the session is killed
// across all services immediately (the denylist is enforced data-plane since
//). These tests drive the real Logout handler with the shared stub, which
// records RevokeJTI calls.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

func signTokenWithJTI(t *testing.T, jti string, exp time.Time) string {
	t.Helper()
	claims := jwt.RegisteredClaims{ID: jti, ExpiresAt: jwt.NewNumericDate(exp)}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("test-secret-for-logout"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newLogoutEngine(stub *stubAuthServiceStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New().String())
		c.Next()
	})
	h := &AuthHandlers{authService: stub, config: &config.Config{}}
	grp.POST("/auth/logout", h.Logout)
	return r
}

func TestLogout_RevokesAccessTokenJTI(t *testing.T) {
	stub := &stubAuthServiceStore{}
	eng := newLogoutEngine(stub)

	jti := "access-jti-789"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+signTokenWithJTI(t, jti, time.Now().Add(time.Hour)))
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	found := false
	for _, j := range stub.revokedJTIs {
		if j == jti {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected access jti %q on the revocation denylist, got %v", jti, stub.revokedJTIs)
	}
}

// An already-expired access token has no remaining lifetime, so there is
// nothing to deny — the handler must not record a (zero/negative-TTL) entry.
func TestLogout_SkipsExpiredAccessToken(t *testing.T) {
	stub := &stubAuthServiceStore{}
	eng := newLogoutEngine(stub)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+signTokenWithJTI(t, "expired-jti", time.Now().Add(-time.Minute)))
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(stub.revokedJTIs) != 0 {
		t.Fatalf("expired token must not be denylisted, got %v", stub.revokedJTIs)
	}
}

// No access token on the request (e.g. only a refresh cookie) → logout still
// succeeds and simply skips the access-token denylist.
func TestLogout_NoAccessTokenIsNoop(t *testing.T) {
	stub := &stubAuthServiceStore{}
	eng := newLogoutEngine(stub)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/logout", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(stub.revokedJTIs) != 0 {
		t.Fatalf("no token should mean no denylist entry, got %v", stub.revokedJTIs)
	}
}
