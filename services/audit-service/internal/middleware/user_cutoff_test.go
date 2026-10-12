package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// cutoffOnlyChecker models the Redis per-user issued-before cutoff.
type cutoffOnlyChecker struct{ cutoffs map[uuid.UUID]time.Time }

func (cutoffOnlyChecker) IsRevoked(context.Context, string) bool { return false }
func (c cutoffOnlyChecker) IsIssuedBeforeUserCutoff(_ context.Context, u uuid.UUID, iat time.Time) bool {
	cut, ok := c.cutoffs[u]
	return ok && iat.Before(cut)
}

// A deactivated/deleted/reset user's access token minted before the cutoff is
// refused by audit-service's own JWT middleware; one minted after is accepted.
func TestRequireAuth_UserCutoffRejectsOlderTokens(t *testing.T) {
	useLiveTenantState(t)
	gin.SetMode(gin.TestMode)
	secret := "test-secret-for-jwt-issuance-only-do-not-use"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}
	userID := uuid.New()
	cutoff := time.Now().Add(-time.Minute).Truncate(time.Second)

	previous := revocationCheckerFromEnv
	revocationCheckerFromEnv = func() sharedmw.RevocationChecker {
		return cutoffOnlyChecker{cutoffs: map[uuid.UUID]time.Time{userID: cutoff}}
	}
	t.Cleanup(func() { revocationCheckerFromEnv = previous })

	mint := func(iat time.Time) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": userID.String(), "email": "a@test.com", "role": "super_admin", "type": "access",
			"iss": "crypto-inventory-auth", "aud": "crypto-inventory", "sub": userID.String(),
			"jti": uuid.NewString(), "iat": iat.Unix(),
			"nbf": iat.Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		s, err := tok.SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	r := gin.New()
	r.GET("/x", RequireAuth(cfg), func(c *gin.Context) { c.Status(http.StatusOK) })
	for name, tc := range map[string]struct {
		iat  time.Time
		want int
	}{
		"minted before cutoff": {cutoff.Add(-time.Hour), http.StatusUnauthorized},
		"minted after cutoff":  {cutoff.Add(time.Second), http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+mint(tc.iat))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", name, w.Code, tc.want, w.Body.String())
		}
	}
}
