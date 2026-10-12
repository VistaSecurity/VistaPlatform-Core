package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// cutoffOnlyChecker models the Redis per-user issued-before cutoff.
type cutoffOnlyChecker struct{ cutoffs map[uuid.UUID]time.Time }

func (cutoffOnlyChecker) IsRevoked(context.Context, string) bool { return false }
func (c cutoffOnlyChecker) IsIssuedBeforeUserCutoff(_ context.Context, u uuid.UUID, iat time.Time) bool {
	cut, ok := c.cutoffs[u]
	return ok && iat.Before(cut)
}

// inventory-service has its own JWT middleware; it must honour the per-user
// issued-before cutoff exactly as the shared one does.
func TestJWTMiddleware_UserCutoffRejectsOlderTokens(t *testing.T) {
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
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &JWTClaims{
			UserID: userID, TenantID: uuid.Nil, Email: "a@test.com", Role: "super_admin", Type: "access",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: userID.String(), IssuedAt: jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				NotBefore: jwt.NewNumericDate(iat.Add(-time.Minute)),
				Issuer:    "crypto-inventory-auth", Audience: jwt.ClaimStrings{"crypto-inventory"},
				ID: uuid.NewString(),
			},
		})
		s, err := tok.SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	r := gin.New()
	r.GET("/algorithms", JWTMiddleware(cfg, nil), func(c *gin.Context) { c.Status(http.StatusOK) })
	for name, tc := range map[string]struct {
		iat  time.Time
		want int
	}{
		"minted before cutoff": {cutoff.Add(-time.Hour), http.StatusUnauthorized},
		"minted after cutoff":  {cutoff.Add(time.Second), http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, "/algorithms", nil)
		req.Header.Set("Authorization", "Bearer "+mint(tc.iat))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", name, w.Code, tc.want, w.Body.String())
		}
	}
}
