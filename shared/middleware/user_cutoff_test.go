package middleware

// The per-user issued-before cutoff (deactivate / delete / reset / revoke): a
// token minted before the cutoff is refused by the shared JWT middleware every
// service mounts, a token minted after it is honoured. Needs a real Redis
// (TEST_REDIS_ADDR[/TEST_REDIS_PASSWORD]); skips without one.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

func cutoffRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("TEST_REDIS_PASSWORD")})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		_ = rdb.Close()
		t.Skipf("redis unreachable: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func tokenIssuedAt(t *testing.T, userID uuid.UUID, iat time.Time) string {
	t.Helper()
	claims := &models.JWTClaims{
		UserID: userID, TenantID: uuid.New(), Email: "u@example.com", Role: "viewer", Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestRequireJWTAuth_UserCutoff(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rdb := cutoffRedis(t)
	ctx := context.Background()
	userID := uuid.New()
	t.Cleanup(func() { rdb.Del(ctx, RevokedUserCutoffKey(userID)) })

	r := gin.New()
	r.Use(RequireJWTAuth(AuthConfig{
		TenantState: liveTenantState(), JWTSecret: testJWTSecret,
		RevocationChecker: NewRedisRevocationChecker(rdb),
	}))
	r.GET("/p", func(c *gin.Context) { c.Status(http.StatusOK) })
	call := func(tok string) int {
		req := httptest.NewRequest(http.MethodGet, "/p", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	old := tokenIssuedAt(t, userID, time.Now().Add(-10*time.Minute))
	if got := call(old); got != http.StatusOK {
		t.Fatalf("no cutoff: got %d, want 200", got)
	}

	if err := RevokeUserTokensIssuedBefore(ctx, rdb, userID, time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := call(old); got != http.StatusUnauthorized {
		t.Fatalf("token minted before the cutoff: got %d, want 401", got)
	}
	if got := call(tokenIssuedAt(t, userID, time.Now().Add(2*time.Second))); got != http.StatusOK {
		t.Fatalf("token minted after the cutoff: got %d, want 200", got)
	}
	// Another user is unaffected.
	if got := call(tokenIssuedAt(t, uuid.New(), time.Now().Add(-10*time.Minute))); got != http.StatusOK {
		t.Fatalf("other user's old token: got %d, want 200", got)
	}
	// A token with no iat cannot prove it post-dates the cutoff.
	noIAT := &models.JWTClaims{UserID: userID, TenantID: uuid.New(), Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{ID: uuid.NewString(), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	signed, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, noIAT).SignedString([]byte(testJWTSecret))
	if got := call(signed); got != http.StatusUnauthorized {
		t.Fatalf("token without iat: got %d, want 401", got)
	}
}

func TestRevokeUserTokensIssuedBefore_ExpiresWithTTL(t *testing.T) {
	rdb := cutoffRedis(t)
	ctx := context.Background()
	userID := uuid.New()
	if err := RevokeUserTokensIssuedBefore(ctx, rdb, userID, time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rdb.Del(ctx, RevokedUserCutoffKey(userID)) })
	ttl := rdb.TTL(ctx, RevokedUserCutoffKey(userID)).Val()
	if ttl <= 0 || ttl > time.Minute {
		t.Fatalf("cutoff TTL = %v, want within (0, 1m]", ttl)
	}
}
