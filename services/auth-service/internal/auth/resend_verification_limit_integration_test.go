package auth

// AllowResendVerification is a fixed-window per-address cap. Needs Redis
// (TEST_REDIS_ADDR); skips without it.

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestIntegration_AllowResendVerification_CapsPerAddress(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("TEST_REDIS_PASSWORD")})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis unreachable: %v", err)
	}
	svc := &AuthService{redis: rdb}
	ctx := context.Background()
	email := "rv-" + uuid.NewString()[:8] + "@example.test"

	for i := 1; i <= resendVerificationLimit; i++ {
		if !svc.AllowResendVerification(ctx, email) {
			t.Fatalf("request %d denied, want allowed", i)
		}
	}
	if svc.AllowResendVerification(ctx, "  "+email+" ") {
		t.Fatal("request over the cap allowed (case/space-insensitive key expected)")
	}
	if !svc.AllowResendVerification(ctx, "other-"+email) {
		t.Fatal("a different address was throttled")
	}
}
