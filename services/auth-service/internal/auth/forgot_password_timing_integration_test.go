package auth

// ForgotPassword must not tell a caller whether an address has an account: the
// outbound mail runs off the request path and the response takes a fixed minimum
// time either way. Needs a real Postgres (TEST_DATABASE_URL) and Redis
// (TEST_REDIS_ADDR); skips without either.

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ForgotPassword_SendIsAsyncAndTimeIsFloored(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("TEST_REDIS_PASSWORD")})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis unreachable: %v", err)
	}
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := testdb.NewTenant(t, db)
	email := "fp-" + uuid.NewString()[:8] + "@example.test"
	if _, err := db.Exec(`
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active, email_verified)
		VALUES ($1, $2, $3, 'x', 'Fo', 'Rgot', true, true)`, uuid.New(), tenantID, email); err != nil {
		t.Fatal(err)
	}

	svc := &AuthService{db: db, bypassDB: db, redis: rdb}

	oldFloor, oldAsync := forgotPasswordMinDuration, runAsync
	t.Cleanup(func() { forgotPasswordMinDuration, runAsync = oldFloor, oldAsync })
	const floor = 200 * time.Millisecond
	forgotPasswordMinDuration = floor
	var mu sync.Mutex
	var deferred []func()
	runAsync = func(f func()) { mu.Lock(); deferred = append(deferred, f); mu.Unlock() }

	timed := func(addr string) time.Duration {
		start := time.Now()
		if err := svc.ForgotPassword(&models.ForgotPasswordRequest{Email: addr}); err != nil {
			t.Fatalf("ForgotPassword(%s): %v", addr, err)
		}
		return time.Since(start)
	}

	known := timed(email)
	unknown := timed("nobody-" + uuid.NewString()[:8] + "@example.test")

	if known < floor || unknown < floor {
		t.Fatalf("response times known=%v unknown=%v; both must be at least the %v floor, or timing reveals the account", known, unknown, floor)
	}
	mu.Lock()
	n := len(deferred)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("%d mail sends were handed to runAsync, want exactly 1 (the real account); the send must not run inline", n)
	}
}
