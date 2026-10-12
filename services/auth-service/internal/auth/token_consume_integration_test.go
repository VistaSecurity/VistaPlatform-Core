package auth

// Real-Redis proof that consumeTokenHash redeems a token exactly once under
// contention. Skips without TEST_REDIS_ADDR (and optional TEST_REDIS_PASSWORD).

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestConsumeTokenHash_ExactlyOneConcurrentRedeemerWins(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("TEST_REDIS_PASSWORD")})
	t.Cleanup(func() { _ = rdb.Close() })
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis unreachable: %v", err)
	}
	a := &AuthService{redis: rdb}

	for round := 0; round < 20; round++ {
		key := "password_reset:test-" + uuid.NewString()
		if err := rdb.HSet(ctx, key, map[string]interface{}{"user_id": "u", "expiry": "1"}).Err(); err != nil {
			t.Fatal(err)
		}
		const n = 32
		var wg sync.WaitGroup
		start := make(chan struct{})
		wins := make(chan int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				m, err := a.consumeTokenHash(ctx, key)
				if err != nil {
					t.Errorf("consume: %v", err)
					return
				}
				if len(m) > 0 {
					wins <- 1
				}
			}()
		}
		close(start)
		wg.Wait()
		close(wins)
		got := 0
		for range wins {
			got++
		}
		if got != 1 {
			t.Fatalf("round %d: %d redeemers got the token, want exactly 1", round, got)
		}
		if exists, _ := rdb.Exists(ctx, key).Result(); exists != 0 {
			t.Fatal("token survived its redemption")
		}
	}
}
