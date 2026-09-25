package middleware

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// fakeRedis is an in-process Redis test double with a controllable clock. It
// is installed as a go-redis Hook, so the real client builds every command
// (including the MULTI/EXEC wrapping of a TxPipeline) and the fake answers it
// without touching the network. It implements only the commands the rate
// limiter might issue and fails any other command loudly, so a limiter
// change that starts using something new cannot pass by accident.
type fakeRedis struct {
	mu       sync.Mutex
	start    time.Time
	now      time.Time
	keys     map[string]*fakeEntry
	failWith error
}

type fakeEntry struct {
	val      int64
	expireAt time.Time // zero = no expiry
}

func newFakeRedis(t *testing.T) (*fakeRedis, *redis.Client) {
	t.Helper()
	start := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	f := &fakeRedis{start: start, now: start, keys: map[string]*fakeEntry{}}
	client := redis.NewClient(&redis.Options{Addr: "fake-redis.invalid:6379"})
	client.AddHook(f)
	t.Cleanup(func() { _ = client.Close() })
	return f, client
}

func (f *fakeRedis) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// setElapsed moves the clock to start+d.
func (f *fakeRedis) setElapsed(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.start.Add(d)
}

func (f *fakeRedis) elapsed() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now.Sub(f.start)
}

// pttl reports the key's remaining lifetime the way Redis PTTL does:
// -2 if absent, -1 if it has no expiry.
func (f *fakeRedis) pttl(key string) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.lookup(key)
	switch {
	case e == nil:
		return -2
	case e.expireAt.IsZero():
		return -1
	default:
		return e.expireAt.Sub(f.now)
	}
}

func (f *fakeRedis) value(key string) (int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.lookup(key)
	if e == nil {
		return 0, false
	}
	return e.val, true
}

// lookup returns the live entry for key, expiring it first if due. Caller
// holds f.mu.
func (f *fakeRedis) lookup(key string) *fakeEntry {
	e, ok := f.keys[key]
	if !ok {
		return nil
	}
	if !e.expireAt.IsZero() && !f.now.Before(e.expireAt) {
		delete(f.keys, key)
		return nil
	}
	return e
}

func (f *fakeRedis) DialHook(redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fakeRedis: the test double never dials")
	}
}

func (f *fakeRedis) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.apply(cmd)
		return cmd.Err()
	}
}

func (f *fakeRedis) ProcessPipelineHook(redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	// One lock across the whole batch: a TxPipeline arrives here as
	// MULTI ... EXEC, and holding the lock gives it Redis's atomicity.
	return func(_ context.Context, cmds []redis.Cmder) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		var first error
		for _, cmd := range cmds {
			f.apply(cmd)
			if err := cmd.Err(); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
}

// apply executes one command against the store. Caller holds f.mu.
func (f *fakeRedis) apply(cmd redis.Cmder) {
	if f.failWith != nil {
		cmd.SetErr(f.failWith)
		return
	}
	args := cmd.Args()
	str := func(i int) string { return fmt.Sprint(args[i]) }
	num := func(i int) int64 {
		n, err := strconv.ParseInt(str(i), 10, 64)
		if err != nil {
			panic(fmt.Sprintf("fakeRedis: %v: arg %d not an integer", args, i))
		}
		return n
	}

	switch name := strings.ToLower(cmd.Name()); name {
	case "multi":
		cmd.(*redis.StatusCmd).SetVal("OK")
	case "exec":
		cmd.(*redis.SliceCmd).SetVal(nil)

	case "set": // SET key value [NX] [EX s | PX ms]
		key := str(1)
		var nx bool
		var ttl time.Duration
		for i := 3; i < len(args); i++ {
			switch strings.ToLower(str(i)) {
			case "nx":
				nx = true
			case "ex":
				i++
				ttl = time.Duration(num(i)) * time.Second
			case "px":
				i++
				ttl = time.Duration(num(i)) * time.Millisecond
			default:
				cmd.SetErr(fmt.Errorf("fakeRedis: unsupported SET option %q", str(i)))
				return
			}
		}
		written := !nx || f.lookup(key) == nil
		if written {
			v, err := strconv.ParseInt(str(2), 10, 64)
			if err != nil {
				cmd.SetErr(fmt.Errorf("fakeRedis: SET value %q is not an integer", str(2)))
				return
			}
			e := &fakeEntry{val: v}
			if ttl > 0 {
				e.expireAt = f.now.Add(ttl)
			}
			f.keys[key] = e
		}
		switch c := cmd.(type) {
		case *redis.BoolCmd:
			c.SetVal(written)
		case *redis.StatusCmd:
			if written {
				c.SetVal("OK")
			} else {
				c.SetErr(redis.Nil)
			}
		}

	case "incr": // INCR preserves an existing TTL, exactly as Redis does.
		e := f.lookup(str(1))
		if e == nil {
			e = &fakeEntry{}
			f.keys[str(1)] = e
		}
		e.val++
		cmd.(*redis.IntCmd).SetVal(e.val)

	case "expire", "pexpire":
		unit := time.Second
		if name == "pexpire" {
			unit = time.Millisecond
		}
		e := f.lookup(str(1))
		if e != nil {
			e.expireAt = f.now.Add(time.Duration(num(2)) * unit)
		}
		cmd.(*redis.BoolCmd).SetVal(e != nil)

	case "ttl", "pttl":
		e := f.lookup(str(1))
		var d time.Duration
		switch {
		case e == nil:
			d = -2 // go-redis passes -1/-2 through unscaled
		case e.expireAt.IsZero():
			d = -1
		case name == "ttl": // Redis rounds TTL to the nearest second
			d = (e.expireAt.Sub(f.now) + 500*time.Millisecond).Truncate(time.Second)
		default:
			d = e.expireAt.Sub(f.now).Truncate(time.Millisecond)
		}
		cmd.(*redis.DurationCmd).SetVal(d)

	default:
		cmd.SetErr(fmt.Errorf("fakeRedis: unsupported command %q", name))
	}
}

func ceilSeconds(d time.Duration) time.Duration {
	return (d + time.Second - 1).Truncate(time.Second)
}

// TestRateLimiter_OverLimitRetriesDoNotExtendWindow pins the fixed window.
// The limiter used to run INCR + EXPIRE on every request, so each attempt
// pushed the key's expiry back a full window: a client that kept retrying
// under a 429 was locked out for as long as it kept retrying, and the
// retry_after it was given (the key's TTL) was never true. Seen on a k3s
// rehearsal as 67 login attempts from one svclb address keeping
// rate_limit:anon:10.42.0.1:/api/v1/auth-service/auth/login alive.
func TestRateLimiter_OverLimitRetriesDoNotExtendWindow(t *testing.T) {
	const (
		window     = time.Minute
		loginLimit = 5
		attempts   = 67
		spacing    = 850 * time.Millisecond // 67 attempts land inside one window
	)
	ctx := context.Background()

	cases := []struct {
		name string
		key  string
		hit  func(*RateLimiter) (bool, time.Duration, error)
	}{
		{
			name: "ip-keyed login (middleware)",
			key:  "rate_limit:anon:10.42.0.1:/api/v1/auth-service/auth/login",
			hit: func(l *RateLimiter) (bool, time.Duration, error) {
				return l.Allow(ctx, "anon:10.42.0.1", "/api/v1/auth-service/auth/login")
			},
		},
		{
			name: "per-email (login handler)",
			key:  "rate_limit:email:victim@example.com",
			hit: func(l *RateLimiter) (bool, time.Duration, error) {
				return l.AllowByEmail(ctx, "  Victim@Example.com ")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake, client := newFakeRedis(t)
			limiter := NewRateLimiter(client, 100, window, loginLimit)

			// Use up the window's allowance at t=0.
			for i := 1; i <= loginLimit; i++ {
				allowed, _, err := tc.hit(limiter)
				if err != nil || !allowed {
					t.Fatalf("attempt %d within the limit: allowed=%v err=%v", i, allowed, err)
				}
			}
			if got := fake.pttl(tc.key); got != window {
				t.Fatalf("new key TTL = %v, want exactly the window %v", got, window)
			}

			// Keep hammering while blocked. The key must never outlive the
			// window that opened at t=0, and retry_after must say so.
			for i := 1; i <= attempts; i++ {
				fake.advance(spacing)
				allowed, retryAfter, err := tc.hit(limiter)
				if err != nil {
					t.Fatalf("over-limit attempt %d: unexpected error %v", i, err)
				}
				if allowed {
					t.Fatalf("over-limit attempt %d at +%v was allowed", i, fake.elapsed())
				}
				left := window - fake.elapsed()
				if ttl := fake.pttl(tc.key); ttl <= 0 || ttl > left {
					t.Fatalf("over-limit attempt %d at +%v: key TTL = %v, but only %v is left of the original window — retries are extending it",
						i, fake.elapsed(), ttl, left)
				}
				if want := ceilSeconds(left); retryAfter != want {
					t.Fatalf("over-limit attempt %d at +%v: retry_after = %v, want %v (time left in the original window, rounded up)",
						i, fake.elapsed(), retryAfter, want)
				}
			}

			// The original window ends on schedule despite the 67 retries.
			fake.setElapsed(window)
			allowed, _, err := tc.hit(limiter)
			if err != nil || !allowed {
				t.Fatalf("first attempt after the original window ended: allowed=%v err=%v, want allowed", allowed, err)
			}
			if got := fake.pttl(tc.key); got != window {
				t.Fatalf("next window's key TTL = %v, want a fresh %v", got, window)
			}
		})
	}
}

// TestRateLimiter_ConcurrentHitsShareOneFixedWindow verifies that concurrent
// first requests cannot create independent counters or lose increments. The
// current policy counts rejected requests too; that decision is pinned here so
// the counter and the number of allowed requests remain deterministic.
func TestRateLimiter_ConcurrentHitsShareOneFixedWindow(t *testing.T) {
	const (
		window     = time.Minute
		loginLimit = 5
		attempts   = 64
	)
	ctx := context.Background()
	fake, client := newFakeRedis(t)
	limiter := NewRateLimiter(client, 100, window, loginLimit)
	const email = "concurrent@example.com"
	const key = "rate_limit:email:" + email

	start := make(chan struct{})
	results := make(chan bool, attempts)
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			allowed, _, err := limiter.AllowByEmail(ctx, email)
			results <- allowed
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent hit: %v", err)
		}
	}
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}
	if allowed != loginLimit {
		t.Fatalf("allowed %d concurrent requests, want exactly %d", allowed, loginLimit)
	}
	if got, ok := fake.value(key); !ok || got != attempts {
		t.Fatalf("counter after concurrent hits = %d (exists=%v), want %d", got, ok, attempts)
	}
	if got := fake.pttl(key); got != window {
		t.Fatalf("TTL after concurrent hits = %v, want one fixed window %v", got, window)
	}
}

// TestRateLimiter_RedisErrorSemantics pins the failure modes the fixed-window
// rewrite must keep: login endpoints fail CLOSED, other endpoints fail open,
// and the per-email limiter always fails closed.
func TestRateLimiter_RedisErrorSemantics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	fake, client := newFakeRedis(t)
	fake.failWith = errors.New("connection refused")
	limiter := NewRateLimiter(client, 100, time.Minute, 5)

	if allowed, _, err := limiter.AllowByEmail(ctx, "victim@example.com"); err == nil || allowed {
		t.Errorf("AllowByEmail on Redis error: allowed=%v err=%v, want allowed=false with an error", allowed, err)
	}

	router := gin.New()
	router.Use(RateLimiting(limiter))
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }
	router.POST("/api/v1/auth-service/auth/login", ok)
	router.GET("/api/v1/auth-service/auth/me", ok)

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/api/v1/auth-service/auth/login", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/v1/auth-service/auth/me", http.StatusOK},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s on Redis error: status %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

// TestRateLimiter_FixedWindowAgainstRealRedis checks the test double's
// assumptions (SET NX leaves an existing TTL alone, INCR preserves it)
// against a real server. Skips when no Redis is reachable.
func TestRateLimiter_FixedWindowAgainstRealRedis(t *testing.T) {
	options := &redis.Options{Addr: "localhost:6379", DialTimeout: 500 * time.Millisecond}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		parsed, err := redis.ParseURL(redisURL)
		if err != nil {
			t.Fatalf("parse REDIS_URL: %v", err)
		}
		options = parsed
		options.DialTimeout = 500 * time.Millisecond
	}
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	const window = 3 * time.Second
	email := fmt.Sprintf("fixed-window-%d@example.com", time.Now().UnixNano())
	key := "rate_limit:email:" + email
	t.Cleanup(func() { client.Del(context.Background(), key) })

	limiter := NewRateLimiter(client, 100, window, 1)
	if allowed, _, err := limiter.AllowByEmail(ctx, email); err != nil || !allowed {
		t.Fatalf("first attempt: allowed=%v err=%v", allowed, err)
	}
	opened := time.Now()

	time.Sleep(1200 * time.Millisecond)
	for i := 0; i < 10; i++ {
		if allowed, _, err := limiter.AllowByEmail(ctx, email); err != nil || allowed {
			t.Fatalf("over-limit attempt %d: allowed=%v err=%v", i+1, allowed, err)
		}
	}
	ttl, err := client.PTTL(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if left := window - time.Since(opened); ttl <= 0 || ttl > left+50*time.Millisecond {
		t.Fatalf("key TTL = %v after retries, but only %v is left of the original window", ttl, left)
	}

	time.Sleep(time.Until(opened.Add(window + 100*time.Millisecond)))
	if allowed, _, err := limiter.AllowByEmail(ctx, email); err != nil || !allowed {
		t.Fatalf("attempt after the original window: allowed=%v err=%v, want allowed", allowed, err)
	}
}
