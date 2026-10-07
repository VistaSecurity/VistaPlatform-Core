package loginthrottle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// fakeRedis is the smallest in-process stand-in for the commands the limiter
// issues (SET NX, INCR, PTTL inside MULTI/EXEC). It never dials. failing makes
// every command error, to model a Redis outage.
type fakeRedis struct {
	mu      sync.Mutex
	vals    map[string]int64
	failing bool
	cmds    int
}

func (f *fakeRedis) DialHook(redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("never dials") }
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
	return func(_ context.Context, cmds []redis.Cmder) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range cmds {
			f.apply(c)
		}
		return cmds[0].Err()
	}
}
func (f *fakeRedis) apply(cmd redis.Cmder) {
	f.cmds++
	if f.failing {
		cmd.SetErr(errors.New("connection refused"))
		return
	}
	args := cmd.Args()
	switch strings.ToLower(cmd.Name()) {
	case "multi":
		cmd.(*redis.StatusCmd).SetVal("OK")
	case "exec":
		cmd.(*redis.SliceCmd).SetVal(nil)
	case "set":
		k := fmt.Sprint(args[1])
		_, exists := f.vals[k]
		if !exists {
			f.vals[k] = 0
		}
		cmd.(*redis.BoolCmd).SetVal(!exists)
	case "incr":
		k := fmt.Sprint(args[1])
		f.vals[k]++
		cmd.(*redis.IntCmd).SetVal(f.vals[k])
	case "pttl":
		cmd.(*redis.DurationCmd).SetVal(42 * time.Second)
	default:
		cmd.SetErr(fmt.Errorf("unsupported %q", cmd.Name()))
	}
}

func newRedis(f *fakeRedis) *redis.Client {
	c := redis.NewClient(&redis.Options{Addr: "fake.invalid:6379"})
	c.AddHook(f)
	return c
}

func TestLimiter_RedisCountsAndReportsTheRemainingWindow(t *testing.T) {
	f := &fakeRedis{vals: map[string]int64{}}
	l := New(newRedis(f), 2, time.Minute)
	for i := 1; i <= 2; i++ {
		if ok, _ := l.AllowEmail(context.Background(), "A@x.test"); !ok {
			t.Fatalf("attempt %d refused", i)
		}
	}
	ok, retry := l.AllowEmail(context.Background(), "a@x.test")
	if ok || retry != 42*time.Second {
		t.Fatalf("3rd attempt => ok=%v retry=%v; want refused with the Redis TTL (42s)", ok, retry)
	}
	if f.cmds == 0 {
		t.Fatal("limiter never used Redis")
	}
}

// A Redis outage must neither disable the limiter nor refuse every sign-in.
func TestLimiter_RedisOutageFallsBackToTheInProcessCounter(t *testing.T) {
	f := &fakeRedis{vals: map[string]int64{}, failing: true}
	l := New(newRedis(f), 2, time.Minute)
	for i := 1; i <= 2; i++ {
		if ok, _ := l.AllowEmail(context.Background(), "a@x.test"); !ok {
			t.Fatalf("attempt %d refused during a Redis outage; the fallback must still admit within the limit", i)
		}
	}
	if ok, retry := l.AllowEmail(context.Background(), "a@x.test"); ok || retry <= 0 {
		t.Fatalf("3rd attempt => ok=%v retry=%v; want refused (a Redis outage must not switch the limiter off)", ok, retry)
	}
}

func TestLimiter_NilRedisUsesTheInProcessCounterAndWindowExpires(t *testing.T) {
	l := New(nil, 1, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	if ok, _ := l.AllowIP(context.Background(), "192.0.2.1"); !ok {
		t.Fatal("first attempt refused")
	}
	l.AllowIP(context.Background(), "192.0.2.1") // 2 of 2 (ip limit = 2x)
	if ok, retry := l.AllowIP(context.Background(), "192.0.2.1"); ok || retry != time.Minute {
		t.Fatalf("over the limit => ok=%v retry=%v; want refused, 1m", ok, retry)
	}
	now = now.Add(61 * time.Second)
	if ok, _ := l.AllowIP(context.Background(), "192.0.2.1"); !ok {
		t.Fatal("still refused after the window elapsed")
	}
}

func TestMiddleware_RestoresTheBodyForTheHandlerAndIgnoresNonJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	l := New(nil, 5, time.Minute)
	r := gin.New()
	var seen string
	r.POST("/login", l.Middleware(true), func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		seen = string(b)
		c.Status(http.StatusNoContent)
	})
	for _, body := range []string{`{"email":"a@x.test","password":"p"}`, `not json`, ``} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent || seen != body {
			t.Fatalf("body %q => %d, handler saw %q", body, w.Code, seen)
		}
	}
}

func TestMiddleware_429CarriesRetryAfter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	l := New(nil, 1, time.Minute) // ip limit 2
	r := gin.New()
	r.POST("/login", l.Middleware(false), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	var last *httptest.ResponseRecorder
	for i := 0; i < 3; i++ {
		last = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "192.0.2.9:1"
		r.ServeHTTP(last, req)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd => %d", last.Code)
	}
	if n, err := strconv.Atoi(last.Header().Get("Retry-After")); err != nil || n < 1 || n > 60 {
		t.Fatalf("Retry-After %q", last.Header().Get("Retry-After"))
	}
}
