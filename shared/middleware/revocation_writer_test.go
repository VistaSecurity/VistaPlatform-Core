package middleware

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type recordingWriter struct {
	jtis map[string]time.Duration
	err  error
}

func (r *recordingWriter) RevokeJTI(_ context.Context, jti string, ttl time.Duration) error {
	if r.err != nil {
		return r.err
	}
	r.jtis[jti] = ttl
	return nil
}

func tokenWith(t *testing.T, jti string, exp time.Time) string {
	t.Helper()
	claims := jwt.RegisteredClaims{ID: jti}
	if !exp.IsZero() {
		claims.ExpiresAt = jwt.NewNumericDate(exp)
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRevokeRequestAccessToken(t *testing.T) {
	soon := time.Now().Add(30 * time.Minute)
	cases := []struct {
		name     string
		build    func(r *http.Request)
		wantJTI  string
		wantDeny bool
	}{
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tokenWith(t, "j-bearer", soon)) }, "j-bearer", true},
		{"cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "platform_access_token", Value: tokenWith(t, "j-cookie", soon)})
		}, "j-cookie", true},
		{"bearer wins over cookie", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+tokenWith(t, "j-b", soon))
			r.AddCookie(&http.Cookie{Name: "platform_access_token", Value: tokenWith(t, "j-c", soon)})
		}, "j-b", true},
		{"no token", func(r *http.Request) {}, "", false},
		{"unparseable token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer not.a.jwt") }, "", false},
		{"no jti", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tokenWith(t, "", soon)) }, "", false},
		{"no exp", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tokenWith(t, "j-noexp", time.Time{})) }, "", false},
		{"already expired", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+tokenWith(t, "j-old", time.Now().Add(-time.Minute)))
		}, "", false},
	}
	for _, tc := range cases {
		w := &recordingWriter{jtis: map[string]time.Duration{}}
		r := httptest.NewRequest(http.MethodPost, "/logout", nil)
		tc.build(r)
		got, err := RevokeRequestAccessToken(context.Background(), w, r, "platform_access_token")
		if err != nil || got != tc.wantDeny {
			t.Errorf("%s: revoked=%v err=%v; want revoked=%v", tc.name, got, err, tc.wantDeny)
			continue
		}
		if tc.wantDeny {
			ttl, ok := w.jtis[tc.wantJTI]
			if !ok || ttl < 25*time.Minute || ttl > 30*time.Minute {
				t.Errorf("%s: wrote %v; want %s with the token's remaining life (~30m)", tc.name, w.jtis, tc.wantJTI)
			}
		} else if len(w.jtis) != 0 {
			t.Errorf("%s: wrote %v; want nothing", tc.name, w.jtis)
		}
	}
}

func TestRevokeRequestAccessToken_NilWriterAndWriteError(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.Header.Set("Authorization", "Bearer "+tokenWith(t, "j", time.Now().Add(time.Hour)))
	if got, err := RevokeRequestAccessToken(context.Background(), nil, r); got || err != nil {
		t.Fatalf("nil writer => %v %v; want a quiet no-op", got, err)
	}
	boom := errors.New("redis down")
	if got, err := RevokeRequestAccessToken(context.Background(), &recordingWriter{err: boom}, r); got || !errors.Is(err, boom) {
		t.Fatalf("failing writer => %v %v; want the write error surfaced", got, err)
	}
}

// capture is a redis hook that records the commands it sees and never dials.
type capture struct {
	mu   sync.Mutex
	args [][]interface{}
}

func (c *capture) DialHook(redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("never dials") }
}
func (c *capture) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		c.mu.Lock()
		c.args = append(c.args, cmd.Args())
		c.mu.Unlock()
		cmd.(*redis.StatusCmd).SetVal("OK")
		return nil
	}
}
func (c *capture) ProcessPipelineHook(redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(_ context.Context, _ []redis.Cmder) error { return errors.New("unexpected pipeline") }
}

// The writer must use the very key the reader (redisRevocationChecker) consults.
func TestRedisRevocationWriter_UsesTheKeyTheCheckerReads(t *testing.T) {
	if NewRedisRevocationWriter(nil) != nil {
		t.Fatal("a nil client must give a nil writer so callers can test for it")
	}
	c := &capture{}
	rdb := redis.NewClient(&redis.Options{Addr: "fake.invalid:6379"})
	rdb.AddHook(c)
	defer func() { _ = rdb.Close() }()

	if err := NewRedisRevocationWriter(rdb).RevokeJTI(context.Background(), "abc-123", 42*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(c.args) != 1 {
		t.Fatalf("got %d commands, want 1", len(c.args))
	}
	a := c.args[0]
	if fmt.Sprint(a[0]) != "set" || fmt.Sprint(a[1]) != RevokedTokenKey("abc-123") {
		t.Fatalf("wrote %v; want SET %s", a, RevokedTokenKey("abc-123"))
	}
}
