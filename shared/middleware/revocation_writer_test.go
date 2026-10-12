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

	"github.com/gin-gonic/gin"
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

// ctxWith builds a gin context carrying the verified-token keys RequireJWTAuth
// publishes. A zero exp / empty jti leaves that key unset.
func ctxWith(jti string, exp time.Time) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/logout", nil)
	if jti != "" {
		c.Set(CtxKeyTokenID, jti)
	}
	if !exp.IsZero() {
		c.Set(CtxKeyTokenExpiresAt, exp)
	}
	return c
}

func TestRevokeRequestAccessToken(t *testing.T) {
	soon := time.Now().Add(30 * time.Minute)
	cases := []struct {
		name     string
		c        *gin.Context
		wantJTI  string
		wantDeny bool
	}{
		{"verified jti and exp", ctxWith("j-verified", soon), "j-verified", true},
		{"no jti", ctxWith("", soon), "", false},
		{"no exp", ctxWith("j-noexp", time.Time{}), "", false},
		{"already expired", ctxWith("j-old", time.Now().Add(-time.Minute)), "", false},
		{"nothing set", ctxWith("", time.Time{}), "", false},
		{"nil context", nil, "", false},
	}
	for _, tc := range cases {
		w := &recordingWriter{jtis: map[string]time.Duration{}}
		got, err := RevokeRequestAccessToken(context.Background(), w, tc.c)
		if err != nil || got != tc.wantDeny {
			t.Errorf("%s: revoked=%v err=%v; want revoked=%v", tc.name, got, err, tc.wantDeny)
			continue
		}
		if tc.wantDeny {
			ttl, ok := w.jtis[tc.wantJTI]
			if !ok || len(w.jtis) != 1 || ttl < 25*time.Minute || ttl > 30*time.Minute {
				t.Errorf("%s: wrote %v; want only %s with the token's remaining life (~30m)", tc.name, w.jtis, tc.wantJTI)
			}
		} else if len(w.jtis) != 0 {
			t.Errorf("%s: wrote %v; want nothing", tc.name, w.jtis)
		}
	}
}

// The helper must not fall back to the request: a token sitting in the
// Authorization header or a cookie, with no verified claims in the context,
// writes nothing.
func TestRevokeRequestAccessToken_IgnoresTheRawRequest(t *testing.T) {
	c := ctxWith("", time.Time{})
	c.Request.Header.Set("Authorization", "Bearer "+signAccessTokenWithJTI(t, "from-header"))
	c.Request.AddCookie(&http.Cookie{Name: "platform_access_token", Value: signAccessTokenWithJTI(t, "from-cookie")})
	w := &recordingWriter{jtis: map[string]time.Duration{}}
	if got, err := RevokeRequestAccessToken(context.Background(), w, c); got || err != nil || len(w.jtis) != 0 {
		t.Fatalf("revoked=%v err=%v wrote=%v; want nothing written from the raw request", got, err, w.jtis)
	}
}

func TestRevokeRequestAccessToken_NilWriterAndWriteError(t *testing.T) {
	c := ctxWith("j", time.Now().Add(time.Hour))
	if got, err := RevokeRequestAccessToken(context.Background(), nil, c); got || err != nil {
		t.Fatalf("nil writer => %v %v; want a quiet no-op", got, err)
	}
	boom := errors.New("redis down")
	if got, err := RevokeRequestAccessToken(context.Background(), &recordingWriter{err: boom}, c); got || !errors.Is(err, boom) {
		t.Fatalf("failing writer => %v %v; want the write error surfaced", got, err)
	}
}

// newLogoutRouter wires the REAL RequireJWTAuth in front of a logout handler
// that calls RevokeRequestAccessToken, the way admin-service registers
// POST /admin/auth/logout. Deleting the middleware's c.Set(CtxKeyTokenID, ...)
// makes TestRevokeRequestAccessToken_Wiring fail.
func newLogoutRouter(w RevocationWriter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireJWTAuth(AuthConfig{
		TenantState:       liveTenantState(),
		JWTSecret:         testJWTSecret,
		AccessTokenCookie: "platform_access_token",
		CSRFCookie:        "platform_csrf_token",
		StrictCookiePair:  true,
	}))
	r.POST("/logout", func(c *gin.Context) {
		if _, err := RevokeRequestAccessToken(c.Request.Context(), w, c); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRevokeRequestAccessToken_Wiring(t *testing.T) {
	t.Run("bearer", func(t *testing.T) {
		w := &recordingWriter{jtis: map[string]time.Duration{}}
		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
		req.Header.Set("Authorization", "Bearer "+signAccessTokenWithJTI(t, "verified-bearer-jti"))
		rec := httptest.NewRecorder()
		newLogoutRouter(w).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
		ttl, ok := w.jtis["verified-bearer-jti"]
		if !ok || len(w.jtis) != 1 || ttl < 55*time.Minute || ttl > time.Hour {
			t.Fatalf("wrote %v; want only verified-bearer-jti with ~1h TTL", w.jtis)
		}
	})
	t.Run("cookie", func(t *testing.T) {
		w := &recordingWriter{jtis: map[string]time.Duration{}}
		jti := "verified-cookie-jti"
		csrf := CSRFToken(testJWTSecret, jti)
		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
		req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: signAccessTokenWithJTI(t, jti)})
		req.AddCookie(&http.Cookie{Name: "platform_csrf_token", Value: csrf})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		newLogoutRouter(w).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
		if _, ok := w.jtis[jti]; !ok || len(w.jtis) != 1 {
			t.Fatalf("wrote %v; want only %s", w.jtis, jti)
		}
	})
}

// The hole CodeQL flagged: a request carrying a valid signed cookie AND an
// attacker-chosen Bearer token. The old helper preferred the Bearer header and
// parsed it unverified, so it would denylist whatever jti the attacker named.
// Now only a jti the middleware verified can ever be written.
func TestRevokeRequestAccessToken_UnverifiedBearerNeverWritten(t *testing.T) {
	jti := "victim-cookie-jti"
	csrf := CSRFToken(testJWTSecret, jti)
	claims := jwt.RegisteredClaims{ID: "attacker", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}

	wrongKey, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("not-the-secret"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}

	for name, bearer := range map[string]string{"wrong key": wrongKey, "alg none": unsigned} {
		t.Run(name, func(t *testing.T) {
			w := &recordingWriter{jtis: map[string]time.Duration{}}
			req := httptest.NewRequest(http.MethodPost, "/logout", nil)
			req.AddCookie(&http.Cookie{Name: "platform_access_token", Value: signAccessTokenWithJTI(t, jti)})
			req.AddCookie(&http.Cookie{Name: "platform_csrf_token", Value: csrf})
			req.Header.Set("X-CSRF-Token", csrf)
			req.Header.Set("Authorization", "Bearer "+bearer)
			newLogoutRouter(w).ServeHTTP(httptest.NewRecorder(), req)
			if _, bad := w.jtis["attacker"]; bad {
				t.Fatalf("wrote %v; an unverified Bearer token's jti reached the denylist", w.jtis)
			}
		})
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
