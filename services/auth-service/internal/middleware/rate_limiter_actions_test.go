package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// actionRouter mounts the real RateLimiting middleware over a handler that
// spends the per-account budget exactly the way the login handlers do, and
// answers with the status the test asks for.
func actionRouter(l *RateLimiter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RateLimiting(l))
	handle := func(action string) gin.HandlerFunc {
		return func(c *gin.Context) {
			allowed, _, err := l.AllowAction(c, action, c.Query("email"))
			if err != nil {
				c.Status(http.StatusServiceUnavailable)
				return
			}
			if !allowed {
				c.Status(http.StatusTooManyRequests)
				return
			}
			if c.Query("ok") == "1" {
				c.Status(http.StatusOK)
				return
			}
			c.Status(http.StatusUnauthorized)
		}
	}
	r.POST("/handler/login", handle(ActionLogin))
	r.POST("/handler/forgot", handle(ActionForgotPassword))
	return r
}

func hitAction(r *gin.Engine, path, email, ip string, ok bool) int {
	target := path + "?email=" + email
	if ok {
		target += "&ok=1"
	}
	req := httptest.NewRequest(http.MethodPost, target, nil)
	req.RemoteAddr = ip + ":4321"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// One shared per-email counter let anyone lock a victim out of signing in:
// spam forgot-password (or guess from any address) for their email and the
// victim's own login 429s. Each action now has its own counter, and a login
// counter belongs to (email, address).
func TestAllowAction_KeysAreSeparatedByActionAndAddress(t *testing.T) {
	const attacker, victimIP, email = "198.51.100.66", "203.0.113.10", "victim@example.com"
	_, client := newFakeRedis(t)
	r := actionRouter(NewRateLimiter(client, 1000, time.Minute, 3))

	// The attacker burns the forgot-password budget and then some.
	for i := 0; i < 6; i++ {
		hitAction(r, "/handler/forgot", email, attacker, true)
	}
	if got := hitAction(r, "/handler/forgot", email, attacker, true); got != http.StatusTooManyRequests {
		t.Fatalf("forgot-password after the budget: %d, want 429", got)
	}
	// ...which must not touch sign-in, even from the same address.
	if got := hitAction(r, "/handler/login", email, attacker, false); got != http.StatusUnauthorized {
		t.Fatalf("login from the same address after forgot-password spam: %d, want the handler's 401 (budgets are shared)", got)
	}
	// ...and certainly not the victim's.
	if got := hitAction(r, "/handler/login", email, victimIP, false); got != http.StatusUnauthorized {
		t.Fatalf("victim login after forgot-password spam: %d, want the handler's 401 (not 429)", got)
	}

	// The attacker guessing passwords locks out only their own address.
	for i := 0; i < 2; i++ {
		hitAction(r, "/handler/login", email, attacker, false)
	}
	if got := hitAction(r, "/handler/login", email, attacker, false); got != http.StatusTooManyRequests {
		t.Fatalf("attacker login after 3 failures: %d, want 429", got)
	}
	if got := hitAction(r, "/handler/login", email, victimIP, true); got != http.StatusOK {
		t.Fatalf("victim login from their own address while the attacker is locked out: %d, want 200", got)
	}
}

// Only failures consume the login budget: signing in correctly any number of
// times never moves a user toward a lockout.
func TestAllowAction_LoginCountsOnlyFailures(t *testing.T) {
	_, client := newFakeRedis(t)
	r := actionRouter(NewRateLimiter(client, 1000, time.Minute, 3))
	const email, ip = "user@example.com", "203.0.113.10"

	for i := 0; i < 20; i++ {
		if got := hitAction(r, "/handler/login", email, ip, true); got != http.StatusOK {
			t.Fatalf("successful login #%d: %d, want 200 — successes are being counted", i+1, got)
		}
	}
	for i := 0; i < 3; i++ {
		if got := hitAction(r, "/handler/login", email, ip, false); got != http.StatusUnauthorized {
			t.Fatalf("failure #%d: %d, want 401", i+1, got)
		}
	}
	if got := hitAction(r, "/handler/login", email, ip, false); got != http.StatusTooManyRequests {
		t.Fatalf("4th failure: %d, want 429", got)
	}
}

// Forgot-password sends mail on every accepted request, so it counts every
// attempt, successes included.
func TestAllowAction_ForgotPasswordCountsEveryAttempt(t *testing.T) {
	_, client := newFakeRedis(t)
	r := actionRouter(NewRateLimiter(client, 1000, time.Minute, 3))
	for i := 0; i < 3; i++ {
		hitAction(r, "/handler/forgot", "u@example.com", "203.0.113.10", true)
	}
	if got := hitAction(r, "/handler/forgot", "u@example.com", "203.0.113.10", true); got != http.StatusTooManyRequests {
		t.Fatalf("4th forgot-password: %d, want 429", got)
	}
}

// A refund must never create a counter: if the window ended between the
// attempt and the refund, DECR would leave -1 with no TTL.
func TestRefund_NeverCreatesOrGoesBelowZero(t *testing.T) {
	fake, client := newFakeRedis(t)
	l := NewRateLimiter(client, 1000, time.Minute, 3)
	l.refund(testGinContext("203.0.113.9:1").Request.Context(), []string{"rate_limit:action:login:gone@example.com:203.0.113.9"})
	if _, exists := fake.value("rate_limit:action:login:gone@example.com:203.0.113.9"); exists {
		t.Fatal("refund created a missing counter")
	}
}

// Every unauthenticated credential/token/signup endpoint refuses on a limiter
// outage instead of letting the request through; a data endpoint still fails
// open so a Redis blip does not wedge the platform.
func TestRateLimiting_AuthEndpointsFailClosedOnRedisError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake, client := newFakeRedis(t)
	fake.failWith = errors.New("connection refused")
	r := gin.New()
	r.Use(RateLimiting(NewRateLimiter(client, 100, time.Minute, 5)))
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }

	closed := []string{
		"/api/v1/auth-service/auth/login",
		"/api/v1/auth-service/auth/authenticate",
		"/api/v1/auth-service/auth/register",
		"/api/v1/auth-service/auth/register/complete",
		"/api/v1/auth-service/auth/forgot-password",
		"/api/v1/auth-service/auth/reset-password",
		"/api/v1/auth-service/auth/refresh",
		"/api/v1/auth-service/auth/initiate",
		"/api/v1/auth-service/auth/methods",
		"/api/v1/auth-service/auth/complete",
		"/api/v1/auth-service/auth/invitations/accept",
		"/api/v1/auth-service/auth/resend-verification",
		"/api/v1/auth-service/auth/verify-email",
		"/api/v1/auth-service/oauth/token",
	}
	for _, p := range closed {
		r.POST(p, ok)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p, strings.NewReader("")))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s with Redis down: %d, want 503 (fail closed)", p, rec.Code)
		}
	}

	r.GET("/api/v1/auth-service/auth/me", ok)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth-service/auth/me", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/auth/me with Redis down: %d, want 200 (non-auth endpoints fail open)", rec.Code)
	}
}

// The strict login limit now covers the signup and token-guessing surfaces,
// not only login/forgot/reset.
func TestIsLoginEndpoint_CoversSignupAndTokenSurfaces(t *testing.T) {
	for _, p := range []string{"/auth/register/complete", "/auth/invitations/accept", "/auth/verify-email", "/auth/resend-verification", "/oauth/token"} {
		if !isLoginEndpoint("/api/v1/auth-service" + p) {
			t.Errorf("%s is not rate-limited as a strict auth endpoint", p)
		}
	}
	if isLoginEndpoint("/api/v1/auth-service/auth/refresh") {
		t.Error("/auth/refresh must keep the default limit: signed-in clients call it routinely")
	}
	if !isAuthEndpoint("/api/v1/auth-service/auth/refresh") {
		t.Error("/auth/refresh must still fail closed")
	}
}

// The fake Redis above only imitates the refund script; run the real one
// against a real server. Skips when none is reachable.
func TestRefundScriptAgainstRealRedis(t *testing.T) {
	client := newRealRedis(t)
	ctx := testGinContext("203.0.113.9:1").Request.Context()
	key := "rate_limit:action:login:refund-" + time.Now().Format("150405.000000") + "@example.com:203.0.113.9"
	t.Cleanup(func() { client.Del(ctx, key) })
	l := NewRateLimiter(client, 100, time.Minute, 5)

	l.refund(ctx, []string{key})
	if n, _ := client.Exists(ctx, key).Result(); n != 0 {
		t.Fatal("refund created a missing key")
	}

	client.Set(ctx, key, 2, time.Minute)
	l.refund(ctx, []string{key})
	if v, _ := client.Get(ctx, key).Int(); v != 1 {
		t.Fatalf("counter after refund = %d, want 1", v)
	}
	l.refund(ctx, []string{key})
	l.refund(ctx, []string{key})
	if v, _ := client.Get(ctx, key).Int(); v != 0 {
		t.Fatalf("counter after repeated refunds = %d, want floor 0", v)
	}
	if ttl, _ := client.PTTL(ctx, key).Result(); ttl <= 0 {
		t.Fatalf("refund dropped the key's TTL (%v)", ttl)
	}
}
