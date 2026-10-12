package middleware

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// RateLimiter handles rate limiting using Redis fixed-window counters.
type RateLimiter struct {
	redis         *redis.Client
	defaultLimit  int
	defaultWindow time.Duration
	loginLimit    int
}

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(redis *redis.Client, defaultLimit int, defaultWindow time.Duration, loginLimit int) *RateLimiter {
	return &RateLimiter{
		redis:         redis,
		defaultLimit:  defaultLimit,
		defaultWindow: defaultWindow,
		loginLimit:    loginLimit,
	}
}

// Allow checks if a request should be allowed based on rate limits.
// Returns (allowed, retryAfter, error). On a Redis error this returns
// (true, 0, err) — the *middleware* decides whether to fail-open or
// fail-closed based on the endpoint sensitivity. Callers MUST inspect
// err and not blindly trust the boolean.
func (r *RateLimiter) Allow(ctx context.Context, tenantID, endpoint string) (bool, time.Duration, error) {
	// Exempt certain public read-only endpoints from rate limiting
	if isExemptEndpoint(endpoint) {
		return true, 0, nil
	}

	// Determine limit based on endpoint
	limit := r.defaultLimit
	if isLoginEndpoint(endpoint) {
		limit = r.loginLimit
	}

	key := fmt.Sprintf("rate_limit:%s:%s", tenantID, endpoint)
	count, retryAfter, err := r.hit(ctx, key)
	if err != nil {
		return true, 0, fmt.Errorf("redis error: %w", err)
	}
	if count > int64(limit) {
		return false, retryAfter, nil
	}
	return true, 0, nil
}

// Actions the per-account limiter distinguishes. Each gets its own counter, so
// spending one cannot lock a victim out of another: before this split, login,
// /auth/authenticate and forgot-password all counted under a single
// rate_limit:email:<email> key, and anyone could exhaust a victim's sign-in
// allowance by spamming forgot-password for their address.
const (
	// ActionLogin covers every endpoint that checks a password for an account
	// (POST /auth/login and POST /auth/authenticate share one budget, since both
	// are guesses at the same secret).
	ActionLogin = "login"
	// ActionForgotPassword covers reset-email requests.
	ActionForgotPassword = "forgot-password"
)

type actionPolicy struct {
	// failuresOnly: only attempts the handler answers with an error status
	// consume the budget; a request that succeeds is refunded by the
	// RateLimiting middleware once the handler returns. A legitimate user who
	// signs in correctly never moves toward a lockout.
	failuresOnly bool
	// perIP keys the counter on email AND client address, so an attacker
	// guessing from their own address locks only themselves out of that
	// account, not its owner. Per-account protection across addresses is the
	// account lockout in the login service.
	perIP bool
}

var actionPolicies = map[string]actionPolicy{
	ActionLogin:          {failuresOnly: true, perIP: true},
	ActionForgotPassword: {failuresOnly: false, perIP: false},
}

// refundKeysCtx is the gin context key under which AllowAction records the
// counters RateLimiting should give a request's attempt back to on success.
const refundKeysCtx = "rateLimitRefundKeys"

// AllowAction rate-limits one account-scoped action (see Action*), keyed on the
// lower-cased email (plus the client address for actions that are per-IP).
// It counts the attempt up front, atomically, so concurrent guesses cannot
// slip past the limit; for failures-only actions the RateLimiting middleware
// refunds that count after the handler if the response was not an error.
//
// Returns the same shape as Allow, but the handler MUST fail closed on a
// non-nil error: a silent brute-force-protection bypass is exactly what this
// guards against.
func (r *RateLimiter) AllowAction(c *gin.Context, action, email string) (bool, time.Duration, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return true, 0, nil
	}
	policy := actionPolicies[action]

	key := fmt.Sprintf("rate_limit:action:%s:%s", action, email)
	if policy.perIP {
		key += ":" + c.ClientIP()
	}
	count, retryAfter, err := r.hit(c.Request.Context(), key)
	if err != nil {
		return false, 0, fmt.Errorf("redis error: %w", err)
	}
	if count > int64(r.loginLimit) {
		return false, retryAfter, nil
	}
	if policy.failuresOnly {
		keys, _ := c.Get(refundKeysCtx)
		c.Set(refundKeysCtx, append(asStrings(keys), key))
	}
	return true, 0, nil
}

func asStrings(v any) []string {
	s, _ := v.([]string)
	return s
}

// refundScript gives one attempt back without ever creating a key: if the
// counter expired between the attempt and the refund, DECR would otherwise
// recreate it at -1 with no TTL, which is a permanent lockout in reverse.
var refundScript = redis.NewScript(`
local n = tonumber(redis.call('GET', KEYS[1]))
if n and n > 0 then return redis.call('DECR', KEYS[1]) end
return 0`)

func (r *RateLimiter) refund(ctx context.Context, keys []string) {
	for _, key := range keys {
		if err := refundScript.Eval(ctx, r.redis, []string{key}).Err(); err != nil && !errors.Is(err, redis.Nil) {
			logrus.WithError(err).Warn("rate limiter: could not refund a successful attempt")
		}
	}
}

// hit counts one request against key's fixed window and returns the new
// count and the time left in the window.
//
// The window is FIXED: its expiry is set only when SET ... NX creates the
// key, and INCR preserves an existing TTL. An earlier version ran
// INCR + EXPIRE on every request, so each hit pushed the expiry back a full
// window — a client retrying under a 429 stayed locked out for as long as it
// kept retrying, and the retry_after it was told was never true. Do not add
// an EXPIRE here.
//
// MULTI/EXEC makes create-with-TTL and increment atomic, so a crash or a
// concurrent expiry between them cannot leave a counter with no TTL (which
// would be a permanent lockout).
func (r *RateLimiter) hit(ctx context.Context, key string) (int64, time.Duration, error) {
	pipe := r.redis.TxPipeline()
	pipe.SetNX(ctx, key, 0, r.defaultWindow)
	incr := pipe.Incr(ctx, key)
	pttl := pipe.PTTL(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, 0, err
	}

	// Round UP to whole seconds: Retry-After is sent in seconds, and rounding
	// down would tell a client to come back just before its window ends.
	retryAfter := (pttl.Val() + time.Second - 1).Truncate(time.Second)
	if pttl.Val() <= 0 {
		// -1 (no expiry) or -2 (gone) cannot happen inside the transaction;
		// if it somehow does, report the full window rather than "retry now".
		retryAfter = r.defaultWindow
	}
	return incr.Val(), retryAfter, nil
}

// authEndpointSuffixes are the unauthenticated credential, token and signup
// endpoints. All of them fail CLOSED on a limiter error (see isAuthEndpoint),
// and the strictSuffixes subset also gets the tight login limit.
//
// The list used to hold only login/authenticate/register/forgot/reset, so the
// real signup (/auth/register/complete), /auth/refresh, invitation acceptance,
// email verification, /auth/initiate and the OAuth token endpoint fell into the
// default class: the 100/min default limit and — worse — a silent pass when
// Redis was down.
var (
	// strictSuffixes: guessing or email-sending surfaces; limited to loginLimit.
	strictSuffixes = []string{
		"/auth/login",
		"/auth/authenticate",
		"/auth/register",
		"/auth/register/complete",
		"/auth/forgot-password",
		"/auth/reset-password",
		"/auth/resend-verification",
		"/auth/verify-email",
		"/auth/invitations/accept",
		"/oauth/token",
	}
	// sessionSuffixes: called routinely by signed-in clients (a refresh every
	// few minutes behind a shared NAT), so they keep the default limit but still
	// never fail open.
	sessionSuffixes = []string{
		"/auth/refresh",
		"/auth/initiate",
		"/auth/methods",
		"/auth/complete",
	}
)

func matchesEndpoint(endpoint string, suffixes []string) bool {
	for _, p := range suffixes {
		if endpoint == p || endpoint == "/api/v1/auth-service"+p || endpoint == "/api/v2/auth-service"+p {
			return true
		}
	}
	return false
}

// isLoginEndpoint reports whether the endpoint gets the strict loginLimit.
func isLoginEndpoint(endpoint string) bool { return matchesEndpoint(endpoint, strictSuffixes) }

// isAuthEndpoint reports whether a limiter outage must refuse the request
// rather than let it through.
func isAuthEndpoint(endpoint string) bool {
	return isLoginEndpoint(endpoint) || matchesEndpoint(endpoint, sessionSuffixes)
}

// isExemptEndpoint checks if the endpoint should be exempt from rate limiting
// These are typically public read-only endpoints that don't need strict rate limiting
func isExemptEndpoint(endpoint string) bool {
	exemptEndpoints := []string{
		"/auth/sso/providers", // Public SSO providers list - read-only, no auth required
	}

	for _, exemptPath := range exemptEndpoints {
		if endpoint == exemptPath || endpoint == "/api/v1/auth-service"+exemptPath || endpoint == "/api/v2/auth-service"+exemptPath {
			return true
		}
	}
	return false
}
