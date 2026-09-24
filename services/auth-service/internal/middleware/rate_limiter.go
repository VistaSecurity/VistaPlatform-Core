package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
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

// AllowByEmail rate-limits per-account (keyed on the lower-cased email)
// independent of the IP-keyed limit applied by the middleware. Closes the
// "spray from many IPs against one victim email" hole that IP-only limiting
// leaves open.
//
// Returns the same shape as Allow. Callers (handlers for /auth/login,
// /auth/password-reset, etc.) MUST fail-closed on a Redis error — a
// silent brute-force-protection bypass is exactly what this guards against.
func (r *RateLimiter) AllowByEmail(ctx context.Context, email string) (bool, time.Duration, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return true, 0, nil
	}

	key := fmt.Sprintf("rate_limit:email:%s", email)
	count, retryAfter, err := r.hit(ctx, key)
	if err != nil {
		return false, 0, fmt.Errorf("redis error: %w", err)
	}
	if count > int64(r.loginLimit) {
		return false, retryAfter, nil
	}
	return true, 0, nil
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

// isLoginEndpoint checks if the endpoint is a login/authentication endpoint.
// Matches both the bare path and the full gateway-routed path.
func isLoginEndpoint(endpoint string) bool {
	loginEndpoints := []string{
		"/auth/login",
		"/auth/authenticate",
		"/auth/register",
		"/auth/password/reset",
		"/auth/password/forgot",
	}

	for _, loginPath := range loginEndpoints {
		if endpoint == loginPath || endpoint == "/api/v1/auth-service"+loginPath || endpoint == "/api/v2/auth-service"+loginPath {
			return true
		}
	}
	return false
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
