package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter handles rate limiting using Redis with token bucket algorithm
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

	// Create Redis key
	key := fmt.Sprintf("rate_limit:%s:%s", tenantID, endpoint)

	// Use Redis INCR with TTL for token bucket
	// This is a simplified token bucket: count requests in window
	pipe := r.redis.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, r.defaultWindow)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return true, 0, fmt.Errorf("redis error: %w", err)
	}

	count := incr.Val()

	// Check if limit exceeded
	if count > int64(limit) {
		// Get TTL to calculate retry after
		ttl, err := r.redis.TTL(ctx, key).Result()
		if err != nil {
			ttl = r.defaultWindow
		}
		return false, ttl, nil
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
	pipe := r.redis.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, r.defaultWindow)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("redis error: %w", err)
	}

	if incr.Val() > int64(r.loginLimit) {
		ttl, ttlErr := r.redis.TTL(ctx, key).Result()
		if ttlErr != nil {
			ttl = r.defaultWindow
		}
		return false, ttl, nil
	}
	return true, 0, nil
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
