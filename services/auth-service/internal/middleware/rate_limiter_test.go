package middleware

import (
	"context"
	"testing"
	"time"
)

// TestRateLimiter_Allow covers the basic limit selection and error semantics
// against the deterministic in-process Redis double. These checks must run in
// every PR job; they must not depend on a Redis service being reachable.
func TestRateLimiter_Allow(t *testing.T) {
	ctx := context.Background()

	t.Run("allows requests within limit", func(t *testing.T) {
		_, client := newFakeRedis(t)
		limiter := NewRateLimiter(client, 5, time.Minute, 2)

		for i := 0; i < 5; i++ {
			allowed, _, err := limiter.Allow(ctx, "test-tenant", "/test")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !allowed {
				t.Errorf("Request %d should be allowed", i+1)
			}
		}
	})

	t.Run("blocks requests exceeding limit", func(t *testing.T) {
		_, client := newFakeRedis(t)
		limiter := NewRateLimiter(client, 5, time.Minute, 2)

		for i := 0; i < 5; i++ {
			_, _, _ = limiter.Allow(ctx, "test-tenant", "/test")
		}

		allowed, retryAfter, err := limiter.Allow(ctx, "test-tenant", "/test")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if allowed {
			t.Error("Request should be blocked")
		}
		if retryAfter <= 0 {
			t.Error("Retry after should be positive")
		}
	})

	t.Run("uses login limit for login endpoints", func(t *testing.T) {
		_, client := newFakeRedis(t)
		limiter := NewRateLimiter(client, 5, time.Minute, 2)

		for i := 0; i < 2; i++ {
			allowed, _, err := limiter.Allow(ctx, "test-tenant", "/auth/login")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !allowed {
				t.Errorf("Request %d should be allowed", i+1)
			}
		}

		allowed, _, err := limiter.Allow(ctx, "test-tenant", "/auth/login")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if allowed {
			t.Error("Request should be blocked (login limit exceeded)")
		}
	})

	t.Run("fails open on Redis error", func(t *testing.T) {
		fake, client := newFakeRedis(t)
		fake.failWith = context.DeadlineExceeded
		limiter := NewRateLimiter(client, 5, time.Minute, 2)

		allowed, _, err := limiter.Allow(ctx, "test-tenant", "/test")
		if err == nil {
			t.Error("Expected error from invalid Redis connection")
		}
		// Should fail open (allow request)
		if !allowed {
			t.Error("Should fail open and allow request on Redis error")
		}
	})
}

// TestIsLoginEndpoint tests the login endpoint detection
func TestIsLoginEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		expected bool
	}{
		{"/auth/login", true},
		{"/auth/authenticate", true},
		{"/auth/register", true},
		{"/auth/password/reset", true},
		{"/auth/password/forgot", true},
		{"/auth/me", false},
		{"/api/v1/auth-service/auth/users", false},
		{"/test", false},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			result := isLoginEndpoint(tt.endpoint)
			if result != tt.expected {
				t.Errorf("isLoginEndpoint(%q) = %v, want %v", tt.endpoint, result, tt.expected)
			}
		})
	}
}
