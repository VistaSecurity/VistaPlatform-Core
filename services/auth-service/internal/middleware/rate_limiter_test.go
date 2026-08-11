package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestRateLimiter_Allow tests the rate limiter with a mock Redis client
func TestRateLimiter_Allow(t *testing.T) {
	// Create a mock Redis client using a real Redis instance for integration testing
	// In a real test environment, you'd use a test Redis instance
	// For unit tests, you'd mock the Redis client

	// Skip if Redis is not available
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	ctx := context.Background()
	err := client.Ping(ctx).Err()
	if err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	// Clean up test keys
	defer func() {
		client.Del(ctx, "rate_limit:test-tenant:/test")
		client.Del(ctx, "rate_limit:test-tenant:/auth/login")
	}()

	// Create rate limiter with low limits for testing
	limiter := NewRateLimiter(client, 5, 1*time.Minute, 2)

	t.Run("allows requests within limit", func(t *testing.T) {
		// Reset counter
		client.Del(ctx, "rate_limit:test-tenant:/test")

		// Make 5 requests (within limit of 5)
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
		// Reset counter
		client.Del(ctx, "rate_limit:test-tenant:/test")

		// Make 5 requests (at limit)
		for i := 0; i < 5; i++ {
			_, _, _ = limiter.Allow(ctx, "test-tenant", "/test")
		}

		// 6th request should be blocked
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
		// Reset counter
		client.Del(ctx, "rate_limit:test-tenant:/auth/login")

		// Make 2 requests (at login limit of 2)
		for i := 0; i < 2; i++ {
			allowed, _, err := limiter.Allow(ctx, "test-tenant", "/auth/login")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !allowed {
				t.Errorf("Request %d should be allowed", i+1)
			}
		}

		// 3rd request should be blocked
		allowed, _, err := limiter.Allow(ctx, "test-tenant", "/auth/login")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if allowed {
			t.Error("Request should be blocked (login limit exceeded)")
		}
	})

	t.Run("fails open on Redis error", func(t *testing.T) {
		// Create a limiter with invalid Redis client
		invalidClient := redis.NewClient(&redis.Options{
			Addr: "localhost:9999", // Invalid address
		})
		invalidLimiter := NewRateLimiter(invalidClient, 5, 1*time.Minute, 2)

		// Should return error but not crash
		allowed, _, err := invalidLimiter.Allow(ctx, "test-tenant", "/test")
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
