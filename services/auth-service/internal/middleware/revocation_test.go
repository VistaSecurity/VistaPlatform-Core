package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// Simple test helpers
func assertEqual(t *testing.T, expected, actual interface{}) {
	if expected != actual {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

func assertContains(t *testing.T, str, substr string) {
	if !contains(str, substr) {
		t.Errorf("Expected %s to contain %s", str, substr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && contains(s[1:], substr)
}

func TestRequireNotRevoked(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		hasJTI         bool
		jti            string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "no jti in context - should pass",
			hasJTI:         false,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "empty jti - should pass",
			hasJTI:         true,
			jti:            "",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			router := gin.New()

			// Create a simple Redis client mock (nil for basic tests)
			var redisClient *redis.Client = nil

			// Setup middleware
			router.Use(func(c *gin.Context) {
				if tt.hasJTI {
					c.Set("jti", tt.jti)
				}
				c.Next()
			})
			router.Use(RequireNotRevoked(redisClient))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request
			req, _ := http.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assertions
			assertEqual(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response map[string]interface{}
				_ = json.Unmarshal(w.Body.Bytes(), &response)
				if errorMsg, ok := response["error"].(string); ok {
					assertContains(t, errorMsg, tt.expectedError)
				}
			}
		})
	}
}

// NOTE: RequireNotRevoked is exercised above against a stubbed checker only —
// nothing here covers it against a real Redis, and in particular nothing covers
// the FAIL-OPEN branch (a denylist outage allows the request through, by design;
// see shared/middleware/auth.go). A `TestRequireNotRevokedWithRealRedis` used to
// stand here, but its body was an unconditional t.Skip() with no assertions, so
// it could not fail and it disguised the gap. Removed rather than left in place.
//
// The branch worth pinning when this is written for real: with Redis
// unreachable, the middleware allows the request AND logs the fail-open warning
// — so that a future refactor cannot silently turn a documented, deliberate
// fail-open into an undocumented one.
