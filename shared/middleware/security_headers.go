package middleware

import (
	"os"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders returns Gin middleware that sets standard security response headers.
// HSTS is only set when serving over TLS (production). It is intentionally omitted
// in development to prevent poisoning browser HSTS caches on localhost/HTTP.
func SecurityHeaders() gin.HandlerFunc {
	tlsEnabled := os.Getenv("COOKIE_SECURE") == "true" ||
		os.Getenv("TLS_ENABLED") == "true" ||
		os.Getenv("ENVIRONMENT") == "production"

	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "0") // Modern recommendation: disable legacy XSS auditor
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if tlsEnabled {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		c.Next()
	}
}
