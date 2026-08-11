package middleware

import (
	"net/http"

	"github.com/vistasecurity/vistaplatform/shared/serviceauth"

	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// RequireAuth delegates JWT validation to the shared middleware.
// It also supports internal service-to-service calls via HMAC verification.
func RequireAuth(jwtSecret string, internalSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:       jwtSecret,
		RequireIssuer:   "crypto-inventory-auth",
		RequireAudience: "crypto-inventory",
		InternalSecret:  internalSecret,
		SkipPaths:       []string{"/health", "/ready"},
	})
}

// RequireInternalAuth validates HMAC-signed service-to-service requests.
func RequireInternalAuth(internalSecret string) gin.HandlerFunc {
	var verifier *serviceauth.Verifier
	if internalSecret != "" {
		verifier = serviceauth.NewVerifier(internalSecret)
	}

	return func(c *gin.Context) {
		if verifier == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Internal auth not configured"})
			c.Abort()
			return
		}

		if !verifier.Verify(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid internal service signature"})
			c.Abort()
			return
		}

		c.Set("isInternalCall", true)
		c.Next()
	}
}
