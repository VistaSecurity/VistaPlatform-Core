package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/security/service_accounts"
)

// ServiceAccountAuth validates service account tokens for platform service authentication
func ServiceAccountAuth(db *sql.DB) gin.HandlerFunc {
	serviceAccountService := service_accounts.NewService(db)

	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Extract token (Bearer <token>)
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format. Expected: Bearer <token>",
			})
			c.Abort()
			return
		}

		token := strings.TrimSpace(authHeader[7:])
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Service account token is required",
			})
			c.Abort()
			return
		}

		// Validate token
		serviceAccount, err := serviceAccountService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid service account token",
			})
			c.Abort()
			return
		}

		// Check if account is active
		if !serviceAccount.IsActive {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Service account is inactive",
			})
			c.Abort()
			return
		}

		// Set service account context
		c.Set("serviceAccount", serviceAccount)
		c.Set("serviceName", serviceAccount.ServiceName)
		c.Set("isServiceAccount", true)

		c.Next()
	}
}
