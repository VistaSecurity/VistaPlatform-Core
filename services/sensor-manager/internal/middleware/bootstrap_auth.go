package middleware

import (
	"database/sql"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// BootstrapAuth validates bootstrap mTLS certificate authentication for platform services
// This middleware validates that the client certificate is a valid bootstrap certificate
// issued by the platform bootstrap CA
func BootstrapAuth(db *sql.DB, encryptionKey string) gin.HandlerFunc {
	bootstrapCertService := certificates.NewBootstrapCertificateService(db, encryptionKey)

	return func(c *gin.Context) {
		// Check if mTLS certificate is present
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate required"})
			c.Abort()
			return
		}

		leaf := c.Request.TLS.PeerCertificates[0]

		// 1. Check certificate expiration
		now := time.Now()
		if now.After(leaf.NotAfter) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "bootstrap certificate has expired"})
			c.Abort()
			return
		}
		if now.Before(leaf.NotBefore) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "bootstrap certificate is not yet valid"})
			c.Abort()
			return
		}

		// 2. Extract service name from certificate CN
		serviceName := leaf.Subject.CommonName
		if serviceName == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "bootstrap certificate missing service name in CN"})
			c.Abort()
			return
		}

		// 3. Validate service name is allowed
		allowedServices := map[string]bool{
			"cluster-sensor-service":       true,
			"device-interrogation-service": true,
		}
		if !allowedServices[serviceName] {
			c.JSON(http.StatusForbidden, gin.H{
				"error":        "service not authorized for bootstrap certificate authentication",
				"service_name": serviceName,
			})
			c.Abort()
			return
		}

		// 4. Validate certificate against bootstrap CA
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: leaf.Raw,
		})

		err := bootstrapCertService.ValidateBootstrapCertificate(string(certPEM))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "bootstrap certificate validation failed",
			})
			c.Abort()
			return
		}

		// 5. Set service context for handlers
		c.Set("serviceName", serviceName)
		c.Set("bootstrapCertificate", leaf)

		c.Next()
	}
}

// GetServiceNameFromContext extracts the service name from the Gin context
func GetServiceNameFromContext(c *gin.Context) (string, bool) {
	serviceNameVal, exists := c.Get("serviceName")
	if !exists {
		return "", false
	}

	serviceName, ok := serviceNameVal.(string)
	if !ok {
		return "", false
	}

	return serviceName, true
}
