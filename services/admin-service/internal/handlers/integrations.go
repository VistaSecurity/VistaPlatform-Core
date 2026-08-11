package handlers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/integrations"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

var integrationService *integrations.IntegrationService

// InitializeIntegrationService initializes the integration service.
// bypassDB is the cross-tenant (BYPASSRLS) handle for platform-global, id-keyed paths.
func InitializeIntegrationService(db, bypassDB *sql.DB, encryptionKey string, log *logrus.Logger) {
	encryptionService, err := encryption.NewService(encryptionKey)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize encryption service")
	}
	integrationService = integrations.NewIntegrationService(db, bypassDB, encryptionService, log)
}

// GetIntegrations retrieves all platform integrations
// GET /admin-service/admin/integrations
func GetIntegrations() gin.HandlerFunc {
	return func(c *gin.Context) {
		integrationType := c.Query("type") // Optional filter by type

		var filterType *string
		if integrationType != "" {
			filterType = &integrationType
		}

		list, err := integrationService.ListIntegrations(c.Request.Context(), filterType)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to retrieve integrations",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"integrations": list,
		})
	}
}

// GetIntegration retrieves a single integration by ID
// GET /admin-service/admin/integrations/:id
func GetIntegration() gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
			return
		}

		integration, err := integrationService.GetIntegration(c.Request.Context(), id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Integration not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"integration": integration,
		})
	}
}

// CreateIntegration creates a new platform integration
// POST /admin-service/admin/integrations
func CreateIntegration() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req integrations.CreateIntegrationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request",
			})
			return
		}

		// Get user ID from context (set by auth middleware)
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		integration, err := integrationService.CreateIntegration(c.Request.Context(), &req, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create integration",
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"integration": integration,
		})
	}
}

// UpdateIntegration updates an existing integration
// PUT /admin-service/admin/integrations/:id
func UpdateIntegration() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
			return
		}

		var req integrations.CreateIntegrationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request",
			})
			return
		}

		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		integration, err := integrationService.UpdateIntegration(c.Request.Context(), id, &req, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update integration",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"integration": integration})
	}
}

// DeleteIntegration soft-deletes an integration
// DELETE /admin-service/admin/integrations/:id
func DeleteIntegration() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
			return
		}

		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		if err := integrationService.DeleteIntegration(c.Request.Context(), id, userID); err != nil {
			status := http.StatusInternalServerError
			if err.Error() == "integration not found" {
				status = http.StatusNotFound
			}
			c.JSON(status, gin.H{
				"error": "Failed to delete integration",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Integration deleted"})
	}
}

// TestIntegration tests the connection for an integration
// POST /admin-service/admin/integrations/:id/test
func TestIntegration() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
			return
		}

		result, err := integrationService.TestIntegration(c.Request.Context(), id)
		if err != nil {
			status := http.StatusInternalServerError
			if err.Error() == "integration not found" {
				status = http.StatusNotFound
			}
			c.JSON(status, gin.H{
				"error": "Failed to test integration",
			})
			return
		}

		c.JSON(http.StatusOK, result)
	}
}
