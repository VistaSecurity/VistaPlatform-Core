package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// CreateDiscoveryJob handles POST /api/v1/sensor-manager/discovery/jobs
func (h *Handler) CreateDiscoveryJob(c *gin.Context) {
	// Get tenant ID and user ID from context
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var input models.DiscoveryJobInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Check if discovery job service is available
	if h.discoveryJobService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Discovery job service unavailable"})
		return
	}

	job, err := h.discoveryJobService.CreateDiscoveryJob(tenantUUID, userUUID, &input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create discovery job",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Discovery job created successfully",
		"job":     job,
	})
}

// ReceiveDiscoveryResults handles POST /api/v1/sensor-manager/discovery/jobs/:id/results
func (h *Handler) ReceiveDiscoveryResults(c *gin.Context) {
	// Get tenant ID from context
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Parse job ID
	jobIDStr := c.Param("id")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	var results models.DiscoveryJobResult
	if err := c.ShouldBindJSON(&results); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Check if discovery job service is available
	if h.discoveryJobService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Discovery job service unavailable"})
		return
	}

	err = h.discoveryJobService.ReceiveDiscoveryResults(tenantUUID, jobID, &results)
	if err != nil {
		if err.Error() == "discovery job not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Discovery job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process discovery results",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Discovery results received successfully",
	})
}
