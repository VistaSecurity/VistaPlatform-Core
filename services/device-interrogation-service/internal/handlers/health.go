package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
)

// HealthHandlers handles health metrics HTTP requests
type HealthHandlers struct {
	healthService *services.HealthMetricsService
}

// NewHealthHandlers creates a new health handlers instance
func NewHealthHandlers(healthService *services.HealthMetricsService) *HealthHandlers {
	return &HealthHandlers{
		healthService: healthService,
	}
}

// GetDeviceHealth handles GET /devices/:id/health
func (h *HealthHandlers) GetDeviceHealth(c *gin.Context) {
	idStr := c.Param("id")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	// Get hours parameter (default 24)
	hours := 24
	if hoursStr := c.Query("hours"); hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 {
			hours = h
		}
	}

	metrics, err := h.healthService.GetDeviceHealthMetrics(c.Request.Context(), tenantID, deviceID, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// GetDeviceHealthTimeline handles GET /devices/:id/health/timeline
func (h *HealthHandlers) GetDeviceHealthTimeline(c *gin.Context) {
	idStr := c.Param("id")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	// Get hours parameter (default 24)
	hours := 24
	if hoursStr := c.Query("hours"); hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 {
			hours = h
		}
	}

	// Get interval parameter (default 60 minutes)
	interval := 60
	if intervalStr := c.Query("interval"); intervalStr != "" {
		if i, err := strconv.Atoi(intervalStr); err == nil && i > 0 {
			interval = i
		}
	}

	timeline, err := h.healthService.GetDeviceHealthTimeline(c.Request.Context(), tenantID, deviceID, hours, interval)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"timeline": timeline})
}

// GetIntegrationHealth handles GET /integrations/:id/health
func (h *HealthHandlers) GetIntegrationHealth(c *gin.Context) {
	idStr := c.Param("id")
	integrationID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
		return
	}

	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	// Get hours parameter (default 24)
	hours := 24
	if hoursStr := c.Query("hours"); hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 {
			hours = h
		}
	}

	metrics, err := h.healthService.GetIntegrationHealthMetrics(c.Request.Context(), tenantID, integrationID, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// GetPlatformHealth handles GET /admin/metrics (platform admin only)
func (h *HealthHandlers) GetPlatformHealth(c *gin.Context) {
	summary, err := h.healthService.GetPlatformHealthSummary(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, summary)
}
