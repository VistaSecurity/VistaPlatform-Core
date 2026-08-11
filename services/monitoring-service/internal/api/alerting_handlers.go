package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/monitoring-service/internal/models"
)

// GetAlertThresholds handles GET /api/v1/monitoring-service/alerting/thresholds
func (s *Server) GetAlertThresholds(c *gin.Context) {
	serviceName := c.Query("service_name")
	enabledStr := c.Query("enabled")

	var serviceNamePtr *string
	if serviceName != "" {
		serviceNamePtr = &serviceName
	}

	var enabledPtr *bool
	if enabledStr != "" {
		if enabled, err := strconv.ParseBool(enabledStr); err == nil {
			enabledPtr = &enabled
		}
	}

	thresholds, err := s.alertingService.GetAlertThresholds(serviceNamePtr, enabledPtr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get alert thresholds",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"thresholds": thresholds,
		"count":      len(thresholds),
	})
}

// GetAlertThreshold handles GET /api/v1/monitoring-service/alerting/thresholds/:id
func (s *Server) GetAlertThreshold(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid threshold ID"})
		return
	}

	threshold, err := s.alertingService.GetAlertThreshold(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Alert threshold not found",
		})
		return
	}

	c.JSON(http.StatusOK, threshold)
}

// CreateAlertThreshold handles POST /api/v1/monitoring-service/alerting/thresholds
func (s *Server) CreateAlertThreshold(c *gin.Context) {
	var req models.CreateAlertThresholdRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get user ID from context (if available)
	var createdBy *uuid.UUID
	if userIDStr, exists := c.Get("userID"); exists {
		if userID, err := uuid.Parse(userIDStr.(string)); err == nil {
			createdBy = &userID
		}
	}

	threshold, err := s.alertingService.CreateAlertThreshold(&req, createdBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create alert threshold",
		})
		return
	}

	c.JSON(http.StatusCreated, threshold)
}

// UpdateAlertThreshold handles PUT /api/v1/monitoring-service/alerting/thresholds/:id
func (s *Server) UpdateAlertThreshold(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid threshold ID"})
		return
	}

	var req models.UpdateAlertThresholdRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get user ID from context (if available)
	var updatedBy *uuid.UUID
	if userIDStr, exists := c.Get("userID"); exists {
		if userID, err := uuid.Parse(userIDStr.(string)); err == nil {
			updatedBy = &userID
		}
	}

	threshold, err := s.alertingService.UpdateAlertThreshold(id, &req, updatedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update alert threshold",
		})
		return
	}

	c.JSON(http.StatusOK, threshold)
}

// DeleteAlertThreshold handles DELETE /api/v1/monitoring-service/alerting/thresholds/:id
func (s *Server) DeleteAlertThreshold(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid threshold ID"})
		return
	}

	if err := s.alertingService.DeleteAlertThreshold(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete alert threshold",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Alert threshold deleted successfully"})
}

// GetAlertHistory handles GET /api/v1/monitoring-service/alerting/history
func (s *Server) GetAlertHistory(c *gin.Context) {
	serviceName := c.Query("service_name")
	status := c.Query("status")
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")

	var serviceNamePtr *string
	if serviceName != "" {
		serviceNamePtr = &serviceName
	}

	var statusPtr *string
	if status != "" {
		statusPtr = &status
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	alerts, totalCount, err := s.alertingService.GetAlertHistory(serviceNamePtr, statusPtr, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get alert history",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"count":  totalCount,
		"limit":  limit,
		"offset": offset,
	})
}
