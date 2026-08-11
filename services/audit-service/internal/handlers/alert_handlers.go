package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// alertService is the narrow surface of *services.AlertService the handlers use,
// so they can run over an in-memory stub in the contract test (ADR-0001). The
// concrete service satisfies it; NewAlertHandler is unchanged.
type alertService interface {
	GetRules(ctx context.Context) []services.AlertRule
	GetAlerts(ctx context.Context, status string, limit int) ([]services.Alert, error)
	AcknowledgeAlert(ctx context.Context, alertID uuid.UUID, userID uuid.UUID) error
}

type AlertHandler struct {
	service alertService
}

func NewAlertHandler(service *services.AlertService) *AlertHandler {
	return &AlertHandler{service: service}
}

// GetAlertRules handles GET /api/v1/audit-service/alerts/rules
func (h *AlertHandler) GetAlertRules(c *gin.Context) {
	rules := h.service.GetRules(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// GetAlerts handles GET /api/v1/audit-service/alerts
func (h *AlertHandler) GetAlerts(c *gin.Context) {
	status := c.DefaultQuery("status", "open")
	limit := 100

	alerts, err := h.service.GetAlerts(c.Request.Context(), status, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"alerts": alerts})
}

// AcknowledgeAlert handles POST /api/v1/audit-service/alerts/:id/acknowledge
func (h *AlertHandler) AcknowledgeAlert(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert ID"})
		return
	}

	// Get user ID from context
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var userID uuid.UUID
	switch v := userIDVal.(type) {
	case uuid.UUID:
		userID = v
	case string:
		userID, err = uuid.Parse(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}
	}

	err = h.service.AcknowledgeAlert(c.Request.Context(), id, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to acknowledge alert"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Alert acknowledged"})
}
