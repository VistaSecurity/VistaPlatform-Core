package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// alertService is the narrow surface of *services.AlertService the handlers use,
// so they can run over an in-memory stub in the contract test (ADR-0001). The
// concrete service satisfies it; NewAlertHandler is unchanged.
type alertService interface {
	GetRules(ctx context.Context) []services.AlertRule
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
