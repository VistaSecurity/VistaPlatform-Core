package handlers

import (
	"net/http"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
)

// ComplianceHandlers contains all compliance-related handlers
type ComplianceHandlers struct {
	mappingsService *services.MappingsService
}

// NewComplianceHandlers creates a new instance of compliance handlers
func NewComplianceHandlers(mappingsService *services.MappingsService) *ComplianceHandlers {
	return &ComplianceHandlers{
		mappingsService: mappingsService,
	}
}

// Health handles health check
func (h *ComplianceHandlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "compliance-engine",
		"version": version.Get(),
	})
}
