package handlers

import (
	"net/http"

	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
)

// ComplianceHandlers contains all compliance-related handlers
type ComplianceHandlers struct{}

// NewComplianceHandlers creates a new instance of compliance handlers
func NewComplianceHandlers() *ComplianceHandlers {
	return &ComplianceHandlers{}
}

// Health handles health check
func (h *ComplianceHandlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "compliance-engine",
		"version": version.Get(),
	})
}
