package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// remediationStore is the persistence surface the RemediationHandler needs.
// *services.RemediationService is the production implementation; depending on
// the interface (rather than the concrete type) lets the HTTP layer be
// exercised by the contract test with an in-memory stub, no database required
// (mirrors the assetStore + certificateStore + scopeStore + cryptoConfigStore
// pattern). Both Get methods are listed so *services.RemediationService still
// satisfies the interface and cmd/main.go is untouched, even though the
// algorithm-only lookup is not exercised in this contract slice.
type remediationStore interface {
	GetRemediationForCryptoImplementation(ctx context.Context, tenantID, implID uuid.UUID) (*services.RemediationSummary, error)
	GetRemediationGuidanceByAlgorithm(ctx context.Context, algorithmCode string) (*services.RemediationIssue, error)
}

// RemediationHandler handles HTTP requests for remediation guidance
type RemediationHandler struct {
	remediationService remediationStore
}

// NewRemediationHandler creates a new RemediationHandler
func NewRemediationHandler(remediationService remediationStore) *RemediationHandler {
	return &RemediationHandler{
		remediationService: remediationService,
	}
}

// GetRemediationForCryptoImplementation handles GET /api/v1/inventory-service/crypto-implementations/:id/remediation
// Returns detailed remediation guidance for a crypto configuration
func (h *RemediationHandler) GetRemediationForCryptoImplementation(c *gin.Context) {
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

	implIDStr := c.Param("id")
	implID, err := uuid.Parse(implIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid crypto configuration ID"})
		return
	}

	summary, err := h.remediationService.GetRemediationForCryptoImplementation(c.Request.Context(), tenantUUID, implID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get remediation guidance"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"remediation": summary,
	})
}

// GetRemediationByAlgorithm handles GET /api/v1/inventory-service/remediation/algorithm/:code
// Returns remediation guidance for a specific algorithm
func (h *RemediationHandler) GetRemediationByAlgorithm(c *gin.Context) {
	algorithmCode := c.Param("code")
	if algorithmCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Algorithm code is required"})
		return
	}

	guidance, err := h.remediationService.GetRemediationGuidanceByAlgorithm(c.Request.Context(), algorithmCode)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Algorithm not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"remediation": guidance,
	})
}
