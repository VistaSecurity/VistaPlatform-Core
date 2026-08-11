package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

type UnifiedInventoryHandler struct {
	unifiedService *services.UnifiedInventoryService
}

func NewUnifiedInventoryHandler(unifiedService *services.UnifiedInventoryService) *UnifiedInventoryHandler {
	return &UnifiedInventoryHandler{
		unifiedService: unifiedService,
	}
}

// GetUnifiedInventory handles GET /api/v1/inventory-service/crypto-inventory
// Returns a unified view of assets, certificates, and crypto implementations
func (h *UnifiedInventoryHandler) GetUnifiedInventory(c *gin.Context) {
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

	// Parse filters
	var filters models.UnifiedInventoryFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	// Apply shared pagination defaults and bounds
	pg := sharedapi.ParsePagination(c)
	filters.Page = pg.Page
	filters.PageSize = pg.PageSize

	entities, total, summary, err := h.unifiedService.GetUnifiedInventory(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve unified inventory"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entities":   entities,
		"pagination": sharedapi.BuildPaginationMeta(pg, int64(total)),
		"summary":    summary,
	})
}
