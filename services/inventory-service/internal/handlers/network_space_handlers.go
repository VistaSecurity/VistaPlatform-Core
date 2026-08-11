package handlers

import (
	"net/http"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type NetworkSpaceHandler struct {
	networkSpaceService   *services.NetworkSpaceService
	networkSegmentService *services.NetworkSegmentService // optional: for legacy proxy to segments
}

func NewNetworkSpaceHandler(networkSpaceService *services.NetworkSpaceService) *NetworkSpaceHandler {
	return &NetworkSpaceHandler{networkSpaceService: networkSpaceService}
}

// SetNetworkSegmentService sets the segment service for legacy proxy (ReclassifyAssets, SaveNetworkSpaces sync).
func (h *NetworkSpaceHandler) SetNetworkSegmentService(svc *services.NetworkSegmentService) {
	h.networkSegmentService = svc
}

// GetNetworkSpaces handles GET /api/v1/network-spaces (deprecated: use GET /api/v2/inventory-service/network-segments).
func (h *NetworkSpaceHandler) GetNetworkSpaces(c *gin.Context) {
	c.Header("X-Deprecated", "Use /api/v2/inventory-service/network-segments")
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

	spaces, err := h.networkSpaceService.GetNetworkSpaces(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get network spaces"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"network_spaces": spaces})
}

// SaveNetworkSpaces handles POST /api/v1/network-spaces
func (h *NetworkSpaceHandler) SaveNetworkSpaces(c *gin.Context) {
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
		// Try to parse as string if it's not a UUID
		if userIDStr, okStr := userID.(string); okStr {
			var err error
			userUUID, err = uuid.Parse(userIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}
	}

	var request struct {
		NetworkSpaces []struct {
			ID                     string                 `json:"id" binding:"required"`
			Type                   string                 `json:"type" binding:"required"`
			Value                  string                 `json:"value" binding:"required"`
			NetworkType            string                 `json:"network_type" binding:"required"`
			Description            string                 `json:"description"`
			IsActive               bool                   `json:"is_active"`
			Tags                   map[string]interface{} `json:"tags"`
			AutoApproveDiscoveries *bool                  `json:"auto_approve_discoveries,omitempty"`
		} `json:"network_spaces" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Convert to service model
	spaces := make([]models.NetworkSpace, len(request.NetworkSpaces))
	for i, ns := range request.NetworkSpaces {
		spaces[i] = models.NetworkSpace{
			ID:                     ns.ID,
			Type:                   ns.Type,
			Value:                  ns.Value,
			NetworkType:            ns.NetworkType,
			Description:            ns.Description,
			IsActive:               ns.IsActive,
			Tags:                   ns.Tags,
			AutoApproveDiscoveries: ns.AutoApproveDiscoveries,
		}
	}

	err := h.networkSpaceService.SaveNetworkSpaces(tenantUUID, userUUID, spaces)
	if err != nil {
		// Log failure
		if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok {
			for _, space := range spaces {
				_ = audithelpers.LogSimple(
					c.Request.Context(),
					mw,
					audithelpers.EventTypeNetworkSpaceCreated,
					audithelpers.EventCategoryAsset,
					"create",
					"network_space",
					space.ID,
					space.Value,
					false,
					err.Error(),
				)
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save network spaces"})
		return
	}

	// Log success for each network space
	if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok {
		for _, space := range spaces {
			_ = audithelpers.LogWithContext(
				c.Request.Context(),
				mw,
				audithelpers.EventTypeNetworkSpaceCreated,
				audithelpers.EventCategoryAsset,
				"create",
				"network_space",
				space.ID,
				space.Value,
				nil, // old values (new creation)
				space,
				audithelpers.AuditMetadata{
					ResourceName:    space.Value,
					BusinessContext: space.Description,
					ChangeSummary:   "Network space created with type: " + space.NetworkType,
					AdditionalData: map[string]interface{}{
						"network_type":             space.NetworkType,
						"auto_approve_discoveries": space.AutoApproveDiscoveries,
						"is_active":                space.IsActive,
					},
				},
			)
		}
	}

	// Sync to network_segments for backward compat so segment-based flows see the same data
	if h.networkSegmentService != nil {
		_, _ = h.networkSegmentService.MigrateFromNetworkSpaces(tenantUUID)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Network spaces saved successfully"})
}

// ReclassifyAssets handles POST /api/v1/network-spaces/classify-assets. Proxies to network segments reclassify-all.
func (h *NetworkSpaceHandler) ReclassifyAssets(c *gin.Context) {
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

	var updatedCount int
	var err error
	if h.networkSegmentService != nil {
		updatedCount, err = h.networkSegmentService.ReclassifyAllAssets(tenantUUID)
	} else {
		updatedCount, err = h.networkSpaceService.ReclassifyAllAssets(tenantUUID)
	}
	if err != nil {
		// Log failure
		if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok {
			_ = audithelpers.LogSimple(
				c.Request.Context(),
				mw,
				audithelpers.EventTypeNetworkSpaceAssetTagged,
				audithelpers.EventCategoryAsset,
				"bulk_classify",
				"network_space",
				"",
				"all_assets",
				false,
				err.Error(),
			)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reclassify assets"})
		return
	}

	// Log success
	if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok {
		_ = audithelpers.LogSimple(
			c.Request.Context(),
			mw,
			audithelpers.EventTypeNetworkSpaceAssetTagged,
			audithelpers.EventCategoryAsset,
			"bulk_classify",
			"network_space",
			"",
			"all_assets",
			true,
			"",
		)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Assets reclassified successfully", "updated_count": updatedCount})
}
