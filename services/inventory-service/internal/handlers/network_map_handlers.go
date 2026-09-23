// Package handlers: the tenant-wide network map (feature spec
// `network-crypto-map`).
package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// networkMapStore is the one method this handler calls — narrow so the
// contract test can drive the real handler with an in-memory stub.
type networkMapStore interface {
	GetNetworkMap(ctx context.Context, tenantID uuid.UUID) (*services.NetworkMap, error)
}

// NetworkMapHandler serves GET /infrastructure-assets/network-map.
type NetworkMapHandler struct {
	assets networkMapStore
}

// NewNetworkMapHandler wires the handler.
func NewNetworkMapHandler(assets networkMapStore) *NetworkMapHandler {
	return &NetworkMapHandler{assets: assets}
}

// GetNetworkMap handles GET /infrastructure-assets/network-map.
//
// No parameters, like the topology: the map is one answer, bounded by a cap
// the response reports (`truncated`, `total_assets`, `asset_cap`) rather than
// by paging, so a tenant past the cap is told rather than silently shown less.
func (h *NetworkMapHandler) GetNetworkMap(c *gin.Context) {
	tenantID, ok := c.Get("tenantID")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	networkMap, err := h.assets.GetNetworkMap(c.Request.Context(), tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to build the network map",
			"message": err.Error(),
		})
		return
	}
	// An empty estate is 200 with empty arrays — the state every tenant starts
	// in, which the view renders as "Nothing discovered yet".
	c.JSON(http.StatusOK, gin.H{"network_map": networkMap})
}
