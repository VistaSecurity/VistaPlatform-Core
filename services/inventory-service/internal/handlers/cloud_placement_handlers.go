// Package handlers: a cloud resource's placement (asset-inventory ADR-0009 D7,
// DCIM row 4.6) — the asset page's Placement breadcrumb.
package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type cloudPlacementStore interface {
	GetCloudPlacement(ctx context.Context, tenantID, assetID uuid.UUID) (*services.CloudPlacement, error)
}

// CloudPlacementHandler serves GET /infrastructure-assets/:id/cloud-placement.
type CloudPlacementHandler struct {
	assets cloudPlacementStore
}

// NewCloudPlacementHandler wires the handler.
func NewCloudPlacementHandler(assets cloudPlacementStore) *CloudPlacementHandler {
	return &CloudPlacementHandler{assets: assets}
}

// GetCloudPlacement answers the placement of one cloud resource: 404 for an
// asset that does not exist (or is another tenant's), 422 for one that is not a
// cloud resource.
func (h *CloudPlacementHandler) GetCloudPlacement(c *gin.Context) {
	tenantUUID, ok := c.Get("tenantID")
	tid, ok2 := tenantUUID.(uuid.UUID)
	if !ok || !ok2 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}
	p, err := h.assets.GetCloudPlacement(c.Request.Context(), tid, assetID)
	switch {
	case errors.Is(err, services.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	case errors.Is(err, services.ErrNotCloudResource):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Placement is only recorded for cloud resources"})
		return
	case err != nil:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the placement", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"placement": p})
}
