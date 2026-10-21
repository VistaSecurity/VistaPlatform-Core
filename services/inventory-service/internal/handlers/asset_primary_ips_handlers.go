package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// AssetPrimaryIPStore is what the primary-ips route needs.
type AssetPrimaryIPStore interface {
	Update(ctx context.Context, tenant, asset uuid.UUID, patch services.AssetPrimaryIPsPatch) (*services.AssetPrimaryIPs, error)
}

// AssetPrimaryIPHandler serves PATCH /dcim/assets/{id}/primary-ips.
type AssetPrimaryIPHandler struct{ store AssetPrimaryIPStore }

// NewAssetPrimaryIPHandler returns the handler over store.
func NewAssetPrimaryIPHandler(store AssetPrimaryIPStore) *AssetPrimaryIPHandler {
	return &AssetPrimaryIPHandler{store: store}
}

// Update sets, moves or clears the asset's primary IPv4, primary IPv6 and
// out-of-band addresses.
func (h *AssetPrimaryIPHandler) Update(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	body, ok := ipamBody(c)
	if !ok {
		return
	}
	var patch services.AssetPrimaryIPsPatch
	if err := json.Unmarshal(body, &patch); err != nil || patch == nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
		return
	}
	out, err := h.store.Update(c.Request.Context(), tenant, id, patch)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}
