package handlers

// HTTP surface of DCIM BUILD_PLAN row 2.4's hardware objects, under
// /api/v2/inventory-service/dcim. CRUD for module bays, modules, inventory item
// roles, inventory items and virtual chassis is the component handler
// (component_handlers.go) over services.HardwareService — POST /modules
// installs a module (instantiating its module type's templates), DELETE
// /modules/{id} removes it (keeping measured components). This file adds the
// virtual chassis membership routes:
//
//	GET    /virtual-chassis/{id}/members                  dcim.read
//	POST   /virtual-chassis/{id}/members                  dcim.manage  {asset_id, vc_position, vc_priority}
//	DELETE /virtual-chassis/{id}/members/{asset_id}       dcim.manage
//	GET    /assets/{id}/virtual-chassis                   dcim.read    the asset's chassis and members
//
// Gates are mounted with the routes (cmd/dcim_hardware_routes.go).

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// VirtualChassisStore is what the membership handlers need;
// services.HardwareService implements it.
type VirtualChassisStore interface {
	VirtualChassisMembers(ctx context.Context, tenant, vc uuid.UUID) ([]services.VirtualChassisMember, error)
	AddVirtualChassisMember(ctx context.Context, tenant, vc uuid.UUID, in services.VirtualChassisMemberInput) ([]services.VirtualChassisMember, error)
	RemoveVirtualChassisMember(ctx context.Context, tenant, vc, asset uuid.UUID) error
	AssetVirtualChassis(ctx context.Context, tenant, asset uuid.UUID) (*services.AssetVirtualChassis, error)
}

// VirtualChassisHandler serves the membership routes.
type VirtualChassisHandler struct {
	store VirtualChassisStore
}

// NewVirtualChassisHandler returns the handler over store.
func NewVirtualChassisHandler(store VirtualChassisStore) *VirtualChassisHandler {
	return &VirtualChassisHandler{store: store}
}

// Members is GET /dcim/virtual-chassis/{id}/members.
func (h *VirtualChassisHandler) Members(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	out, err := h.store.VirtualChassisMembers(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// AddMember is POST /dcim/virtual-chassis/{id}/members.
func (h *VirtualChassisHandler) AddMember(c *gin.Context) {
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
	var in services.VirtualChassisMemberInput
	if err := json.Unmarshal(body, &in); err != nil || in.AssetID == uuid.Nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "The body must name an asset_id (UUID), and may give vc_position and vc_priority (0-255).")
		return
	}
	out, err := h.store.AddVirtualChassisMember(c.Request.Context(), tenant, id, in)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// RemoveMember is DELETE /dcim/virtual-chassis/{id}/members/{asset_id}.
func (h *VirtualChassisHandler) RemoveMember(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	asset, err := uuid.Parse(c.Param("asset_id"))
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_id", "asset_id must be a UUID.")
		return
	}
	if err := h.store.RemoveVirtualChassisMember(c.Request.Context(), tenant, id, asset); err != nil {
		ipamStoreError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ForAsset is GET /dcim/assets/{id}/virtual-chassis.
func (h *VirtualChassisHandler) ForAsset(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	out, err := h.store.AssetVirtualChassis(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}
