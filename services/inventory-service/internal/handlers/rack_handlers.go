package handlers

// HTTP surface of racks and placement (DCIM BUILD_PLAN row 2.3), under
// /api/v2/inventory-service/dcim:
//
//	GET    /{object}                      dcim.read    list (filters, q, limit, offset)
//	POST   /{object}                      dcim.manage
//	GET    /{object}/{id}                 dcim.read
//	PATCH  /{object}/{id}                 dcim.manage  a platform rack role/type answers 403 read_only
//	DELETE /{object}/{id}                 dcim.manage
//	GET    /racks/{id}/elevation          dcim.read    per-unit occupancy, reservations, utilisation
//	GET    /assets/{id}/placement         dcim.read    the asset's Placement card
//	PUT    /assets/{id}/placement         dcim.manage  {rack_id, position, face}
//	DELETE /assets/{id}/placement         dcim.manage  take the asset out of its rack
//
// {object} is rack-roles, rack-types, racks, rack-reservations. Envelope and
// error codes are IPAM's (ipam_handlers.go), plus `placement_conflict` (409)
// whose body names the asset or reservation in the way. Gates are mounted with
// the routes (cmd/rack_routes.go).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// RackStore is the rack object CRUD; services.RackService implements it.
type RackStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
}

// PlacementStore is placement and elevation; services.PlacementService
// implements it.
type PlacementStore interface {
	Get(ctx context.Context, tenant, asset uuid.UUID) (*services.AssetPlacement, error)
	Place(ctx context.Context, tenant, asset uuid.UUID, in services.PlaceInput) (*services.AssetPlacement, error)
	Unplace(ctx context.Context, tenant, asset uuid.UUID) (*services.AssetPlacement, error)
	Elevation(ctx context.Context, tenant, rack uuid.UUID) (*services.RackElevation, error)
	ElevationPosture(ctx context.Context, tenant, rack uuid.UUID) (map[uuid.UUID]*services.DevicePosture, error)
}

// RackHandler serves the rack and placement routes.
type RackHandler struct {
	racks     RackStore
	placement PlacementStore
}

// NewRackHandler returns the handler.
func NewRackHandler(racks RackStore, placement PlacementStore) *RackHandler {
	return &RackHandler{racks: racks, placement: placement}
}

// rackStoreError is ipamStoreError plus the placement conflict's details.
func rackStoreError(c *gin.Context, err error) {
	var pc *services.PlacementConflictError
	if errors.As(err, &pc) {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": gin.H{
			"code": "placement_conflict", "message": pc.Message,
			"blocking_asset": pc.BlockingAsset, "blocking_reservation": pc.BlockingReservation,
		}})
		return
	}
	ipamStoreError(c, err)
}

// List returns the list handler for one rack object.
func (h *RackHandler) List(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		p, ok := catalogueListParams(c)
		if !ok {
			return
		}
		rows, total, err := h.racks.List(c.Request.Context(), tenant, route, p)
		if err != nil {
			rackStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, p.Limit, p.Offset)})
	}
}

// Get returns the single-object handler for one rack object.
func (h *RackHandler) Get(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		id, ok := ipamID(c)
		if !ok {
			return
		}
		row, err := h.racks.Get(c.Request.Context(), tenant, route, id)
		if err != nil {
			rackStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": row})
	}
}

// Create returns the create handler for one rack object.
func (h *RackHandler) Create(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		body, ok := ipamBody(c)
		if !ok {
			return
		}
		row, err := h.racks.Create(c.Request.Context(), tenant, route, body)
		if err != nil {
			rackStoreError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"data": row})
	}
}

// Update returns the PATCH handler for one rack object.
func (h *RackHandler) Update(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
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
		row, err := h.racks.Update(c.Request.Context(), tenant, route, id, body)
		if err != nil {
			rackStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": row})
	}
}

// Delete returns the delete handler for one rack object.
func (h *RackHandler) Delete(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		id, ok := ipamID(c)
		if !ok {
			return
		}
		if err := h.racks.Delete(c.Request.Context(), tenant, route, id); err != nil {
			rackStoreError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// Elevation is GET /dcim/racks/{id}/elevation.
func (h *RackHandler) Elevation(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	e, err := h.placement.Elevation(c.Request.Context(), tenant, id)
	if err != nil {
		rackStoreError(c, err)
		return
	}
	// include=posture (DCIM row 2.5): the crypto overlay's per-device read,
	// batched by rack so the elevation does not fan out a request per block.
	if includes(c.Query("include"), "posture") {
		posture, err := h.placement.ElevationPosture(c.Request.Context(), tenant, id)
		if err != nil {
			rackStoreError(c, err)
			return
		}
		for i := range e.Devices {
			if p, ok := posture[e.Devices[i].AssetID]; ok {
				e.Devices[i].Posture = p
			} else {
				e.Devices[i].Posture = &services.DevicePosture{}
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": e})
}

// GetPlacement is GET /dcim/assets/{id}/placement.
func (h *RackHandler) GetPlacement(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	p, err := h.placement.Get(c.Request.Context(), tenant, id)
	if err != nil {
		rackStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": p})
}

// Place is PUT /dcim/assets/{id}/placement {"rack_id", "position", "face"}.
func (h *RackHandler) Place(c *gin.Context) {
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
	var req struct {
		RackID   string   `json:"rack_id"`
		Position *float64 `json:"position"`
		Face     string   `json:"face"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "body must be {rack_id, position, face}")
		return
	}
	rack, err := uuid.Parse(req.RackID)
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "rack_id must be a UUID.")
		return
	}
	if req.Position == nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "position is required.")
		return
	}
	p, err := h.placement.Place(c.Request.Context(), tenant, id, services.PlaceInput{RackID: rack, Position: *req.Position, Face: req.Face})
	if err != nil {
		rackStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": p})
}

// Unplace is DELETE /dcim/assets/{id}/placement.
func (h *RackHandler) Unplace(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	p, err := h.placement.Unplace(c.Request.Context(), tenant, id)
	if err != nil {
		rackStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": p})
}

// includes reports whether the comma-separated include list names want.
func includes(list, want string) bool {
	for _, part := range strings.Split(list, ",") {
		if strings.TrimSpace(part) == want {
			return true
		}
	}
	return false
}
