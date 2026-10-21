package handlers

// HTTP surface of power panels and power feeds (DCIM BUILD_PLAN row 6.1;
// ADR-0010 D9), under /api/v2/inventory-service/dcim:
//
//	GET    /{object}                  dcim.read    list (filters, q, limit, offset)
//	POST   /{object}                  dcim.manage
//	GET    /{object}/{id}             dcim.read
//	PATCH  /{object}/{id}             dcim.manage
//	DELETE /{object}/{id}             dcim.manage
//	GET    /assets/{id}/power         dcim.read    the asset's power ports, outlets and the feeds they reach
//	GET    /racks/{id}/power          dcim.read    the rack's power budget (row 6.2)
//
// {object} is power-panels, power-feeds. The traces of power ports, outlets
// and feeds are cable routes (cable_handlers.go). Envelope and error codes are
// IPAM's (ipam_handlers.go). Gates are mounted with the routes
// (cmd/dcim_power_routes.go).

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// PowerStore is what the handlers need; services.PowerService implements it.
type PowerStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
	AssetPower(ctx context.Context, tenant, asset uuid.UUID) (*services.AssetPowerSummary, error)
	RackPower(ctx context.Context, tenant, rack uuid.UUID) (*services.RackPowerBudget, error)
}

// PowerHandler serves the power routes.
type PowerHandler struct {
	store PowerStore
	crud  *RackHandler
}

// NewPowerHandler returns the handler over store. The CRUD envelope is the
// rack objects' (the same engine, the same error mapping).
func NewPowerHandler(store PowerStore) *PowerHandler {
	return &PowerHandler{store: store, crud: NewRackHandler(store, nil)}
}

// List is GET /dcim/{object}.
func (h *PowerHandler) List(route string) gin.HandlerFunc { return h.crud.List(route) }

// Get is GET /dcim/{object}/{id}.
func (h *PowerHandler) Get(route string) gin.HandlerFunc { return h.crud.Get(route) }

// Create is POST /dcim/{object}.
func (h *PowerHandler) Create(route string) gin.HandlerFunc { return h.crud.Create(route) }

// Update is PATCH /dcim/{object}/{id}.
func (h *PowerHandler) Update(route string) gin.HandlerFunc { return h.crud.Update(route) }

// Delete is DELETE /dcim/{object}/{id}.
func (h *PowerHandler) Delete(route string) gin.HandlerFunc { return h.crud.Delete(route) }

// AssetPower is GET /dcim/assets/{id}/power.
func (h *PowerHandler) AssetPower(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	out, err := h.store.AssetPower(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// RackPower is GET /dcim/racks/{id}/power.
func (h *PowerHandler) RackPower(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	out, err := h.store.RackPower(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}
