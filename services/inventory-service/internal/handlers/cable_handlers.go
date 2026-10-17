package handlers

// HTTP surface of cables and cable traces (DCIM BUILD_PLAN row 3.2), under
// /api/v2/inventory-service/dcim:
//
//	GET    /cables                         dcim.read    list (site_id, rack_id, location_id, asset_id,
//	                                                    type, operational_status, status,
//	                                                    termination_kind, termination_id, q, limit, offset)
//	POST   /cables                         dcim.manage  create with a_terminations / b_terminations
//	GET    /cables/{id}                    dcim.read
//	PATCH  /cables/{id}                    dcim.manage  columns, and either end replaced
//	DELETE /cables/{id}                    dcim.manage
//	POST   /cables/{id}/approve            dcim.manage  a proposed (pending) cable → active, paths recomputed
//	POST   /cables/{id}/reject             dcim.manage  a proposed cable → rejected (row 3.3)
//	GET    /{kind}/{id}/trace              dcim.read    kind: interfaces, front-ports, rear-ports,
//	                                                    console-ports, console-server-ports,
//	                                                    circuit-terminations
//	GET    /assets/{id}/interface-posture  dcim.read    the faceplate's crypto overlay (row 3.4)
//
// Envelope and error codes are IPAM's (ipam_handlers.go). Gates are mounted
// with the routes (cmd/dcim_cable_routes.go).

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// CableStore is what the handlers need; services.CableService implements it.
type CableStore interface {
	List(ctx context.Context, tenant uuid.UUID, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant, id uuid.UUID) error
	Approve(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error)
	Reject(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error)
	Trace(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) (services.TraceResult, error)
	InterfacePosture(ctx context.Context, tenant, asset uuid.UUID) (services.AssetInterfacePosture, error)
}

// CableHandler serves the cable routes.
type CableHandler struct {
	store CableStore
}

// NewCableHandler returns the handler over store.
func NewCableHandler(store CableStore) *CableHandler { return &CableHandler{store: store} }

// List is GET /dcim/cables.
func (h *CableHandler) List(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	p, ok := catalogueListParams(c)
	if !ok {
		return
	}
	rows, total, err := h.store.List(c.Request.Context(), tenant, p)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, p.Limit, p.Offset)})
}

// Get is GET /dcim/cables/{id}.
func (h *CableHandler) Get(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	row, err := h.store.Get(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": row})
}

// Create is POST /dcim/cables.
func (h *CableHandler) Create(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	body, ok := ipamBody(c)
	if !ok {
		return
	}
	row, err := h.store.Create(c.Request.Context(), tenant, body)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": row})
}

// Update is PATCH /dcim/cables/{id}.
func (h *CableHandler) Update(c *gin.Context) {
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
	row, err := h.store.Update(c.Request.Context(), tenant, id, body)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": row})
}

// Delete is DELETE /dcim/cables/{id}.
func (h *CableHandler) Delete(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	if err := h.store.Delete(c.Request.Context(), tenant, id); err != nil {
		ipamStoreError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Approve is POST /dcim/cables/{id}/approve: accept an LLDP / CDP proposal.
func (h *CableHandler) Approve(c *gin.Context) { h.decide(c, h.store.Approve) }

// Reject is POST /dcim/cables/{id}/reject: refuse an LLDP / CDP proposal.
func (h *CableHandler) Reject(c *gin.Context) { h.decide(c, h.store.Reject) }

func (h *CableHandler) decide(c *gin.Context, fn func(context.Context, uuid.UUID, uuid.UUID) (json.RawMessage, error)) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	row, err := fn(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": row})
}

// Trace is GET /dcim/{kind}/{id}/trace for one termination route segment.
func (h *CableHandler) Trace(route string) gin.HandlerFunc {
	kind, known := services.TraceRoutes[route]
	return func(c *gin.Context) {
		if !known {
			ipamError(c, http.StatusNotFound, "not_found", "no trace for "+route)
			return
		}
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		id, ok := ipamID(c)
		if !ok {
			return
		}
		res, err := h.store.Trace(c.Request.Context(), tenant, kind, id)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": res})
	}
}

// InterfacePosture is GET /dcim/assets/{id}/interface-posture (row 3.4): per
// interface, the crypto observed behind it, and the asset's worst open finding.
func (h *CableHandler) InterfacePosture(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	res, err := h.store.InterfacePosture(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res})
}
