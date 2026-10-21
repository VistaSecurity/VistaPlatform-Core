package handlers

// HTTP surface of DCIM gap 8 (spares, stock and RMA), under
// /api/v2/inventory-service/dcim. A spare is an inventory item with no asset
// (the inventory item CRUD serves it; ?stock_state=, ?location_id=, ?site_id=
// and ?asset_id=null filter the stock); this file adds the transitions and the
// RMA cases (services/spares_service.go):
//
//	POST  /inventory-items/{id}/install   dcim.manage  {asset_id, module_bay_id?, parent_id?, name?, quantity?}
//	POST  /inventory-items/{id}/remove    dcim.manage  {location_id, name?, stock_state?}
//	POST  /inventory-items/{id}/rma       dcim.manage  {vendor?, case_number?, opened_at?, notes?, location_id?}
//	GET   /rma-cases                      dcim.read    list (state, inventory_item_id, open, q, limit, offset)
//	GET   /rma-cases/{id}                 dcim.read
//	PATCH /rma-cases/{id}                 dcim.manage  state, dates, vendor, case number, replacement, notes
//
// Gates are mounted with the routes (cmd/dcim_hardware_routes.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// SparesStore is what the spares handlers need; services.SparesService
// implements it.
type SparesStore interface {
	Install(ctx context.Context, tenant, id uuid.UUID, in services.SpareInstallInput) (*services.SpareResult, error)
	Remove(ctx context.Context, tenant, id uuid.UUID, in services.SpareRemoveInput) (*services.SpareResult, error)
	OpenRMA(ctx context.Context, tenant, id uuid.UUID, in services.SpareRMAInput) (*services.SpareResult, error)
	ListRMACases(ctx context.Context, tenant uuid.UUID, p services.IPAMListParams) ([]json.RawMessage, int, error)
	GetRMACase(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error)
	UpdateRMACase(ctx context.Context, tenant, id uuid.UUID, body []byte) (json.RawMessage, error)
}

// SparesHandler serves the spares routes.
type SparesHandler struct {
	store SparesStore
}

// NewSparesHandler returns the handler over store.
func NewSparesHandler(store SparesStore) *SparesHandler {
	return &SparesHandler{store: store}
}

// decodeSpareBody reads a JSON object into v, refusing unknown fields.
func decodeSpareBody(body []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil
}

func (h *SparesHandler) action(c *gin.Context, run func(ctx context.Context, tenant, id uuid.UUID, body []byte) (*services.SpareResult, bool, error)) {
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
	out, valid, err := run(c.Request.Context(), tenant, id, body)
	if !valid {
		return
	}
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// Install is POST /dcim/inventory-items/{id}/install.
func (h *SparesHandler) Install(c *gin.Context) {
	h.action(c, func(ctx context.Context, tenant, id uuid.UUID, body []byte) (*services.SpareResult, bool, error) {
		var in services.SpareInstallInput
		if !decodeSpareBody(body, &in) || in.AssetID == uuid.Nil {
			ipamError(c, http.StatusBadRequest, "invalid_request", "The body must name an asset_id (UUID), and may give module_bay_id, parent_id, name and quantity.")
			return nil, false, nil
		}
		out, err := h.store.Install(ctx, tenant, id, in)
		return out, true, err
	})
}

// Remove is POST /dcim/inventory-items/{id}/remove.
func (h *SparesHandler) Remove(c *gin.Context) {
	h.action(c, func(ctx context.Context, tenant, id uuid.UUID, body []byte) (*services.SpareResult, bool, error) {
		var in services.SpareRemoveInput
		if !decodeSpareBody(body, &in) || in.LocationID == uuid.Nil {
			ipamError(c, http.StatusBadRequest, "invalid_request", "The body must name a location_id (UUID), and may give name and stock_state (in_stock or reserved).")
			return nil, false, nil
		}
		out, err := h.store.Remove(ctx, tenant, id, in)
		return out, true, err
	})
}

// OpenRMA is POST /dcim/inventory-items/{id}/rma.
func (h *SparesHandler) OpenRMA(c *gin.Context) {
	h.action(c, func(ctx context.Context, tenant, id uuid.UUID, body []byte) (*services.SpareResult, bool, error) {
		var in services.SpareRMAInput
		if !decodeSpareBody(body, &in) {
			ipamError(c, http.StatusBadRequest, "invalid_request", "The body may give vendor, case_number, opened_at (YYYY-MM-DD), notes and location_id.")
			return nil, false, nil
		}
		out, err := h.store.OpenRMA(ctx, tenant, id, in)
		return out, true, err
	})
}

// ListRMACases is GET /dcim/rma-cases.
func (h *SparesHandler) ListRMACases(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	p, ok := catalogueListParams(c)
	if !ok {
		return
	}
	rows, total, err := h.store.ListRMACases(c.Request.Context(), tenant, p)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, p.Limit, p.Offset)})
}

// GetRMACase is GET /dcim/rma-cases/{id}.
func (h *SparesHandler) GetRMACase(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	out, err := h.store.GetRMACase(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// UpdateRMACase is PATCH /dcim/rma-cases/{id}.
func (h *SparesHandler) UpdateRMACase(c *gin.Context) {
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
	out, err := h.store.UpdateRMACase(c.Request.Context(), tenant, id, body)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}
