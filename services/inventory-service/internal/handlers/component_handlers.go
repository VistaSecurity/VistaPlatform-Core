package handlers

// HTTP surface of the asset components beyond interfaces (DCIM BUILD_PLAN row
// 3.1), under /api/v2/inventory-service/dcim:
//
//	GET    /{kind}                       dcim.read    list (filters, q, limit, offset)
//	POST   /{kind}                       dcim.manage  declare one (the body names its asset)
//	GET    /{kind}/{id}                  dcim.read
//	PATCH  /{kind}/{id}                  dcim.manage
//	DELETE /{kind}/{id}                  dcim.manage
//	GET    /assets/{id}/{kind}           dcim.read    one asset's components of the kind
//	POST   /assets/{id}/{kind}           dcim.manage  declare one on the asset
//
// {kind} is console-ports, console-server-ports, front-ports, rear-ports,
// device-bays, power-ports, power-outlets. Envelope and error codes are IPAM's
// (ipam_handlers.go). Gates are mounted with the routes
// (cmd/dcim_component_routes.go).

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// ComponentStore is what the handlers need; services.ComponentService
// implements it.
type ComponentStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	ListForAsset(ctx context.Context, tenant, asset uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	CreateForAsset(ctx context.Context, tenant, asset uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
}

// ComponentHandler serves the component routes.
type ComponentHandler struct {
	store ComponentStore
}

// NewComponentHandler returns the handler over store.
func NewComponentHandler(store ComponentStore) *ComponentHandler {
	return &ComponentHandler{store: store}
}

// List is GET /dcim/{kind}.
func (h *ComponentHandler) List(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		p, ok := catalogueListParams(c)
		if !ok {
			return
		}
		rows, total, err := h.store.List(c.Request.Context(), tenant, route, p)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, p.Limit, p.Offset)})
	}
}

// ListForAsset is GET /dcim/assets/{id}/{kind}.
func (h *ComponentHandler) ListForAsset(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		asset, ok := ipamID(c)
		if !ok {
			return
		}
		p, ok := catalogueListParams(c)
		if !ok {
			return
		}
		rows, total, err := h.store.ListForAsset(c.Request.Context(), tenant, asset, route, p)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, p.Limit, p.Offset)})
	}
}

// Get is GET /dcim/{kind}/{id}.
func (h *ComponentHandler) Get(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		id, ok := ipamID(c)
		if !ok {
			return
		}
		row, err := h.store.Get(c.Request.Context(), tenant, route, id)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": row})
	}
}

// Create is POST /dcim/{kind}.
func (h *ComponentHandler) Create(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		body, ok := ipamBody(c)
		if !ok {
			return
		}
		row, err := h.store.Create(c.Request.Context(), tenant, route, body)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"data": row})
	}
}

// CreateForAsset is POST /dcim/assets/{id}/{kind}.
func (h *ComponentHandler) CreateForAsset(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		asset, ok := ipamID(c)
		if !ok {
			return
		}
		body, ok := ipamBody(c)
		if !ok {
			return
		}
		row, err := h.store.CreateForAsset(c.Request.Context(), tenant, asset, route, body)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"data": row})
	}
}

// Update is PATCH /dcim/{kind}/{id}.
func (h *ComponentHandler) Update(route string) gin.HandlerFunc {
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
		row, err := h.store.Update(c.Request.Context(), tenant, route, id, body)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": row})
	}
}

// Delete is DELETE /dcim/{kind}/{id}.
func (h *ComponentHandler) Delete(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		id, ok := ipamID(c)
		if !ok {
			return
		}
		if err := h.store.Delete(c.Request.Context(), tenant, route, id); err != nil {
			ipamStoreError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}
