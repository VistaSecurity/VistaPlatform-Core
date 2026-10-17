package handlers

// HTTP surface of config contexts (DCIM BUILD_PLAN row 5.3), under
// /api/v2/inventory-service/dcim:
//
//	GET|POST         /config-contexts
//	GET|PATCH|DELETE /config-contexts/{id}
//	GET              /assets/{id}/config-context   the asset's merged config + contributors
//
// reads behind dcim.read, writes behind dcim.manage (cmd/dcim_config_context_routes.go).
// Envelope and error codes are IPAM's (ipam_handlers.go).

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// ConfigContextStore is what the handlers need; services.ConfigContextService implements it.
type ConfigContextStore interface {
	List(ctx context.Context, tenant uuid.UUID, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant, id uuid.UUID) error
	Render(ctx context.Context, tenant, assetID uuid.UUID) (services.RenderedConfigContext, error)
}

// ConfigContextHandler serves the config-context routes.
type ConfigContextHandler struct{ store ConfigContextStore }

// NewConfigContextHandler returns the handler over store.
func NewConfigContextHandler(store ConfigContextStore) *ConfigContextHandler {
	return &ConfigContextHandler{store: store}
}

// List is GET /config-contexts.
func (h *ConfigContextHandler) List(c *gin.Context) {
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

// Get is GET /config-contexts/{id}.
func (h *ConfigContextHandler) Get(c *gin.Context) {
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

// Create is POST /config-contexts.
func (h *ConfigContextHandler) Create(c *gin.Context) {
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

// Update is PATCH /config-contexts/{id}.
func (h *ConfigContextHandler) Update(c *gin.Context) {
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

// Delete is DELETE /config-contexts/{id}.
func (h *ConfigContextHandler) Delete(c *gin.Context) {
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

// Render is GET /assets/{id}/config-context.
func (h *ConfigContextHandler) Render(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	out, err := h.store.Render(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}
