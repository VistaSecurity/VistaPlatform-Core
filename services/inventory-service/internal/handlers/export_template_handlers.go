package handlers

// HTTP surface of export templates (DCIM BUILD_PLAN row 5.5), under
// /api/v2/inventory-service/dcim:
//
//	GET|POST         /export-templates
//	GET|PATCH|DELETE /export-templates/{id}
//
// reads behind dcim.read, writes behind dcim.manage (cmd/dcim_export_template_routes.go).
// Envelope and error codes are IPAM's (ipam_handlers.go).

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// ExportTemplateCRUD is what the handlers need; services.ExportTemplateService implements it.
type ExportTemplateCRUD interface {
	List(ctx context.Context, tenant uuid.UUID, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant, id uuid.UUID) error
}

// ExportTemplateHandler serves the config-context routes.
type ExportTemplateHandler struct{ store ExportTemplateCRUD }

// NewExportTemplateHandler returns the handler over store.
func NewExportTemplateHandler(store ExportTemplateCRUD) *ExportTemplateHandler {
	return &ExportTemplateHandler{store: store}
}

// List is GET /export-templates.
func (h *ExportTemplateHandler) List(c *gin.Context) {
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

// Get is GET /export-templates/{id}.
func (h *ExportTemplateHandler) Get(c *gin.Context) {
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

// Create is POST /export-templates.
func (h *ExportTemplateHandler) Create(c *gin.Context) {
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

// Update is PATCH /export-templates/{id}.
func (h *ExportTemplateHandler) Update(c *gin.Context) {
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

// Delete is DELETE /export-templates/{id}.
func (h *ExportTemplateHandler) Delete(c *gin.Context) {
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
