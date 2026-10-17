package handlers

// HTTP surface of the device catalogue (DCIM BUILD_PLAN row 2.2), under
// /api/v2/inventory-service/dcim:
//
//	GET    /{object}                         dcim.read    list (filters, q, scope, limit, offset)
//	POST   /{object}                         dcim.manage  create a tenant row
//	GET    /{object}/{id}                    dcim.read
//	PATCH  /{object}/{id}                    dcim.manage  a platform row answers 403 read_only
//	DELETE /{object}/{id}                    dcim.manage
//	GET    /{device|module}-types/{id}/{kind}-templates                 dcim.read
//	POST   /{device|module}-types/{id}/{kind}-templates                 dcim.manage
//	GET    /{device|module}-types/{id}/{kind}-templates/{template_id}   dcim.read
//	PATCH  /{device|module}-types/{id}/{kind}-templates/{template_id}   dcim.manage
//	DELETE /{device|module}-types/{id}/{kind}-templates/{template_id}   dcim.manage
//	GET    /assets/{id}/hardware             dcim.read    the asset's Hardware card
//	PATCH  /assets/{id}/hardware             dcim.manage  device type, role, platform, serial, asset tag
//	POST   /assets/{id}/device-type          dcim.manage  assign a type and instantiate its templates
//	POST   /device-types/import              dcim.manage  import device-type library YAML as the tenant's own types
//
// {object} is manufacturers, device-types, module-types, device-roles,
// platforms. Envelope and error codes are IPAM's (ipam_handlers.go). Gates are
// mounted with the routes (cmd/dcim_catalogue_routes.go).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	"github.com/vistasecurity/vistaplatform/shared/dcim/devicetypelib"
)

// CatalogueStore is what the handlers need; services.CatalogueService
// implements it.
type CatalogueStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
	ListTemplates(ctx context.Context, tenant uuid.UUID, p services.TemplateParent, route string, lp services.IPAMListParams) ([]json.RawMessage, int, error)
	GetTemplate(ctx context.Context, tenant uuid.UUID, p services.TemplateParent, route string, id uuid.UUID) (json.RawMessage, error)
	CreateTemplate(ctx context.Context, tenant uuid.UUID, p services.TemplateParent, route string, body []byte) (json.RawMessage, error)
	UpdateTemplate(ctx context.Context, tenant uuid.UUID, p services.TemplateParent, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	DeleteTemplate(ctx context.Context, tenant uuid.UUID, p services.TemplateParent, route string, id uuid.UUID) error
	Hardware(ctx context.Context, tenant, asset uuid.UUID) (*services.AssetHardware, error)
	UpdateHardware(ctx context.Context, tenant, asset uuid.UUID, patch services.HardwarePatch) (*services.AssetHardware, error)
	ApplyDeviceType(ctx context.Context, tenant, asset, deviceType uuid.UUID) (*services.ApplyDeviceTypeResult, error)
	ImportDeviceTypes(ctx context.Context, tenant uuid.UUID, data []byte) ([]services.ImportedDeviceType, error)
}

// CatalogueHandler serves the catalogue routes.
type CatalogueHandler struct {
	store CatalogueStore
}

// NewCatalogueHandler returns the handler over store.
func NewCatalogueHandler(store CatalogueStore) *CatalogueHandler {
	return &CatalogueHandler{store: store}
}

func catalogueListParams(c *gin.Context) (services.IPAMListParams, bool) {
	limit, offset, err := sharedapi.ParseLimitOffsetStrict(c, ipamDefaultLimit, ipamMaxLimit)
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_pagination", err.Error())
		return services.IPAMListParams{}, false
	}
	filters := map[string]string{}
	for k, v := range c.Request.URL.Query() {
		if k != "q" && k != "limit" && k != "offset" && len(v) > 0 {
			filters[k] = v[0]
		}
	}
	return services.IPAMListParams{Filters: filters, Q: c.Query("q"), Limit: limit, Offset: offset}, true
}

// List returns the list handler for one catalogue object.
func (h *CatalogueHandler) List(route string) gin.HandlerFunc {
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

// Get returns the single-object handler for one catalogue object.
func (h *CatalogueHandler) Get(route string) gin.HandlerFunc {
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

// Create returns the create handler for one catalogue object.
func (h *CatalogueHandler) Create(route string) gin.HandlerFunc {
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

// Update returns the PATCH handler for one catalogue object.
func (h *CatalogueHandler) Update(route string) gin.HandlerFunc {
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

// Delete returns the delete handler for one catalogue object.
func (h *CatalogueHandler) Delete(route string) gin.HandlerFunc {
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

func templateIDs(c *gin.Context, parentKind string) (services.TemplateParent, uuid.UUID, bool) {
	parent, ok := ipamID(c)
	if !ok {
		return services.TemplateParent{}, uuid.Nil, false
	}
	p := services.TemplateParent{Kind: parentKind, ID: parent}
	raw := c.Param("template_id")
	if raw == "" {
		return p, uuid.Nil, true
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_id", "template_id must be a UUID.")
		return p, uuid.Nil, false
	}
	return p, id, true
}

// ListTemplates lists one parent's templates of one kind. parentKind is
// "device-types" or "module-types".
func (h *CatalogueHandler) ListTemplates(parentKind, route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		p, _, ok := templateIDs(c, parentKind)
		if !ok {
			return
		}
		lp, ok := catalogueListParams(c)
		if !ok {
			return
		}
		rows, total, err := h.store.ListTemplates(c.Request.Context(), tenant, p, route, lp)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, lp.Limit, lp.Offset)})
	}
}

// GetTemplate returns one template.
func (h *CatalogueHandler) GetTemplate(parentKind, route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		p, id, ok := templateIDs(c, parentKind)
		if !ok {
			return
		}
		row, err := h.store.GetTemplate(c.Request.Context(), tenant, p, route, id)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": row})
	}
}

// CreateTemplate adds a template to the parent in the path.
func (h *CatalogueHandler) CreateTemplate(parentKind, route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		p, _, ok := templateIDs(c, parentKind)
		if !ok {
			return
		}
		body, ok := ipamBody(c)
		if !ok {
			return
		}
		row, err := h.store.CreateTemplate(c.Request.Context(), tenant, p, route, body)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"data": row})
	}
}

// UpdateTemplate patches one template.
func (h *CatalogueHandler) UpdateTemplate(parentKind, route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		p, id, ok := templateIDs(c, parentKind)
		if !ok {
			return
		}
		body, ok := ipamBody(c)
		if !ok {
			return
		}
		row, err := h.store.UpdateTemplate(c.Request.Context(), tenant, p, route, id, body)
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": row})
	}
}

// DeleteTemplate removes one template.
func (h *CatalogueHandler) DeleteTemplate(parentKind, route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		p, id, ok := templateIDs(c, parentKind)
		if !ok {
			return
		}
		if err := h.store.DeleteTemplate(c.Request.Context(), tenant, p, route, id); err != nil {
			ipamStoreError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// Hardware is GET /dcim/assets/{id}/hardware.
func (h *CatalogueHandler) Hardware(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	hw, err := h.store.Hardware(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": hw})
}

// UpdateHardware is PATCH /dcim/assets/{id}/hardware.
func (h *CatalogueHandler) UpdateHardware(c *gin.Context) {
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
	var patch services.HardwarePatch
	if err := json.Unmarshal(body, &patch); err != nil || patch == nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
		return
	}
	hw, err := h.store.UpdateHardware(c.Request.Context(), tenant, id, patch)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": hw})
}

// ApplyDeviceType is POST /dcim/assets/{id}/device-type {"device_type_id": "…"}.
func (h *CatalogueHandler) ApplyDeviceType(c *gin.Context) {
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
		DeviceTypeID string `json:"device_type_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
		return
	}
	dt, err := uuid.Parse(req.DeviceTypeID)
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "device_type_id must be a UUID.")
		return
	}
	res, err := h.store.ApplyDeviceType(c.Request.Context(), tenant, id, dt)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res})
}

// ImportDeviceTypes is POST /dcim/device-types/import {"yaml": "<one or more
// library documents>"}: each becomes the tenant's own device type with its
// templates, or is reported as already in the catalogue.
func (h *CatalogueHandler) ImportDeviceTypes(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	// The YAML may be larger than an ordinary body; JSON escaping can double it.
	limit := int64(2*devicetypelib.MaxDocumentBytes + 1024)
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		ipamError(c, http.StatusRequestEntityTooLarge, "too_large", "The import is too large.")
		return
	}
	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.YAML == "" {
		ipamError(c, http.StatusBadRequest, "invalid_request", "body must be {\"yaml\": \"<device-type library YAML>\"}")
		return
	}
	res, err := h.store.ImportDeviceTypes(c.Request.Context(), tenant, []byte(req.YAML))
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res})
}
