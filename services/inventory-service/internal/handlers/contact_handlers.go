package handlers

// HTTP surface of contacts (DCIM BUILD_PLAN row 2.8), under
// /api/v2/inventory-service/dcim:
//
//	GET|POST        /contacts, /contact-roles, /contact-assignments
//	GET|PATCH|DELETE /contacts/{id}, /contact-roles/{id}, /contact-assignments/{id}
//	GET  /objects/{kind}/{id}/contacts   the object's assignments, contact and role inlined
//	POST /objects/{kind}/{id}/contacts   assign {contact_id, role_id, priority?}
//
// reads behind dcim.read, writes behind dcim.manage (cmd/dcim_contact_routes.go).
// Envelope and error codes are IPAM's (ipam_handlers.go).

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// ContactStore is what the handlers need; services.ContactService implements it.
type ContactStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
	ListForObject(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, p services.IPAMListParams) ([]json.RawMessage, int, error)
	AssignToObject(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, body []byte) (json.RawMessage, error)
}

// ContactHandler serves the contact routes.
type ContactHandler struct{ store ContactStore }

// NewContactHandler returns the handler over store.
func NewContactHandler(store ContactStore) *ContactHandler { return &ContactHandler{store: store} }

func listParams(c *gin.Context) (services.IPAMListParams, bool) {
	return catalogueListParams(c)
}

// List returns the list handler for one contact route.
func (h *ContactHandler) List(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		p, ok := listParams(c)
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

// Get returns the single-object handler.
func (h *ContactHandler) Get(route string) gin.HandlerFunc {
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

// Create returns the create handler.
func (h *ContactHandler) Create(route string) gin.HandlerFunc {
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

// Update returns the PATCH handler.
func (h *ContactHandler) Update(route string) gin.HandlerFunc {
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

// Delete returns the delete handler.
func (h *ContactHandler) Delete(route string) gin.HandlerFunc {
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

func objectRef(c *gin.Context) (dcim.ObjectKind, uuid.UUID, bool) {
	kind, ok := dcim.ParseObjectKind(c.Param("kind"))
	if !ok {
		ipamError(c, http.StatusBadRequest, "invalid_object_kind", "Unknown object kind.")
		return "", uuid.Nil, false
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_object_id", "Object id must be a UUID.")
		return "", uuid.Nil, false
	}
	return kind, id, true
}

// ListForObject is GET /objects/{kind}/{id}/contacts.
func (h *ContactHandler) ListForObject(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	kind, id, ok := objectRef(c)
	if !ok {
		return
	}
	p, ok := listParams(c)
	if !ok {
		return
	}
	// The path decides the object; query filters on it are ignored.
	delete(p.Filters, "object_kind")
	delete(p.Filters, "object_id")
	rows, total, err := h.store.ListForObject(c.Request.Context(), tenant, kind, id, p)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, p.Limit, p.Offset)})
}

// AssignToObject is POST /objects/{kind}/{id}/contacts.
func (h *ContactHandler) AssignToObject(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	kind, id, ok := objectRef(c)
	if !ok {
		return
	}
	body, ok := ipamBody(c)
	if !ok {
		return
	}
	row, err := h.store.AssignToObject(c.Request.Context(), tenant, kind, id, body)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": row})
}
