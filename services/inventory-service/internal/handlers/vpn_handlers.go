package handlers

// HTTP surface of the VPN objects (DCIM BUILD_PLAN row 4.3), under
// /api/v2/inventory-service/vpn:
//
//	GET    /{object}       vpn.read    list (filters, q, limit, offset)
//	POST   /{object}       vpn.manage  create
//	GET    /{object}/{id}  vpn.read    one object, in its list shape
//	PATCH  /{object}/{id}  vpn.manage  partial update
//	DELETE /{object}/{id}  vpn.manage
//
// {object} is tunnel-groups, tunnels, tunnel-terminations, ike-proposals,
// ike-policies, ipsec-proposals, ipsec-policies, ipsec-profiles, l2vpns,
// l2vpn-terminations. Gates are mounted with the routes (cmd/vpn_routes.go).
// Envelope and errors are IPAM's.

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// VPNStore is what the handlers need; services.VPNService implements it.
type VPNStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
}

// VPNHandler serves the VPN routes.
type VPNHandler struct{ store VPNStore }

// NewVPNHandler returns the handler over store.
func NewVPNHandler(store VPNStore) *VPNHandler { return &VPNHandler{store: store} }

// List returns the list handler for one object route.
func (h *VPNHandler) List(route string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenant, ok := ipamTenant(c)
		if !ok {
			return
		}
		limit, offset, err := sharedapi.ParseLimitOffsetStrict(c, ipamDefaultLimit, ipamMaxLimit)
		if err != nil {
			ipamError(c, http.StatusBadRequest, "invalid_pagination", err.Error())
			return
		}
		filters := map[string]string{}
		for k, v := range c.Request.URL.Query() {
			if k != "q" && k != "limit" && k != "offset" && len(v) > 0 {
				filters[k] = v[0]
			}
		}
		rows, total, err := h.store.List(c.Request.Context(), tenant, route, services.IPAMListParams{
			Filters: filters, Q: c.Query("q"), Limit: limit, Offset: offset,
		})
		if err != nil {
			ipamStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, limit, offset)})
	}
}

// Get returns the single-object handler for one object route.
func (h *VPNHandler) Get(route string) gin.HandlerFunc {
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

// Create returns the create handler for one object route.
func (h *VPNHandler) Create(route string) gin.HandlerFunc {
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

// Update returns the PATCH handler for one object route.
func (h *VPNHandler) Update(route string) gin.HandlerFunc {
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

// Delete returns the delete handler for one object route.
func (h *VPNHandler) Delete(route string) gin.HandlerFunc {
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
