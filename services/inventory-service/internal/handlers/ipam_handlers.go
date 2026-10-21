package handlers

// HTTP surface of IPAM (DCIM BUILD_PLAN row 1.3), under
// /api/v2/inventory-service/ipam:
//
//	GET    /{object}            ipam.read    list (filters, q, limit, offset)
//	POST   /{object}            ipam.manage  create
//	GET    /{object}/{id}       ipam.read    one object (prefixes: with computed parts)
//	PATCH  /{object}/{id}       ipam.manage  partial update
//	DELETE /{object}/{id}       ipam.manage
//	GET    /prefixes/tree       ipam.read    one VRF's prefix tree
//	GET    /find                ipam.read    where an address lives
//
// {object} is rirs, aggregates, vrfs, route-targets, prefix-roles, prefixes,
// ip-ranges, ip-addresses, vlan-groups, vlans, fhrp-groups,
// fhrp-group-assignments, asns. Gates are mounted with the routes
// (cmd/ipam_routes.go). Envelope: `data`, `pagination` on lists,
// `{error: {code, message}}`.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// IPAMStore is what the handlers need; services.IPAMService implements it.
type IPAMStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
	PrefixDetail(ctx context.Context, tenant, id uuid.UUID, p services.PrefixDetailParams) (*services.PrefixDetail, error)
	PrefixTree(ctx context.Context, tenant uuid.UUID, vrf *uuid.UUID) ([]*services.PrefixTreeNode, int, error)
	FindAddress(ctx context.Context, tenant uuid.UUID, addr netip.Addr, vrf *uuid.UUID, allVRFs bool) ([]services.FindResult, error)
	// AvailableASNs is an ASN range's free numbers (DCIM gap 10).
	AvailableASNs(ctx context.Context, tenant, rangeID uuid.UUID, limit int) (*services.AvailableASNs, error)
}

// IPAMHandler serves the IPAM routes.
type IPAMHandler struct {
	store IPAMStore
}

// NewIPAMHandler returns the handler over store.
func NewIPAMHandler(store IPAMStore) *IPAMHandler { return &IPAMHandler{store: store} }

const (
	ipamDefaultLimit = 50
	ipamMaxLimit     = 1000
	ipamMaxBody      = 1 << 20
)

func ipamError(c *gin.Context, status int, code, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": msg}})
}

func ipamTenant(c *gin.Context) (uuid.UUID, bool) {
	t, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		ipamError(c, http.StatusUnauthorized, "unauthenticated", "tenant context required")
	}
	return t, ok
}

func ipamStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrIPAMNotFound):
		ipamError(c, http.StatusNotFound, "not_found", "No such object for this organisation.")
	case errors.Is(err, services.ErrIPAMInvalid):
		ipamError(c, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, services.ErrIPAMConflict):
		ipamError(c, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, services.ErrIPAMInUse):
		ipamError(c, http.StatusConflict, "in_use", err.Error())
	case errors.Is(err, services.ErrIPAMReadOnly):
		ipamError(c, http.StatusForbidden, "read_only", err.Error())
	case errors.Is(err, changes.ErrNoActor):
		ipamError(c, http.StatusUnauthorized, "unauthenticated", "A change must be attributed to a signed-in user.")
	default:
		_ = c.Error(err)
		ipamError(c, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
	}
}

func ipamID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_id", "id must be a UUID.")
		return uuid.Nil, false
	}
	return id, true
}

func ipamBody(c *gin.Context) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, ipamMaxBody+1))
	if err != nil || len(body) > ipamMaxBody {
		ipamError(c, http.StatusBadRequest, "invalid_request", "The body could not be read or is too large.")
		return nil, false
	}
	return body, true
}

func ipamPagination(total, limit, offset int) gin.H {
	var next any
	if offset+limit < total {
		next = offset + limit
	}
	return gin.H{"total": total, "limit": limit, "offset": offset, "next_offset": next}
}

// List returns the list handler for one object route.
func (h *IPAMHandler) List(route string) gin.HandlerFunc {
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
func (h *IPAMHandler) Get(route string) gin.HandlerFunc {
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
func (h *IPAMHandler) Create(route string) gin.HandlerFunc {
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
func (h *IPAMHandler) Update(route string) gin.HandlerFunc {
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
func (h *IPAMHandler) Delete(route string) gin.HandlerFunc {
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

func queryInt(c *gin.Context, name string, def, lo, hi int) (int, bool) {
	v := c.Query(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		ipamError(c, http.StatusBadRequest, "invalid_"+name, name+" must be an integer between "+strconv.Itoa(lo)+" and "+strconv.Itoa(hi)+".")
		return 0, false
	}
	return n, true
}

// PrefixDetail is GET /ipam/prefixes/{id}: the prefix with its parent, depth,
// children, utilisation, available prefixes (?length=, ?available_limit=) and
// available addresses (?limit=).
func (h *IPAMHandler) PrefixDetail(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	length, ok := queryInt(c, "length", 0, 0, 128)
	if !ok {
		return
	}
	availLimit, ok := queryInt(c, "available_limit", 50, 1, 1000)
	if !ok {
		return
	}
	ipLimit, ok := queryInt(c, "limit", 10, 0, 1000)
	if !ok {
		return
	}
	d, err := h.store.PrefixDetail(c.Request.Context(), tenant, id, services.PrefixDetailParams{
		AvailableLength: length, AvailableLimit: availLimit, IPLimit: ipLimit,
	})
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": d})
}

// AvailableASNs is GET /ipam/asn-ranges/{id}/available-asns?limit=: the
// first free AS numbers of the range, how many are free and how many of the
// tenant's ASNs are in it (DCIM gap 10; NetBox's available-asns).
func (h *IPAMHandler) AvailableASNs(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	limit, ok := queryInt(c, "limit", 50, 1, 1000)
	if !ok {
		return
	}
	d, err := h.store.AvailableASNs(c.Request.Context(), tenant, id, limit)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": d})
}

// PrefixTree is GET /ipam/prefixes/tree?vrf=<id|global>.
func (h *IPAMHandler) PrefixTree(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	vrf, err := services.IPAMVRFParam(c.Query("vrf"))
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	nodes, total, err := h.store.PrefixTree(c.Request.Context(), tenant, vrf)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": nodes, "total": total})
}

// Find is GET /ipam/find?address=10.0.0.5[&vrf=<id|global>]. Without vrf
// every VRF holding the address answers.
func (h *IPAMHandler) Find(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	addr, err := ipam.ParseAddr(c.Query("address"))
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_address", "address must be an IPv4 or IPv6 address.")
		return
	}
	v, scoped := c.GetQuery("vrf")
	vrf, err := services.IPAMVRFParam(v)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	res, err := h.store.FindAddress(c.Request.Context(), tenant, addr, vrf, !scoped)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res, "address": addr.String()})
}
