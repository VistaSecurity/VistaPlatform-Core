package handlers

// HTTP surface of interfaces (DCIM BUILD_PLAN row 1.2):
//
//	GET    /dcim/interfaces                 dcim.read    list, NetBox-style filters
//	POST   /dcim/interfaces                 dcim.manage  create
//	POST   /dcim/interfaces/bulk            dcim.manage  create many, all or none
//	GET    /dcim/interfaces/{id}            dcim.read
//	PATCH  /dcim/interfaces/{id}            dcim.manage  JSON merge-patch
//	DELETE /dcim/interfaces/{id}            dcim.manage
//	GET    /dcim/assets/{id}/interfaces     dcim.read    one asset's interfaces
//
// The permission gates are mounted with the routes
// (cmd/dcim_interface_routes.go). Responses use the ADR-0002 envelope: `data`,
// `pagination` on lists, `{error: {code, message, field?}}`.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// InterfaceStore is what the handlers need; services.InterfaceService
// implements it, the route tests stub it.
type InterfaceStore interface {
	List(ctx context.Context, tenant uuid.UUID, f services.InterfaceFilter) ([]services.Interface, int, error)
	Get(ctx context.Context, tenant, id uuid.UUID) (services.Interface, error)
	Create(ctx context.Context, tenant, actor uuid.UUID, in services.InterfaceInput) (services.Interface, error)
	BulkCreate(ctx context.Context, tenant, actor uuid.UUID, ins []services.InterfaceInput) ([]services.Interface, error)
	Patch(ctx context.Context, tenant, id uuid.UUID, patch map[string]json.RawMessage) (services.Interface, error)
	Delete(ctx context.Context, tenant, id uuid.UUID) error
}

// InterfaceHandler serves the interface routes.
type InterfaceHandler struct{ store InterfaceStore }

// NewInterfaceHandler returns the handler over store.
func NewInterfaceHandler(store InterfaceStore) *InterfaceHandler {
	return &InterfaceHandler{store: store}
}

const (
	ifaceDefaultLimit = 50
	// An asset's whole interface list fits one page: a chassis switch has a
	// few hundred, and the tab shows them all.
	ifaceMaxLimit = 1000
	ifaceMaxBulk  = 1000
)

func ifaceError(c *gin.Context, status int, code, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": msg}})
}

func ifaceTenant(c *gin.Context) (uuid.UUID, bool) {
	tenant, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		ifaceError(c, http.StatusUnauthorized, "unauthenticated", "tenant context required")
	}
	return tenant, ok
}

func ifaceActor(c *gin.Context) uuid.UUID {
	if uid, ok := sharedmw.GetUserIDFromContext(c); ok {
		return uid
	}
	return uuid.Nil
}

func ifaceStoreError(c *gin.Context, err error) {
	var ve *services.InterfaceValidationError
	switch {
	case errors.As(err, &ve):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": gin.H{
			"code": "invalid_interface", "message": ve.Message, "field": ve.Field}})
	case errors.Is(err, services.ErrInterfaceNotFound):
		ifaceError(c, http.StatusNotFound, "interface_not_found", "No such interface.")
	case errors.Is(err, services.ErrInterfaceAssetNotFound):
		ifaceError(c, http.StatusNotFound, "asset_not_found", "No such asset.")
	case errors.Is(err, services.ErrInterfaceNameTaken):
		ifaceError(c, http.StatusConflict, "interface_exists", "This asset already has an interface with that name.")
	case errors.Is(err, services.ErrInterfaceImmutable):
		ifaceError(c, http.StatusUnprocessableEntity, "immutable_field", err.Error())
	default:
		_ = c.Error(err)
		ifaceError(c, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
	}
}

func ifaceUUIDParam(c *gin.Context, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		ifaceError(c, http.StatusBadRequest, "invalid_id", name+" must be a UUID.")
		return uuid.Nil, false
	}
	return id, true
}

func ifaceQueryUUID(c *gin.Context, key string, dst **uuid.UUID) bool {
	v := c.Query(key)
	if v == "" {
		return true
	}
	id, err := uuid.Parse(v)
	if err != nil {
		ifaceError(c, http.StatusBadRequest, "invalid_filter", key+" must be a UUID.")
		return false
	}
	*dst = &id
	return true
}

func ifaceQueryBool(c *gin.Context, key string, dst **bool) bool {
	v := c.Query(key)
	if v == "" {
		return true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		ifaceError(c, http.StatusBadRequest, "invalid_filter", key+" must be true or false.")
		return false
	}
	*dst = &b
	return true
}

func (h *InterfaceHandler) list(c *gin.Context, assetID *uuid.UUID) {
	tenant, ok := ifaceTenant(c)
	if !ok {
		return
	}
	limit, offset, err := sharedapi.ParseLimitOffsetStrict(c, ifaceDefaultLimit, ifaceMaxLimit)
	if err != nil {
		ifaceError(c, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	f := services.InterfaceFilter{
		AssetID: assetID, Name: c.Query("name"), Type: c.Query("type"), MACAddress: c.Query("mac_address"),
		Status: c.Query("status"), Q: c.Query("q"), Limit: limit, Offset: offset,
	}
	if f.AssetID == nil && !ifaceQueryUUID(c, "asset_id", &f.AssetID) {
		return
	}
	if !ifaceQueryUUID(c, "lag_id", &f.LagID) || !ifaceQueryUUID(c, "vlan", &f.VLAN) ||
		!ifaceQueryBool(c, "enabled", &f.Enabled) || !ifaceQueryBool(c, "mgmt_only", &f.MgmtOnly) {
		return
	}
	rows, total, err := h.store.List(c.Request.Context(), tenant, f)
	if err != nil {
		ifaceStoreError(c, err)
		return
	}
	var next any
	if offset+limit < total {
		next = offset + limit
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": gin.H{
		"total": total, "limit": limit, "offset": offset, "next_offset": next}})
}

// ListInterfaces is GET /dcim/interfaces.
func (h *InterfaceHandler) ListInterfaces(c *gin.Context) { h.list(c, nil) }

// ListAssetInterfaces is GET /dcim/assets/{id}/interfaces.
func (h *InterfaceHandler) ListAssetInterfaces(c *gin.Context) {
	id, ok := ifaceUUIDParam(c, "id")
	if !ok {
		return
	}
	h.list(c, &id)
}

// GetInterface is GET /dcim/interfaces/{id}.
func (h *InterfaceHandler) GetInterface(c *gin.Context) {
	tenant, ok := ifaceTenant(c)
	if !ok {
		return
	}
	id, ok := ifaceUUIDParam(c, "id")
	if !ok {
		return
	}
	i, err := h.store.Get(c.Request.Context(), tenant, id)
	if err != nil {
		ifaceStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": i})
}

// CreateInterface is POST /dcim/interfaces.
func (h *InterfaceHandler) CreateInterface(c *gin.Context) {
	tenant, ok := ifaceTenant(c)
	if !ok {
		return
	}
	var in services.InterfaceInput
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		ifaceError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	i, err := h.store.Create(c.Request.Context(), tenant, ifaceActor(c), in)
	if err != nil {
		ifaceStoreError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": i})
}

// BulkCreateInterfaces is POST /dcim/interfaces/bulk: `{"interfaces": [...]}`.
func (h *InterfaceHandler) BulkCreateInterfaces(c *gin.Context) {
	tenant, ok := ifaceTenant(c)
	if !ok {
		return
	}
	var body struct {
		Interfaces []services.InterfaceInput `json:"interfaces"`
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		ifaceError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(body.Interfaces) == 0 || len(body.Interfaces) > ifaceMaxBulk {
		ifaceError(c, http.StatusBadRequest, "invalid_request", "interfaces must hold between 1 and 1000 entries")
		return
	}
	rows, err := h.store.BulkCreate(c.Request.Context(), tenant, ifaceActor(c), body.Interfaces)
	if err != nil {
		ifaceStoreError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": rows})
}

// PatchInterface is PATCH /dcim/interfaces/{id}.
func (h *InterfaceHandler) PatchInterface(c *gin.Context) {
	tenant, ok := ifaceTenant(c)
	if !ok {
		return
	}
	id, ok := ifaceUUIDParam(c, "id")
	if !ok {
		return
	}
	var patch map[string]json.RawMessage
	if err := json.NewDecoder(c.Request.Body).Decode(&patch); err != nil || len(patch) == 0 {
		ifaceError(c, http.StatusBadRequest, "invalid_request", "body must be a non-empty JSON object")
		return
	}
	i, err := h.store.Patch(c.Request.Context(), tenant, id, patch)
	if err != nil {
		ifaceStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": i})
}

// DeleteInterface is DELETE /dcim/interfaces/{id}.
func (h *InterfaceHandler) DeleteInterface(c *gin.Context) {
	tenant, ok := ifaceTenant(c)
	if !ok {
		return
	}
	id, ok := ifaceUUIDParam(c, "id")
	if !ok {
		return
	}
	if err := h.store.Delete(c.Request.Context(), tenant, id); err != nil {
		ifaceStoreError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
