package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
	"github.com/vistasecurity/vistaplatform/shared/syncauthority"
)

// The internal DCIM sync surface (ADR-0010 D7; SYNC_MODEL §1.5): what a sync
// connector running outside this service (the Enterprise NetBox
// connector) reads and writes. Mounted only behind RequireSignedServiceCall by
// mountSourceImportRoutes, like /internal/sources/* — an HMAC call naming one
// tenant in a signed X-Tenant-ID, and nothing else.

// dcimSyncService is the service slice the handlers need.
type dcimSyncService interface {
	ListObjects(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, after uuid.UUID, limit int) ([]services.SyncObject, bool, error)
	Changes(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, since time.Time) ([]services.SyncFieldChange, []services.SyncDeleted, error)
	Write(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, items []services.SyncWrite) ([]services.SyncWriteResult, error)
	Delete(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, id uuid.UUID) error
	PeerAssets(ctx context.Context, tenant uuid.UUID, peer string) (map[string]uuid.UUID, error)
	Park(ctx context.Context, tenant uuid.UUID, peer string, items []services.SyncPark) error
	Resolve(ctx context.Context, tenant uuid.UUID) (unresolved.ResolvedCount, error)
}

// DCIMSyncHandler serves /internal/dcim-sync/*.
type DCIMSyncHandler struct{ svc dcimSyncService }

// NewDCIMSyncHandler wires the handler. A nil service is allowed for the
// route-gate tests, which never reach a handler body.
func NewDCIMSyncHandler(svc *services.DCIMSyncService) *DCIMSyncHandler {
	if svc == nil {
		return &DCIMSyncHandler{}
	}
	return &DCIMSyncHandler{svc: svc}
}

// maxSyncWrites bounds one write request.
const maxSyncWrites = 500

// RegisterDCIMSyncRoutes mounts the routes on the signed-call group.
func RegisterDCIMSyncRoutes(internal *gin.RouterGroup, h *DCIMSyncHandler) {
	internal.GET("/inventory-service/internal/dcim-sync/objects/:kind", h.ListObjects)
	internal.DELETE("/inventory-service/internal/dcim-sync/objects/:kind/:id", h.Delete)
	internal.GET("/inventory-service/internal/dcim-sync/changes/:kind", h.Changes)
	internal.POST("/inventory-service/internal/dcim-sync/write/:kind", h.Write)
	internal.GET("/inventory-service/internal/dcim-sync/peer-assets", h.PeerAssets)
	internal.POST("/inventory-service/internal/dcim-sync/park", h.Park)
	internal.POST("/inventory-service/internal/dcim-sync/resolve", h.Resolve)
}

func (h *DCIMSyncHandler) ready(c *gin.Context) (uuid.UUID, bool) {
	tenant, ok := signedTenant(c)
	if !ok {
		return uuid.Nil, false
	}
	if h.svc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "sync service not configured"})
		return uuid.Nil, false
	}
	return tenant, true
}

func syncKindParam(c *gin.Context) (dcim.ObjectKind, bool) {
	k, ok := dcim.ParseObjectKind(c.Param("kind"))
	if !ok {
		// A sync kind over another object's table (a NetBox virtual machine
		// or VM interface, standards/sync-authority.yaml `object:`).
		if spec, isSync := syncauthority.Kind(dcim.ObjectKind(c.Param("kind"))); isSync && spec.Object != "" {
			k, ok = spec.Kind, true
		}
	}
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown object kind"})
		return "", false
	}
	return k, true
}

func respondSyncError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrSyncInvalid), errors.Is(err, services.ErrIPAMInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrSyncNotFound), errors.Is(err, services.ErrIPAMNotFound),
		errors.Is(err, services.ErrBusinessUnitNotFound), errors.Is(err, services.ErrInterfaceNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, services.ErrIPAMInUse), errors.Is(err, services.ErrIPAMConflict):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sync request failed"})
	}
}

// ListObjects — GET /internal/dcim-sync/objects/:kind?after=&limit=
func (h *DCIMSyncHandler) ListObjects(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	kind, ok := syncKindParam(c)
	if !ok {
		return
	}
	after := uuid.Nil
	if raw := c.Query("after"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "after must be a UUID"})
			return
		}
		after = id
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	objs, more, err := h.svc.ListObjects(c.Request.Context(), tenant, kind, after, limit)
	if err != nil {
		respondSyncError(c, err)
		return
	}
	if objs == nil {
		objs = []services.SyncObject{}
	}
	c.JSON(http.StatusOK, gin.H{"objects": objs, "more": more})
}

// Changes — GET /internal/dcim-sync/changes/:kind?peer=&since=
func (h *DCIMSyncHandler) Changes(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	kind, ok := syncKindParam(c)
	if !ok {
		return
	}
	since, err := time.Parse(time.RFC3339Nano, c.Query("since"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "since must be an RFC 3339 time"})
		return
	}
	fields, deleted, err := h.svc.Changes(c.Request.Context(), tenant, c.Query("peer"), kind, since)
	if err != nil {
		respondSyncError(c, err)
		return
	}
	if fields == nil {
		fields = []services.SyncFieldChange{}
	}
	if deleted == nil {
		deleted = []services.SyncDeleted{}
	}
	c.JSON(http.StatusOK, gin.H{"fields": fields, "deleted": deleted})
}

// Write — POST /internal/dcim-sync/write/:kind?peer=  {items: [...]}
func (h *DCIMSyncHandler) Write(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	kind, ok := syncKindParam(c)
	if !ok {
		return
	}
	var body struct {
		Items []services.SyncWrite `json:"items"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Items) == 0 || len(body.Items) > maxSyncWrites {
		c.JSON(http.StatusBadRequest, gin.H{"error": "items must hold between 1 and 500 writes"})
		return
	}
	res, err := h.svc.Write(c.Request.Context(), tenant, c.Query("peer"), kind, body.Items)
	if err != nil {
		respondSyncError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": res})
}

// Delete — DELETE /internal/dcim-sync/objects/:kind/:id?peer=
func (h *DCIMSyncHandler) Delete(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	kind, ok := syncKindParam(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id must be a UUID"})
		return
	}
	if err := h.svc.Delete(c.Request.Context(), tenant, c.Query("peer"), kind, id); err != nil {
		respondSyncError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// PeerAssets — GET /internal/dcim-sync/peer-assets?peer=
func (h *DCIMSyncHandler) PeerAssets(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	m, err := h.svc.PeerAssets(c.Request.Context(), tenant, c.Query("peer"))
	if err != nil {
		respondSyncError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"assets": m})
}

// Park — POST /internal/dcim-sync/park?peer=  {items: [...]}
func (h *DCIMSyncHandler) Park(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	var body struct {
		Items []services.SyncPark `json:"items"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Items) == 0 || len(body.Items) > maxSyncWrites {
		c.JSON(http.StatusBadRequest, gin.H{"error": "items must hold between 1 and 500 terminations"})
		return
	}
	if err := h.svc.Park(c.Request.Context(), tenant, c.Query("peer"), body.Items); err != nil {
		respondSyncError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"parked": len(body.Items)})
}

// Resolve — POST /internal/dcim-sync/resolve
func (h *DCIMSyncHandler) Resolve(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	n, err := h.svc.Resolve(c.Request.Context(), tenant)
	if err != nil {
		// A resolver pass is partial-success: rows that failed stay parked.
		c.JSON(http.StatusOK, gin.H{"examined": n.Examined, "resolved": n.Resolved, "expired": n.Expired, "unmatched": n.Unmatched, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"examined": n.Examined, "resolved": n.Resolved, "expired": n.Expired, "unmatched": n.Unmatched})
}
