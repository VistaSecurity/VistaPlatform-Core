package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// The internal DCIM import surface (DCIM SYNC_MODEL §6; BUILD_PLAN row 5.6):
// what an import-only connector running outside this service (the Enterprise
// Device42 importer) reads and writes. Mounted only behind
// RequireSignedServiceCall by mountSourceImportRoutes, like /internal/sources/*
// — an HMAC call naming one tenant in a signed X-Tenant-ID, and nothing else.

// dcimImportService is the service slice the handlers need.
type dcimImportService interface {
	Objects(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, prefix string) ([]services.ImportObject, error)
	Write(ctx context.Context, tenant uuid.UUID, producer string, kind dcim.ObjectKind, items []services.ImportWrite) ([]services.ImportWriteResult, error)
	Placements(ctx context.Context, tenant uuid.UUID, producer string, items []services.ImportPlacement) ([]services.ImportPlacementResult, error)
}

// DCIMImportHandler serves /internal/dcim-import/*.
type DCIMImportHandler struct{ svc dcimImportService }

// NewDCIMImportHandler wires the handler. A nil service is allowed for the
// route-gate tests, which never reach a handler body.
func NewDCIMImportHandler(svc *services.DCIMImportService) *DCIMImportHandler {
	if svc == nil {
		return &DCIMImportHandler{}
	}
	return &DCIMImportHandler{svc: svc}
}

// maxImportWrites bounds one write request.
const maxImportWrites = 500

// RegisterDCIMImportRoutes mounts the routes on the signed-call group.
func RegisterDCIMImportRoutes(internal *gin.RouterGroup, h *DCIMImportHandler) {
	internal.GET("/inventory-service/internal/dcim-import/objects/:kind", h.Objects)
	internal.POST("/inventory-service/internal/dcim-import/write/:kind", h.Write)
	internal.POST("/inventory-service/internal/dcim-import/placements", h.Placements)
}

func (h *DCIMImportHandler) ready(c *gin.Context) (uuid.UUID, bool) {
	tenant, ok := signedTenant(c)
	if !ok {
		return uuid.Nil, false
	}
	if h.svc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "import service not configured"})
		return uuid.Nil, false
	}
	return tenant, true
}

func respondImportError(c *gin.Context, err error) {
	if errors.Is(err, services.ErrImportInvalid) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "import request failed"})
}

// Objects — GET /internal/dcim-import/objects/:kind?prefix=
func (h *DCIMImportHandler) Objects(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	kind, ok := dcim.ParseObjectKind(c.Param("kind"))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown object kind"})
		return
	}
	objs, err := h.svc.Objects(c.Request.Context(), tenant, kind, c.Query("prefix"))
	if err != nil {
		respondImportError(c, err)
		return
	}
	if objs == nil {
		objs = []services.ImportObject{}
	}
	c.JSON(http.StatusOK, gin.H{"objects": objs})
}

// Write — POST /internal/dcim-import/write/:kind?producer=  {items: [...]}
func (h *DCIMImportHandler) Write(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	kind, ok := dcim.ParseObjectKind(c.Param("kind"))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown object kind"})
		return
	}
	var body struct {
		Items []services.ImportWrite `json:"items"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Items) == 0 || len(body.Items) > maxImportWrites {
		c.JSON(http.StatusBadRequest, gin.H{"error": "items must hold between 1 and 500 writes"})
		return
	}
	res, err := h.svc.Write(c.Request.Context(), tenant, c.Query("producer"), kind, body.Items)
	if err != nil {
		respondImportError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": res})
}

// Placements — POST /internal/dcim-import/placements?producer=  {items: [...]}
func (h *DCIMImportHandler) Placements(c *gin.Context) {
	tenant, ok := h.ready(c)
	if !ok {
		return
	}
	var body struct {
		Items []services.ImportPlacement `json:"items"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Items) == 0 || len(body.Items) > maxImportWrites {
		c.JSON(http.StatusBadRequest, gin.H{"error": "items must hold between 1 and 500 placements"})
		return
	}
	res, err := h.svc.Placements(c.Request.Context(), tenant, c.Query("producer"), body.Items)
	if err != nil {
		respondImportError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": res})
}
