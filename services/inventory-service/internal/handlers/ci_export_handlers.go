package handlers

// The internal CI export surface (platform ADR-0002 D4, step M3): the reads a
// connector running outside this service needs to PUSH the inventory into a
// system of record. The service layer is services/ci_export.go.
//
// Same gate as the source-import routes, and for the same reasons (see
// source_import_handlers.go): mounted on the HMAC-only group behind
// RequireSignedServiceCall, the tenant REQUIRED and signed, every read under
// that tenant's RLS, the /inventory-service/internal/ prefix denied at the edge
// on every host.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// ciExporter is the service behind the CI export routes. An interface so the
// contract test can drive the real handlers without a database; production
// passes *services.CIExportService.
type ciExporter interface {
	ExportItems(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]services.CIExportItem, error)
	ExportAssets(ctx context.Context, tenantID uuid.UUID, q services.CIExportAssetQuery) ([]services.CIExportAsset, error)
	ExportRelationships(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]services.CIExportRelationship, error)
	ExportDCIM(ctx context.Context, tenantID uuid.UUID, class string, after uuid.UUID, limit int) ([]services.CIExportDCIMItem, error)
}

// CIExportHandler serves the internal CI export routes.
type CIExportHandler struct {
	svc ciExporter
}

// NewCIExportHandler wires the handler.
func NewCIExportHandler(svc *services.CIExportService) *CIExportHandler {
	if svc == nil {
		return &CIExportHandler{}
	}
	return &CIExportHandler{svc: svc}
}

// newCIExportHandlerWith is the injectable form the contract test uses.
func newCIExportHandlerWith(svc ciExporter) *CIExportHandler {
	return &CIExportHandler{svc: svc}
}

// pageParams reads ?after=<uuid>&limit=<n> for the two paged listings.
func pageParams(c *gin.Context) (uuid.UUID, int, bool) {
	after := uuid.Nil
	if raw := strings.TrimSpace(c.Query("after")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "after must be an id"})
			return uuid.Nil, 0, false
		}
		after = id
	}
	limit := services.MaxCIExportPage
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > services.MaxCIExportPage {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be between 1 and " + strconv.Itoa(services.MaxCIExportPage)})
			return uuid.Nil, 0, false
		}
		limit = n
	}
	return after, limit, true
}

// Items — GET /inventory-service/internal/ci-export/items?after=&limit=
//
// The tenant's configuration items in push scope, a page at a time in id
// order. `more` is true when the page is full: ask again after its last id.
func (h *CIExportHandler) Items(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	after, limit, ok := pageParams(c)
	if !ok {
		return
	}
	items, err := h.svc.ExportItems(c.Request.Context(), tenantID, after, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read the inventory"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "more": len(items) == limit})
}

// ciExportAssetsRequest is the body of POST /internal/ci-export/assets.
type ciExportAssetsRequest struct {
	AssetIDs []uuid.UUID `json:"asset_ids"`
	Include  struct {
		Fields        bool     `json:"fields"`
		FactKeys      []string `json:"fact_keys"`
		CryptoPosture bool     `json:"crypto_posture"`
		Identifier    *struct {
			Kind  string `json:"kind"`
			Scope string `json:"scope"`
		} `json:"identifier"`
	} `json:"include"`
}

// Assets — POST /inventory-service/internal/ci-export/assets
//
// Detail for up to MaxCIExportAssets assets: whether each has left push scope
// (always), and — as asked — its allowlisted fields, named facts, crypto
// posture and link identifiers. An id that is not this tenant's asset is
// absent from the answer.
func (h *CIExportHandler) Assets(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req ciExportAssetsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.AssetIDs) == 0 || len(req.AssetIDs) > services.MaxCIExportAssets {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_ids must hold between 1 and " + strconv.Itoa(services.MaxCIExportAssets) + " ids"})
		return
	}
	q := services.CIExportAssetQuery{
		AssetIDs:      req.AssetIDs,
		Fields:        req.Include.Fields,
		FactKeys:      req.Include.FactKeys,
		CryptoPosture: req.Include.CryptoPosture,
	}
	if req.Include.Identifier != nil {
		q.IdentifierKind = strings.TrimSpace(req.Include.Identifier.Kind)
		q.IdentifierScope = strings.TrimSpace(req.Include.Identifier.Scope)
		if q.IdentifierKind == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "include.identifier needs a kind"})
			return
		}
	}
	assets, err := h.svc.ExportAssets(c.Request.Context(), tenantID, q)
	if err != nil {
		var qe *services.ErrCIExportQuery
		if errors.As(err, &qe) {
			c.JSON(http.StatusBadRequest, gin.H{"error": qe.Message})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read the inventory"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"assets": assets})
}

// Relationships — GET /inventory-service/internal/ci-export/relationships?after=&limit=
//
// The tenant's APPROVED relationships, a page at a time in id order.
func (h *CIExportHandler) Relationships(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	after, limit, ok := pageParams(c)
	if !ok {
		return
	}
	rels, err := h.svc.ExportRelationships(c.Request.Context(), tenantID, after, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read the inventory"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"relationships": rels, "more": len(rels) == limit})
}

// DCIM — GET /inventory-service/internal/ci-export/dcim/:class?after=&limit=
//
// The tenant's objects of one DCIM class in push scope (rack, prefix,
// ip_address, circuit, vlan, interface, site), a page at a time in id order,
// each with its allowlisted fields and its structural edges. An unknown class
// is a 400, never an empty page: a caller that misspells one must not read it
// as "the tenant has none".
func (h *CIExportHandler) DCIM(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	class := c.Param("class")
	if !services.IsDCIMExportClass(class) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "class must be one of: " + strings.Join(services.DCIMExportClasses(), ", ")})
		return
	}
	after, limit, ok := pageParams(c)
	if !ok {
		return
	}
	items, err := h.svc.ExportDCIM(c.Request.Context(), tenantID, class, after, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read the inventory"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "more": len(items) == limit})
}

// RegisterCIExportRoutes mounts the internal CI export routes on internal,
// which must be a group carrying RequireSignedServiceCall. Paths are written in
// full so the spec-route guard can see them.
func RegisterCIExportRoutes(internal *gin.RouterGroup, h *CIExportHandler) {
	internal.GET("/inventory-service/internal/ci-export/items", h.Items)
	internal.POST("/inventory-service/internal/ci-export/assets", h.Assets)
	internal.GET("/inventory-service/internal/ci-export/relationships", h.Relationships)
	internal.GET("/inventory-service/internal/ci-export/dcim/:class", h.DCIM)
}
