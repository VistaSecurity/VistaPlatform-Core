package handlers

// POST /api/v1/inventory-service/internal/sightings (platform ADR-0003 D3
// step 2): how device-interrogation-service hands what it saw to the one
// identity engine host.
//
// Same gate as the internal source routes (source_import_handlers.go): an
// HMAC-signed service call naming one tenant in its signed X-Tenant-ID, on a
// group of its own behind RequireSignedServiceCall, under the
// /inventory-service/internal/ prefix the edge denies on every host
// (standards/service-registry.yaml internal_prefixes).

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// sightingIngester is the service behind the route; production passes
// *services.AssetService.
type sightingIngester interface {
	IngestSightings(ctx context.Context, tenantID uuid.UUID, items []services.SightingItem) ([]services.SightingResult, error)
}

// gatewayLinker is the service behind the gateway-links route; production
// passes *services.AssetService.
type gatewayLinker interface {
	ReconcileGatewayLinks(ctx context.Context, tenantID, assetID uuid.UUID, sourceRef string, observedAt time.Time, addresses []string) (pgidentity.GatewayLinkResult, error)
}

// SightingHandler serves the internal sightings route and the gateway-links
// route that follows an interrogation's claimed-address sightings.
type SightingHandler struct {
	svc   sightingIngester
	links gatewayLinker
}

// NewSightingHandler wires the handler. A nil service is the route tests'
// shape: every request they send stops before it is used.
func NewSightingHandler(svc *services.AssetService) *SightingHandler {
	if svc == nil {
		return &SightingHandler{}
	}
	return &SightingHandler{svc: svc, links: svc}
}

// sightingsRequest is the body of POST /internal/sightings.
type sightingsRequest struct {
	// Each item is a sighting's own fields plus an optional
	// target_asset_id (services.SightingItem).
	Sightings []services.SightingItem `json:"sightings"`
}

// IngestSightings — POST /inventory-service/internal/sightings
//
// One result per sighting, in order: {outcome, asset_id, observation_id,
// proposal_id, reasons}. A sighting naming another tenant, one the intake
// cannot read, or one with nothing usable is `rejected` with the reason; a
// store failure is a 500 the caller retries.
func (h *SightingHandler) IngestSightings(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sightingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Sightings) == 0 || len(req.Sightings) > services.MaxSightingsPerCall {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sightings must hold between 1 and " + strconv.Itoa(services.MaxSightingsPerCall) + " items"})
		return
	}
	results, err := h.svc.IngestSightings(c.Request.Context(), tenantID, req.Sightings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not resolve the sightings"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// gatewayLinksRequest is the body of POST /internal/gateway-links
// (sightingclient.GatewayLinksRequest on the caller's side).
type gatewayLinksRequest struct {
	AssetID    string    `json:"asset_id" binding:"required"`
	SourceRef  string    `json:"source_ref"`
	ObservedAt time.Time `json:"observed_at"`
	Addresses  []string  `json:"addresses"`
}

// maxGatewayLinkAddresses bounds one device's list: a device serving more
// networks than this is not a gateway this route was designed for.
const maxGatewayLinkAddresses = 1024

// ReconcileGatewayLinks — POST /inventory-service/internal/gateway-links
//
// One interrogation's COMPLETE list of the device's own addresses on the
// networks it serves ( slice B). The device becomes the gateway of every
// segment where it HOLDS one of them, scoped to that segment, and stops being
// the gateway of every segment where it no longer does; another device's link
// is never touched. Answers {linked, candidates, cleared}. A device that is not
// a live asset of the signed tenant is a 404.
func (h *SightingHandler) ReconcileGatewayLinks(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req gatewayLinksRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	assetID, err := uuid.Parse(req.AssetID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_id must be a uuid"})
		return
	}
	if len(req.Addresses) > maxGatewayLinkAddresses {
		c.JSON(http.StatusBadRequest, gin.H{"error": "addresses must hold at most " + strconv.Itoa(maxGatewayLinkAddresses) + " items"})
		return
	}
	if len(req.SourceRef) > pgidentity.MaxGatewaySourceRefLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source_ref must be at most " + strconv.Itoa(pgidentity.MaxGatewaySourceRefLen) + " characters"})
		return
	}
	res, err := h.links.ReconcileGatewayLinks(c.Request.Context(), tenantID, assetID, req.SourceRef, req.ObservedAt, req.Addresses)
	switch {
	case errors.Is(err, pgidentity.ErrGatewayAssetUnknown):
		c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
		return
	case err != nil:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not reconcile the gateway links"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// RegisterSightingRoutes mounts the routes on internal, which must be a group
// carrying RequireSignedServiceCall. The paths are written in full for the
// spec-route guard.
func RegisterSightingRoutes(internal *gin.RouterGroup, h *SightingHandler) {
	internal.POST("/inventory-service/internal/sightings", h.IngestSightings)
	internal.POST("/inventory-service/internal/gateway-links", h.ReconcileGatewayLinks)
}
