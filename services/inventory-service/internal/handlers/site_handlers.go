package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

func getTenantID(c *gin.Context) (uuid.UUID, bool) {
	tid, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	return tid, true
}

// getOptionalUserID returns the authenticated user's id, or uuid.Nil when the
// request carries none (change recording then attributes the write to the
// system).
func getOptionalUserID(c *gin.Context) uuid.UUID {
	userID, exists := c.Get("userID")
	if !exists {
		return uuid.Nil
	}
	if u, ok := userID.(uuid.UUID); ok {
		return u
	}
	if s, ok := userID.(string); ok {
		if parsed, err := uuid.Parse(s); err == nil {
			return parsed
		}
	}
	return uuid.Nil
}

// siteService is the slice of *services.SiteService the handlers depend on.
type siteService interface {
	ListRegions(ctx context.Context, tenantID uuid.UUID) ([]models.Region, error)
	GetRegion(ctx context.Context, tenantID, id uuid.UUID) (*models.Region, error)
	CreateRegion(ctx context.Context, tenantID, actor uuid.UUID, in models.RegionInput) (*models.Region, error)
	UpdateRegion(ctx context.Context, tenantID, actor, id uuid.UUID, in models.RegionInput) (*models.Region, error)
	DeleteRegion(ctx context.Context, tenantID, actor, id uuid.UUID) error

	ListSiteGroups(ctx context.Context, tenantID uuid.UUID) ([]models.SiteGroup, error)
	GetSiteGroup(ctx context.Context, tenantID, id uuid.UUID) (*models.SiteGroup, error)
	CreateSiteGroup(ctx context.Context, tenantID, actor uuid.UUID, in models.RegionInput) (*models.SiteGroup, error)
	UpdateSiteGroup(ctx context.Context, tenantID, actor, id uuid.UUID, in models.RegionInput) (*models.SiteGroup, error)
	DeleteSiteGroup(ctx context.Context, tenantID, actor, id uuid.UUID) error

	ListSites(ctx context.Context, tenantID uuid.UUID, f models.SiteFilters) ([]models.Site, error)
	GetSite(ctx context.Context, tenantID, id uuid.UUID) (*models.Site, error)
	CreateSite(ctx context.Context, tenantID, actor uuid.UUID, in models.SiteInput) (*models.Site, error)
	UpdateSite(ctx context.Context, tenantID, actor, id uuid.UUID, in models.SiteInput) (*models.Site, error)
	DeleteSite(ctx context.Context, tenantID, actor, id uuid.UUID, reassignTo *uuid.UUID) error

	ListLocations(ctx context.Context, tenantID uuid.UUID, siteID *uuid.UUID) ([]models.Location, error)
	GetLocation(ctx context.Context, tenantID, id uuid.UUID) (*models.Location, error)
	CreateLocation(ctx context.Context, tenantID, actor uuid.UUID, in models.LocationInput) (*models.Location, error)
	UpdateLocation(ctx context.Context, tenantID, actor, id uuid.UUID, in models.LocationInput) (*models.Location, error)
	DeleteLocation(ctx context.Context, tenantID, actor, id uuid.UUID) error
	LocationFloorPlan(ctx context.Context, tenantID, id uuid.UUID) (*services.LocationFloorPlan, error)
}

// SiteHandler serves /api/v2/inventory-service/dcim/{regions,site-groups,sites,locations}.
type SiteHandler struct{ svc siteService }

// NewSiteHandler returns the handler over the real service.
func NewSiteHandler(svc *services.SiteService) *SiteHandler { return &SiteHandler{svc: svc} }

func siteRespondError(c *gin.Context, err error) {
	var inUse *services.SiteInUseError
	switch {
	case errors.As(err, &inUse):
		c.JSON(http.StatusConflict, gin.H{"error": inUse.Error(), "assets": inUse.Assets})
	case errors.Is(err, services.ErrSiteNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": capitalise(err.Error())})
	case errors.Is(err, services.ErrSiteConflict):
		c.JSON(http.StatusConflict, gin.H{"error": strings.TrimPrefix(err.Error(), "already exists: ")})
	case errors.Is(err, services.ErrSiteInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": strings.TrimPrefix(err.Error(), "invalid: ")})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Request failed"})
	}
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func pathID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid id"})
		return uuid.Nil, false
	}
	return id, true
}

func queryUUID(c *gin.Context, name string) (*uuid.UUID, bool) {
	raw := strings.TrimSpace(c.Query(name))
	if raw == "" {
		return nil, true
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": name + " is not a uuid"})
		return nil, false
	}
	return &id, true
}

// respond writes v as JSON with status, or the mapped error.
func respond(c *gin.Context, status int, v any, err error) {
	if err != nil {
		siteRespondError(c, err)
		return
	}
	c.JSON(status, v)
}

func bindInput[T any](c *gin.Context) (T, bool) {
	var in T
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return in, false
	}
	return in, true
}

// ---- regions ----

// ListRegions handles GET /dcim/regions.
func (h *SiteHandler) ListRegions(c *gin.Context) {
	tid, ok := getTenantID(c)
	if !ok {
		return
	}
	l, err := h.svc.ListRegions(c.Request.Context(), tid)
	respond(c, http.StatusOK, gin.H{"regions": l, "total": len(l)}, err)
}

// GetRegion handles GET /dcim/regions/:id.
func (h *SiteHandler) GetRegion(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	v, err := h.svc.GetRegion(c.Request.Context(), tid, id)
	respond(c, http.StatusOK, v, err)
}

// CreateRegion handles POST /dcim/regions.
func (h *SiteHandler) CreateRegion(c *gin.Context) {
	tid, ok := getTenantID(c)
	if !ok {
		return
	}
	in, ok := bindInput[models.RegionInput](c)
	if !ok {
		return
	}
	v, err := h.svc.CreateRegion(c.Request.Context(), tid, getOptionalUserID(c), in)
	respond(c, http.StatusCreated, v, err)
}

// UpdateRegion handles PUT /dcim/regions/:id (a patch).
func (h *SiteHandler) UpdateRegion(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	in, ok := bindInput[models.RegionInput](c)
	if !ok {
		return
	}
	v, err := h.svc.UpdateRegion(c.Request.Context(), tid, getOptionalUserID(c), id, in)
	respond(c, http.StatusOK, v, err)
}

// DeleteRegion handles DELETE /dcim/regions/:id.
func (h *SiteHandler) DeleteRegion(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	if err := h.svc.DeleteRegion(c.Request.Context(), tid, getOptionalUserID(c), id); err != nil {
		siteRespondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- site groups ----

// ListSiteGroups handles GET /dcim/site-groups.
func (h *SiteHandler) ListSiteGroups(c *gin.Context) {
	tid, ok := getTenantID(c)
	if !ok {
		return
	}
	l, err := h.svc.ListSiteGroups(c.Request.Context(), tid)
	respond(c, http.StatusOK, gin.H{"site_groups": l, "total": len(l)}, err)
}

// GetSiteGroup handles GET /dcim/site-groups/:id.
func (h *SiteHandler) GetSiteGroup(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	v, err := h.svc.GetSiteGroup(c.Request.Context(), tid, id)
	respond(c, http.StatusOK, v, err)
}

// CreateSiteGroup handles POST /dcim/site-groups.
func (h *SiteHandler) CreateSiteGroup(c *gin.Context) {
	tid, ok := getTenantID(c)
	if !ok {
		return
	}
	in, ok := bindInput[models.RegionInput](c)
	if !ok {
		return
	}
	v, err := h.svc.CreateSiteGroup(c.Request.Context(), tid, getOptionalUserID(c), in)
	respond(c, http.StatusCreated, v, err)
}

// UpdateSiteGroup handles PUT /dcim/site-groups/:id (a patch).
func (h *SiteHandler) UpdateSiteGroup(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	in, ok := bindInput[models.RegionInput](c)
	if !ok {
		return
	}
	v, err := h.svc.UpdateSiteGroup(c.Request.Context(), tid, getOptionalUserID(c), id, in)
	respond(c, http.StatusOK, v, err)
}

// DeleteSiteGroup handles DELETE /dcim/site-groups/:id.
func (h *SiteHandler) DeleteSiteGroup(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	if err := h.svc.DeleteSiteGroup(c.Request.Context(), tid, getOptionalUserID(c), id); err != nil {
		siteRespondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- sites ----

// ListSites handles GET /dcim/sites?region_id=&group_id=&q=.
func (h *SiteHandler) ListSites(c *gin.Context) {
	tid, ok := getTenantID(c)
	if !ok {
		return
	}
	region, ok := queryUUID(c, "region_id")
	if !ok {
		return
	}
	group, ok := queryUUID(c, "group_id")
	if !ok {
		return
	}
	l, err := h.svc.ListSites(c.Request.Context(), tid, models.SiteFilters{RegionID: region, GroupID: group, Q: c.Query("q")})
	respond(c, http.StatusOK, gin.H{"sites": l, "total": len(l)}, err)
}

// GetSite handles GET /dcim/sites/:id (with counts).
func (h *SiteHandler) GetSite(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	v, err := h.svc.GetSite(c.Request.Context(), tid, id)
	respond(c, http.StatusOK, v, err)
}

// CreateSite handles POST /dcim/sites.
func (h *SiteHandler) CreateSite(c *gin.Context) {
	tid, ok := getTenantID(c)
	if !ok {
		return
	}
	in, ok := bindInput[models.SiteInput](c)
	if !ok {
		return
	}
	v, err := h.svc.CreateSite(c.Request.Context(), tid, getOptionalUserID(c), in)
	respond(c, http.StatusCreated, v, err)
}

// UpdateSite handles PUT /dcim/sites/:id (a patch).
func (h *SiteHandler) UpdateSite(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	in, ok := bindInput[models.SiteInput](c)
	if !ok {
		return
	}
	v, err := h.svc.UpdateSite(c.Request.Context(), tid, getOptionalUserID(c), id, in)
	respond(c, http.StatusOK, v, err)
}

// DeleteSite handles DELETE /dcim/sites/:id?reassign_to=<site id>. 409 when
// assets are in the site and no target is given.
func (h *SiteHandler) DeleteSite(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	reassign, ok := queryUUID(c, "reassign_to")
	if !ok {
		return
	}
	if err := h.svc.DeleteSite(c.Request.Context(), tid, getOptionalUserID(c), id, reassign); err != nil {
		siteRespondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- locations ----

// ListLocations handles GET /dcim/locations?site_id=.
func (h *SiteHandler) ListLocations(c *gin.Context) {
	tid, ok := getTenantID(c)
	if !ok {
		return
	}
	site, ok := queryUUID(c, "site_id")
	if !ok {
		return
	}
	l, err := h.svc.ListLocations(c.Request.Context(), tid, site)
	respond(c, http.StatusOK, gin.H{"locations": l, "total": len(l)}, err)
}

// GetLocation handles GET /dcim/locations/:id.
func (h *SiteHandler) GetLocation(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	v, err := h.svc.GetLocation(c.Request.Context(), tid, id)
	respond(c, http.StatusOK, v, err)
}

// CreateLocation handles POST /dcim/locations.
func (h *SiteHandler) CreateLocation(c *gin.Context) {
	tid, ok := getTenantID(c)
	if !ok {
		return
	}
	in, ok := bindInput[models.LocationInput](c)
	if !ok {
		return
	}
	v, err := h.svc.CreateLocation(c.Request.Context(), tid, getOptionalUserID(c), in)
	respond(c, http.StatusCreated, v, err)
}

// UpdateLocation handles PUT /dcim/locations/:id (a patch).
func (h *SiteHandler) UpdateLocation(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	in, ok := bindInput[models.LocationInput](c)
	if !ok {
		return
	}
	v, err := h.svc.UpdateLocation(c.Request.Context(), tid, getOptionalUserID(c), id, in)
	respond(c, http.StatusOK, v, err)
}

// DeleteLocation handles DELETE /dcim/locations/:id.
func (h *SiteHandler) DeleteLocation(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	if err := h.svc.DeleteLocation(c.Request.Context(), tid, getOptionalUserID(c), id); err != nil {
		siteRespondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
