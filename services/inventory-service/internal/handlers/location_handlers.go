package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// locationService is the slice of *services.LocationService the location
// handlers depend on. Declaring it as an interface (the concrete service still
// satisfies it) lets the contract test drive the real handlers with an
// in-memory stub — no database — per the spec-first contract recipe (ADR-0001).
type locationService interface {
	List(tenantID uuid.UUID, filters models.LocationFilters) ([]models.Location, int, error)
	GetTree(tenantID uuid.UUID) ([]models.Location, error)
	Create(tenantID uuid.UUID, input models.LocationInput) (*models.Location, error)
	GetByIDWithChildren(tenantID, id uuid.UUID) (*models.Location, error)
	Update(tenantID, id uuid.UUID, input models.LocationInput) (*models.Location, error)
	Delete(tenantID, id uuid.UUID) error
	GetLocationAssets(tenantID, locationID uuid.UUID) ([]models.Asset, int, error)
	GetLocationSummary(tenantID, locationID uuid.UUID) (*models.LocationSummary, error)
}

type LocationHandler struct {
	locationService locationService
}

func NewLocationHandler(locationService *services.LocationService) *LocationHandler {
	return &LocationHandler{locationService: locationService}
}

func getTenantID(c *gin.Context) (uuid.UUID, bool) {
	tid, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	return tid, true
}

// GetLocations handles GET /inventory-service/locations
func (h *LocationHandler) GetLocations(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	var filters models.LocationFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}
	if filters.Tree {
		tree, err := h.locationService.GetTree(tenantID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get location tree"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"locations": tree})
		return
	}
	list, total, err := h.locationService.List(tenantID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list locations"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"locations": list, "total": total})
}

// GetLocationTree handles GET /inventory-service/locations/tree
func (h *LocationHandler) GetLocationTree(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	tree, err := h.locationService.GetTree(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get location tree"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"locations": tree})
}

// CreateLocation handles POST /inventory-service/locations
func (h *LocationHandler) CreateLocation(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	var input models.LocationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	loc, err := h.locationService.Create(tenantID, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create location"})
		return
	}
	c.JSON(http.StatusCreated, loc)
}

// GetLocation handles GET /inventory-service/locations/:id
func (h *LocationHandler) GetLocation(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	idStr := c.Param("id")
	if idStr == "tree" {
		// Handled by route order: tree must be registered before :id
		return
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid location ID"})
		return
	}
	loc, err := h.locationService.GetByIDWithChildren(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get location"})
		return
	}
	if loc == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Location not found"})
		return
	}
	c.JSON(http.StatusOK, loc)
}

// UpdateLocation handles PUT /inventory-service/locations/:id
func (h *LocationHandler) UpdateLocation(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid location ID"})
		return
	}
	var input models.LocationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	loc, err := h.locationService.Update(tenantID, id, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update location"})
		return
	}
	c.JSON(http.StatusOK, loc)
}

// DeleteLocation handles DELETE /inventory-service/locations/:id
func (h *LocationHandler) DeleteLocation(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid location ID"})
		return
	}
	if err := h.locationService.Delete(tenantID, id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	c.Status(http.StatusNoContent)
}

// GetLocationAssets handles GET /inventory-service/locations/:id/assets
func (h *LocationHandler) GetLocationAssets(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid location ID"})
		return
	}
	assets, total, err := h.locationService.GetLocationAssets(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get location assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"assets": assets, "total": total})
}

// GetLocationSummary handles GET /inventory-service/locations/:id/summary
func (h *LocationHandler) GetLocationSummary(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid location ID"})
		return
	}
	sum, err := h.locationService.GetLocationSummary(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get location summary"})
		return
	}
	if sum == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Location not found"})
		return
	}
	c.JSON(http.StatusOK, sum)
}
