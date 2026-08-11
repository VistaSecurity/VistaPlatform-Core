package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// alertCatalogService is the narrow surface the HTTP handler depends on (not
// the concrete *services.AlertCatalogService) so it can be exercised against
// an in-memory stub — no database — in the spec-first contract test
// (alert_catalog_contract_test.go, ADR-0001), same pattern as alertEngine in
// alert_handlers.go. The concrete *services.AlertCatalogService satisfies it;
// production wiring in cmd/main.go is unchanged.
type alertCatalogService interface {
	GetCatalog(ctx context.Context, tenantID uuid.UUID) ([]services.CatalogEntry, error)
	UpdateSetting(ctx context.Context, tenantID uuid.UUID, alertType string, enabled bool, preferenceRung map[string]int, updatedBy uuid.UUID) error
}

// AlertCatalogHandlers serves the tenant alert catalog (Settings → Alert
// Rules): registry types overlaid with tenant enable/preference state and,
// for ladder types, the effective rung ladder including policy rungs.
type AlertCatalogHandlers struct {
	catalog alertCatalogService
}

func NewAlertCatalogHandlers(catalog *services.AlertCatalogService) *AlertCatalogHandlers {
	return &AlertCatalogHandlers{catalog: catalog}
}

// GetCatalog returns the tenant-track catalog.
// GET /alert-catalog
func (h *AlertCatalogHandlers) GetCatalog(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	catalog, err := h.catalog.GetCatalog(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load alert catalog"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"catalog": catalog})
}

// UpdateCatalogEntry updates enable/preference state for one alert type.
// PUT /alert-catalog/:type  body: { "enabled": bool, "preference_rung": {"days": 45} | null }
func (h *AlertCatalogHandlers) UpdateCatalogEntry(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	userID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}
	var body struct {
		Enabled        *bool          `json:"enabled" binding:"required"`
		PreferenceRung map[string]int `json:"preference_rung"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled is required"})
		return
	}
	if err := h.catalog.UpdateSetting(c.Request.Context(), tenantID, c.Param("type"),
		*body.Enabled, body.PreferenceRung, userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}
