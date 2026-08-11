package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// operationalStore is the slice of *services.OperationalService the operational
// handlers depend on. Declaring it as an interface (the concrete service still
// satisfies it) lets the contract test drive the real handlers with an
// in-memory stub — no database — per the spec-first contract recipe (ADR-0001).
type operationalStore interface {
	GetLocationSummaries(tenantID uuid.UUID) ([]models.LocationFindingSummaryRow, error)
	GetLocationEnvironments(tenantID, locationID uuid.UUID) ([]models.EnvironmentSummary, error)
	GetEnvironmentAssets(tenantID, locationID uuid.UUID, environment string, page, pageSize int) ([]models.Asset, int, error)
	GetRemediationQueue(tenantID uuid.UUID, filters models.RemediationQueueFilters) ([]models.RemediationQueueRow, int, error)
	GetRemediationQueueStats(tenantID uuid.UUID) (bySeverity map[string]int, byFindingType map[string]int, total int, err error)
}

// OperationalHandler provides v2 operational overview and remediation queue endpoints.
type OperationalHandler struct {
	operational operationalStore
	templates   *services.RemediationTemplateService
}

// NewOperationalHandler returns a new operational handler.
func NewOperationalHandler(operational *services.OperationalService, templates *services.RemediationTemplateService) *OperationalHandler {
	return &OperationalHandler{operational: operational, templates: templates}
}

// GetLocationsSummary handles GET /inventory-service/operational/locations-summary
func (h *OperationalHandler) GetLocationsSummary(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	rows, err := h.operational.GetLocationSummaries(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get location summaries"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"locations_summary": rows})
}

// GetLocationEnvironments handles GET /inventory-service/operational/locations/:id/environments
func (h *OperationalHandler) GetLocationEnvironments(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid location id"})
		return
	}
	envs, err := h.operational.GetLocationEnvironments(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get environments"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"environments": envs})
}

// GetEnvironmentAssets handles GET /inventory-service/operational/locations/:id/environments/:env/assets
func (h *OperationalHandler) GetEnvironmentAssets(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	idStr := c.Param("id")
	locationID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid location id"})
		return
	}
	env := c.Param("env")
	if env == "" {
		env = "production"
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	assets, total, err := h.operational.GetEnvironmentAssets(tenantID, locationID, env, page, pageSize)
	if err != nil {
		log.Printf("[operational] GetEnvironmentAssets: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"assets": assets, "total": total, "page": page, "page_size": pageSize})
}

// GetRemediationQueue handles GET /inventory-service/operational/remediation-queue
func (h *OperationalHandler) GetRemediationQueue(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	var filters models.RemediationQueueFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query parameters"})
		return
	}
	rows, total, err := h.operational.GetRemediationQueue(tenantID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get remediation queue"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rows, "total": total, "page": filters.Page, "page_size": filters.PageSize})
}

// GetRemediationStats handles GET /inventory-service/operational/remediation-queue/stats
func (h *OperationalHandler) GetRemediationStats(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	bySeverity, byFindingType, total, err := h.operational.GetRemediationQueueStats(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get stats"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"by_severity":     bySeverity,
		"by_finding_type": byFindingType,
		"total":           total,
	})
}

// GetRemediationTemplates handles GET /inventory-service/operational/remediation-templates
func (h *OperationalHandler) GetRemediationTemplates(c *gin.Context) {
	templates := h.templates.GetTemplates()
	c.JSON(http.StatusOK, gin.H{"templates": templates})
}
