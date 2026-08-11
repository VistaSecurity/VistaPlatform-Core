package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// externalConnectionsStore is the slice of *services.ExternalConnectionsService
// the connections handlers depend on. Declaring it as an interface (the
// concrete service satisfies it) lets the contract test drive the real handlers
// with an in-memory stub — no database — per the spec-first contract recipe
// (ADR-0001). It is the union of every service method the handlers call.
type externalConnectionsStore interface {
	Upsert(tenantID uuid.UUID, input models.ExternalConnectionUpsert) (*models.ExternalConnection, error)
	List(tenantID uuid.UUID, f models.ExternalConnectionFilters) ([]models.ExternalConnection, int, error)
	GetByID(tenantID, id uuid.UUID) (*models.ExternalConnection, error)
	GetHistory(tenantID, connectionID uuid.UUID, page, pageSize int) ([]models.ExternalConnectionHistory, int, error)
	GetSummary(tenantID uuid.UUID) (*models.ExternalConnectionsSummary, error)
	Delete(tenantID, id uuid.UUID) error
}

// ExternalConnectionsHandler handles external connections API routes.
type ExternalConnectionsHandler struct {
	service externalConnectionsStore
}

// NewExternalConnectionsHandler creates a new handler. Production callers pass
// the concrete *services.ExternalConnectionsService, which satisfies
// externalConnectionsStore; the contract test passes an in-memory stub.
func NewExternalConnectionsHandler(service *services.ExternalConnectionsService) *ExternalConnectionsHandler {
	return &ExternalConnectionsHandler{service: service}
}

// UpsertExternalConnection handles POST /external-connections (internal service call only).
func (h *ExternalConnectionsHandler) UpsertExternalConnection(c *gin.Context) {
	tenantID, err := tenantIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var input models.ExternalConnectionUpsert
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	conn, err := h.service.Upsert(tenantID, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upsert external connection"})
		return
	}
	c.JSON(http.StatusOK, conn)
}

// ListExternalConnections handles GET /external-connections.
func (h *ExternalConnectionsHandler) ListExternalConnections(c *gin.Context) {
	tenantID, err := tenantIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var f models.ExternalConnectionFilters
	if err := c.ShouldBindQuery(&f); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}
	// Apply shared pagination defaults and bounds
	pg := sharedapi.ParsePagination(c)
	f.Page = pg.Page
	f.PageSize = pg.PageSize

	// Parse bool query params manually (ShouldBindQuery doesn't handle *bool cleanly)
	if pqc := c.Query("is_pqc_resistant"); pqc != "" {
		if b, err := strconv.ParseBool(pqc); err == nil {
			f.IsPQCResistant = &b
		}
	}
	if exp := c.Query("cert_expired"); exp != "" {
		if b, err := strconv.ParseBool(exp); err == nil {
			f.CertExpired = &b
		}
	}
	if legacy := c.Query("has_legacy_tls"); legacy != "" {
		if b, err := strconv.ParseBool(legacy); err == nil {
			f.HasLegacyTLS = &b
		}
	}
	if trust := c.Query("cert_trust_issue"); trust != "" {
		if b, err := strconv.ParseBool(trust); err == nil {
			f.CertTrustIssue = &b
		}
	}
	if srcID := c.Query("source_asset_id"); srcID != "" {
		if id, err := uuid.Parse(srcID); err == nil {
			f.SourceAssetID = &id
		}
	}

	list, total, err := h.service.List(tenantID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list external connections"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"connections": list,
		"pagination":  sharedapi.BuildPaginationMeta(pg, int64(total)),
	})
}

// GetExternalConnectionsSummary handles GET /external-connections/summary.
func (h *ExternalConnectionsHandler) GetExternalConnectionsSummary(c *gin.Context) {
	tenantID, err := tenantIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	summary, err := h.service.GetSummary(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get summary"})
		return
	}
	c.JSON(http.StatusOK, summary)
}

// GetExternalConnection handles GET /external-connections/:id.
func (h *ExternalConnectionsHandler) GetExternalConnection(c *gin.Context) {
	tenantID, err := tenantIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	conn, err := h.service.GetByID(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get external connection"})
		return
	}
	if conn == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	c.JSON(http.StatusOK, conn)
}

// GetExternalConnectionHistory handles GET /external-connections/:id/history.
func (h *ExternalConnectionsHandler) GetExternalConnectionHistory(c *gin.Context) {
	tenantID, err := tenantIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	pg := sharedapi.ParsePagination(c)

	history, total, err := h.service.GetHistory(tenantID, id, pg.Page, pg.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get history"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"history":    history,
		"pagination": sharedapi.BuildPaginationMeta(pg, int64(total)),
	})
}

// DeleteExternalConnection handles DELETE /external-connections/:id.
func (h *ExternalConnectionsHandler) DeleteExternalConnection(c *gin.Context) {
	tenantID, err := tenantIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	if err := h.service.Delete(tenantID, id); err != nil {
		if err.Error() == "external connection not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete external connection"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Deleted"})
}

// tenantIDFromContext extracts the tenant UUID from Gin context.
func tenantIDFromContext(c *gin.Context) (uuid.UUID, error) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		return uuid.UUID{}, fmt.Errorf("tenant ID not found in context")
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		return uuid.UUID{}, fmt.Errorf("invalid tenant ID type")
	}
	return tenantUUID, nil
}
