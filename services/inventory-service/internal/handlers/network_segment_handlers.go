package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// networkSegmentService is the slice of *services.NetworkSegmentService the
// handlers depend on. Declaring it as an interface (the concrete service still
// satisfies it) lets the contract test drive the real handlers with an
// in-memory stub — no database — per the spec-first contract recipe (ADR-0001).
type networkSegmentService interface {
	List(tenantID uuid.UUID, filters models.NetworkSegmentFilters) ([]models.NetworkSegment, int, error)
	GetByID(tenantID, id uuid.UUID) (*models.NetworkSegment, error)
	Create(tenantID uuid.UUID, input models.NetworkSegmentInput) (*models.NetworkSegment, error)
	BulkCreate(tenantID uuid.UUID, inputs []models.NetworkSegmentInput) *models.BulkImportResult
	Update(tenantID, id uuid.UUID, input models.NetworkSegmentInput) (*models.NetworkSegment, error)
	Delete(tenantID, id uuid.UUID) error
	ManageAutoApprovalRules(tenantID, userID uuid.UUID) error
	GetSegmentForIP(tenantID uuid.UUID, ipAddress *string, hostname *string) (*models.NetworkSegment, error)
	ClassifyAsset(tenantID uuid.UUID, ipAddress *string, hostname *string, fqdns []string) (string, error)
	ReclassifyAllAssets(tenantID uuid.UUID) (int, error)
	MigrateFromNetworkSpaces(tenantID uuid.UUID) (int, error)
}

type NetworkSegmentHandler struct {
	segmentService networkSegmentService
}

func NewNetworkSegmentHandler(segmentService *services.NetworkSegmentService) *NetworkSegmentHandler {
	return &NetworkSegmentHandler{segmentService: segmentService}
}

// getOptionalUserID returns the request user ID from context, or uuid.Nil if not set (e.g. service-to-service).
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

// GetNetworkSegments handles GET /inventory-service/network-segments
func (h *NetworkSegmentHandler) GetNetworkSegments(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	var filters models.NetworkSegmentFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}
	list, total, err := h.segmentService.List(tenantID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list network segments"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"network_segments": list, "total": total})
}

// CreateNetworkSegment handles POST /inventory-service/network-segments
func (h *NetworkSegmentHandler) CreateNetworkSegment(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	var input models.NetworkSegmentInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	seg, err := h.segmentService.Create(tenantID, input)
	if err != nil {
		if err.Error() == "location not found" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create network segment"})
		return
	}
	if err := h.segmentService.ManageAutoApprovalRules(tenantID, getOptionalUserID(c)); err != nil {
		_ = err
	}
	if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok {
		desc := ""
		if seg.Description != nil {
			desc = *seg.Description
		}
		_ = audithelpers.LogWithContext(
			c.Request.Context(), mw,
			audithelpers.EventTypeNetworkSegmentCreated, audithelpers.EventCategoryAsset,
			"create", "network_segment", seg.ID.String(), seg.Value,
			nil, seg,
			audithelpers.AuditMetadata{
				ResourceName: seg.Name, BusinessContext: desc,
				ChangeSummary: "Network segment created: " + seg.NetworkType,
				AdditionalData: map[string]interface{}{
					"network_type": seg.NetworkType, "auto_approve_discoveries": seg.AutoApproveDiscoveries,
					"is_active": seg.IsActive,
				},
			},
		)
	}
	c.JSON(http.StatusCreated, seg)
}

// CreateNetworkSegmentsBulk handles POST /inventory-service/network-segments/bulk.
// It creates many segments from a parsed spreadsheet in one request, returning a
// per-row result (created / skipped / failed). Per-row value validation and
// dedupe happen in the service. After import it refreshes auto-approval rules
// once, mirroring single creation.
func (h *NetworkSegmentHandler) CreateNetworkSegmentsBulk(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	var req models.NetworkSegmentBulkImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if len(req.Rows) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No rows to import"})
		return
	}
	if len(req.Rows) > maxBulkImportRows {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": "Too many rows (max " + strconv.Itoa(maxBulkImportRows) + " per import)",
		})
		return
	}

	res := h.segmentService.BulkCreate(tenantID, req.Rows)

	// Re-derive auto-approval rules once for the whole batch, not per row.
	if res.Created > 0 {
		if err := h.segmentService.ManageAutoApprovalRules(tenantID, getOptionalUserID(c)); err != nil {
			_ = err
		}
	}

	if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok {
		_ = audithelpers.LogWithContext(
			c.Request.Context(), mw,
			audithelpers.EventTypeNetworkSegmentCreated, audithelpers.EventCategoryAsset,
			"create", "network_segment", "", "",
			nil, res,
			audithelpers.AuditMetadata{
				ChangeSummary: "Network segments imported from spreadsheet",
				AdditionalData: map[string]interface{}{
					"created": res.Created, "skipped": res.Skipped, "failed": res.Failed,
				},
			},
		)
	}

	c.JSON(http.StatusOK, res)
}

// GetNetworkSegment handles GET /inventory-service/network-segments/:id
func (h *NetworkSegmentHandler) GetNetworkSegment(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid segment ID"})
		return
	}
	seg, err := h.segmentService.GetByID(tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get network segment"})
		return
	}
	if seg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Network segment not found"})
		return
	}
	c.JSON(http.StatusOK, seg)
}

// UpdateNetworkSegment handles PUT /inventory-service/network-segments/:id
func (h *NetworkSegmentHandler) UpdateNetworkSegment(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid segment ID"})
		return
	}
	var input models.NetworkSegmentInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	seg, err := h.segmentService.Update(tenantID, id, input)
	if err != nil {
		if err.Error() == "location not found" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		if err.Error() == "network segment not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update network segment"})
		return
	}
	if err := h.segmentService.ManageAutoApprovalRules(tenantID, getOptionalUserID(c)); err != nil {
		_ = err
	}
	if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok {
		desc := ""
		if seg.Description != nil {
			desc = *seg.Description
		}
		_ = audithelpers.LogWithContext(
			c.Request.Context(), mw,
			audithelpers.EventTypeNetworkSegmentUpdated, audithelpers.EventCategoryAsset,
			"update", "network_segment", seg.ID.String(), seg.Value,
			nil, seg,
			audithelpers.AuditMetadata{
				ResourceName: seg.Name, BusinessContext: desc,
				ChangeSummary: "Network segment updated",
				AdditionalData: map[string]interface{}{
					"network_type": seg.NetworkType, "auto_approve_discoveries": seg.AutoApproveDiscoveries,
					"is_active": seg.IsActive,
				},
			},
		)
	}
	c.JSON(http.StatusOK, seg)
}

// DeleteNetworkSegment handles DELETE /inventory-service/network-segments/:id
func (h *NetworkSegmentHandler) DeleteNetworkSegment(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid segment ID"})
		return
	}
	seg, _ := h.segmentService.GetByID(tenantID, id)
	err = h.segmentService.Delete(tenantID, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Network segment not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete network segment"})
		return
	}
	if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok && seg != nil {
		_ = audithelpers.LogSimple(
			c.Request.Context(), mw,
			audithelpers.EventTypeNetworkSegmentDeleted, audithelpers.EventCategoryAsset,
			"delete", "network_segment", id.String(), seg.Value, true, "",
		)
	}
	c.Status(http.StatusNoContent)
}

// ClassifyAsset handles POST /inventory-service/network-segments/classify-asset
func (h *NetworkSegmentHandler) ClassifyAsset(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	var req models.ClassifyAssetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	seg, err := h.segmentService.GetSegmentForIP(tenantID, req.IPAddress, req.Hostname)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to classify asset"})
		return
	}
	ownership, err := h.segmentService.ClassifyAsset(tenantID, req.IPAddress, req.Hostname, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to classify asset"})
		return
	}
	resp := gin.H{"segment": seg, "ownership": ownership}
	if seg != nil {
		resp["segment_id"] = seg.ID
		resp["segment_name"] = seg.Name
		resp["network_type"] = seg.NetworkType
	} else {
		resp["network_type"] = "public"
	}
	c.JSON(http.StatusOK, resp)
}

// ReclassifyAllAssets handles POST /inventory-service/network-segments/reclassify-all
func (h *NetworkSegmentHandler) ReclassifyAllAssets(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	updated, err := h.segmentService.ReclassifyAllAssets(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reclassify assets"})
		return
	}
	if err := h.segmentService.ManageAutoApprovalRules(tenantID, getOptionalUserID(c)); err != nil {
		_ = err
	}
	if mw, ok := audithelpers.ExtractAuditMiddleware(c); ok {
		_ = audithelpers.LogSimple(
			c.Request.Context(), mw,
			audithelpers.EventTypeNetworkSegmentAssetTagged, audithelpers.EventCategoryAsset,
			"bulk_classify", "network_segment", "", "all_assets", true, "",
		)
	}
	c.JSON(http.StatusOK, gin.H{"updated": updated})
}

// MigrateFromNetworkSpaces handles POST /inventory-service/network-segments/migrate-from-spaces
func (h *NetworkSegmentHandler) MigrateFromNetworkSpaces(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	migrated, err := h.segmentService.MigrateFromNetworkSpaces(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to migrate from network spaces"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"migrated": migrated})
}
