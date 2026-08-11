package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// assetApprovalStore is the narrow persistence surface the approval handler needs.
// *services.AssetService satisfies it in production; the contract test passes an
// in-memory stub (mirrors cbom-service/scopes' scopeStore pattern).
type assetApprovalStore interface {
	ApproveAssets(tenantID uuid.UUID, assetIDs []uuid.UUID) error
	DenyAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, userID uuid.UUID) error
}

type AssetApprovalHandler struct {
	assetService assetApprovalStore
}

func NewAssetApprovalHandler(assetService assetApprovalStore) *AssetApprovalHandler {
	return &AssetApprovalHandler{assetService: assetService}
}

type approvalRequest struct {
	AssetIDs []string `json:"asset_ids" binding:"required"`
}

// ApproveAssets moves assets from pending_approval to monitoring
func (h *AssetApprovalHandler) ApproveAssets(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant not found"})
		return
	}
	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}

	var req approvalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var ids []uuid.UUID
	for _, idStr := range req.AssetIDs {
		if id, err := uuid.Parse(idStr); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid asset ids provided"})
		return
	}

	if err := h.assetService.ApproveAssets(tenantID, ids); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve assets"})
		return
	}

	// Log audit event
	resourceType := "asset"
	for _, assetID := range ids {
		logAuditActivity(c, "asset.approved", "asset", "approve", &resourceType, &assetID, nil, map[string]interface{}{
			"status":      "monitoring",
			"approved_at": time.Now(),
		}, []string{"status"}, map[string]interface{}{
			"asset_count": len(ids),
		})
	}

	c.JSON(http.StatusOK, gin.H{"message": "assets approved", "count": len(ids)})
}

// DenyAssets moves assets to denied and suppresses rediscovery
func (h *AssetApprovalHandler) DenyAssets(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant not found"})
		return
	}
	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}

	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var req approvalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var ids []uuid.UUID
	for _, idStr := range req.AssetIDs {
		if id, err := uuid.Parse(idStr); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid asset ids provided"})
		return
	}

	if err := h.assetService.DenyAssets(tenantID, ids, userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deny assets"})
		return
	}

	// Log audit event
	resourceType := "asset"
	for _, assetID := range ids {
		logAuditActivity(c, "asset.denied", "asset", "deny", &resourceType, &assetID, nil, map[string]interface{}{
			"status":    "denied",
			"denied_at": time.Now(),
		}, []string{"status"}, map[string]interface{}{
			"asset_count": len(ids),
		})
	}

	c.JSON(http.StatusOK, gin.H{"message": "assets denied", "count": len(ids)})
}
