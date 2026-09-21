package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// assetApprovalStore is the narrow persistence surface the approval handler needs.
// *services.AssetService satisfies it in production; the contract test passes an
// in-memory stub (mirrors cbom-service/scopes' scopeStore pattern).
type assetApprovalStore interface {
	ApproveAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, actorUserID uuid.UUID) error
	DenyAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, userID uuid.UUID) error
	// AutoApproveAgentHost admits the host a tenant's device agent runs on.
	// See services.AssetService.AutoApproveAgentHost for the rules.
	AutoApproveAgentHost(tenantID, assetID, agentID uuid.UUID) (bool, error)
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

	if err := h.assetService.ApproveAssets(tenantID, ids, approvalActor(c)); err != nil {
		if errors.Is(err, services.ErrAssetLifecycleConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
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
		if errors.Is(err, services.ErrAssetLifecycleConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
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

// approvalActor is the person deciding, or uuid.Nil when the session carries no
// user. Nil writes NULL to `asset_history.actor_user_id`, which is the honest
// value: empty is "no person was involved", not "the system".
func approvalActor(c *gin.Context) uuid.UUID {
	v, ok := c.Get("userID")
	if !ok {
		return uuid.Nil
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}

// agentHostApprovalRequest is the wire shape of the INTERNAL agent-host
// approval. One asset, one agent: a local host inventory is about one host.
type agentHostApprovalRequest struct {
	AssetID string `json:"asset_id" binding:"required"`
	AgentID string `json:"agent_id" binding:"required"`
}

// AutoApproveAgentHost — POST /inventory-service/assets/auto-approve/agent-host.
//
// INTERNAL ONLY. device-interrogation-service calls it after a LOCAL host
// inventory — the agent's own account of the machine it is installed on — has
// landed on a pending asset. It is the same transport rule as the discovery
// import route: the handler refuses anything that is not an HMAC-verified
// service call, and no tenant permission gates it because an internal call
// carries the "system" sentinel rather than a user. The tenant comes from the
// X-Tenant-ID header the auth middleware honours for verified internal calls.
//
// Not in the OpenAPI contract; no browser calls it. A tenant user who wants a
// host approved has Discovery → Approvals.
//
// `approved: false` with 200 is a normal answer, not a failure — the host was
// already monitoring, or was denied, or is not in the queue — and the agent
// that asked will ask again on its next scheduled report.
func (h *AssetApprovalHandler) AutoApproveAgentHost(c *gin.Context) {
	if !sharedmw.IsInternalCall(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "agent-host approval is an internal service call"})
		return
	}
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

	var req agentHostApprovalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	assetID, err := uuid.Parse(req.AssetID)
	if err != nil || assetID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset id"})
		return
	}
	agentID, err := uuid.Parse(req.AgentID)
	if err != nil || agentID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	approved, err := h.assetService.AutoApproveAgentHost(tenantID, assetID, agentID)
	if err != nil {
		if errors.Is(err, services.ErrAssetLifecycleConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve agent host", "approved": approved})
		return
	}
	c.JSON(http.StatusOK, gin.H{"approved": approved, "asset_id": assetID.String(), "approved_at": time.Now().UTC()})
}
