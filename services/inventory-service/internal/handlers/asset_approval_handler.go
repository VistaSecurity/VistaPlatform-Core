package handlers

import (
	"errors"
	"fmt"
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
	ApproveAssetsReport(tenantID uuid.UUID, assetIDs []uuid.UUID, actorUserID uuid.UUID) (services.LifecycleChangeResult, error)
	DenyAssetsReport(tenantID uuid.UUID, assetIDs []uuid.UUID, userID uuid.UUID) (services.LifecycleChangeResult, error)
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

// maxApprovalAssetIDs caps one approve/deny request, matching merge proposals.
// Each id costs a history row, an event and a deferred-crypto replay.
const maxApprovalAssetIDs = 200

// parseApprovalIDs validates the id list of an approve/deny request. It writes
// the 400/413 itself and reports ok=false; otherwise it returns the parseable
// ids and the strings that were not UUIDs, which the response reports back
// rather than silently dropping.
func parseApprovalIDs(c *gin.Context, raw []string) (ids []uuid.UUID, invalid []string, ok bool) {
	if len(raw) > maxApprovalAssetIDs {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": fmt.Sprintf("too many asset ids: %d (max %d per request)", len(raw), maxApprovalAssetIDs),
		})
		return nil, nil, false
	}
	for _, idStr := range raw {
		if id, err := uuid.Parse(idStr); err == nil {
			ids = append(ids, id)
		} else {
			invalid = append(invalid, idStr)
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid asset ids provided"})
		return nil, nil, false
	}
	return ids, invalid, true
}

// approvalResponse reports what really happened. count is the number of assets
// whose status moved, not the number requested; skipped are valid ids that did
// not move (unknown, already in the target state, or not in a state this
// decision applies to) and invalid_ids are strings that were not UUIDs.
func approvalResponse(message string, res services.LifecycleChangeResult, invalid []string) gin.H {
	out := gin.H{
		"message": message,
		"count":   len(res.Changed),
		"changed": res.Changed,
		"skipped": res.Skipped,
	}
	if len(invalid) > 0 {
		out["invalid_ids"] = invalid
	}
	return out
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

	ids, invalid, ok := parseApprovalIDs(c, req.AssetIDs)
	if !ok {
		return
	}

	res, err := h.assetService.ApproveAssetsReport(tenantID, ids, approvalActor(c))
	if err != nil {
		if errors.Is(err, services.ErrAssetLifecycleConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve assets"})
		return
	}

	// Audit only what changed: a repeated approve, or an id that matched
	// nothing, did not happen and must not read as if it did.
	resourceType := "asset"
	for _, assetID := range res.Changed {
		logAuditActivity(c, "asset.approved", "asset", "approve", &resourceType, &assetID, nil, map[string]interface{}{
			"status":      "monitoring",
			"approved_at": time.Now(),
		}, []string{"status"}, map[string]interface{}{
			"asset_count": len(res.Changed),
		})
	}

	c.JSON(http.StatusOK, approvalResponse("assets approved", res, invalid))
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

	ids, invalid, ok := parseApprovalIDs(c, req.AssetIDs)
	if !ok {
		return
	}

	res, err := h.assetService.DenyAssetsReport(tenantID, ids, userID)
	if err != nil {
		if errors.Is(err, services.ErrAssetLifecycleConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deny assets"})
		return
	}

	resourceType := "asset"
	for _, assetID := range res.Changed {
		logAuditActivity(c, "asset.denied", "asset", "deny", &resourceType, &assetID, nil, map[string]interface{}{
			"status":    "denied",
			"denied_at": time.Now(),
		}, []string{"status"}, map[string]interface{}{
			"asset_count": len(res.Changed),
		})
	}

	c.JSON(http.StatusOK, approvalResponse("assets denied", res, invalid))
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
