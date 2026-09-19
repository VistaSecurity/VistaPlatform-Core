package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type mergePreviewStore interface {
	PreviewMerge(context.Context, uuid.UUID, uuid.UUID, services.MergeSelection) (*services.AssetMergePreview, error)
	ExecuteMerge(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, services.MergeExecutionRequest) (*services.AssetMergeResult, error)
}

// PreviewAssetMerge compares only the explicitly selected existing records.
func (h *AssetPhase1Handler) PreviewAssetMerge(c *gin.Context) {
	tenant, _, ok := tenantAndUser(c)
	if !ok {
		return
	}
	proposal, ok := mergePreviewProposal(c)
	if !ok {
		return
	}
	var in services.MergeSelection
	if c.ShouldBindJSON(&in) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid merge selection"})
		return
	}
	store, ok := h.proposals.(mergePreviewStore)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Merge previews unavailable"})
		return
	}
	out, err := store.PreviewMerge(c.Request.Context(), tenant, proposal, in)
	if writeMergePreviewError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"preview": out})
}

// ExecuteAssetMerge requires a preview revision and a reason for the decision.
func (h *AssetPhase1Handler) ExecuteAssetMerge(c *gin.Context) {
	tenant, actor, ok := tenantAndUser(c)
	if !ok {
		return
	}
	proposal, ok := mergePreviewProposal(c)
	if !ok {
		return
	}
	var in services.MergeExecutionRequest
	if c.ShouldBindJSON(&in) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid merge request"})
		return
	}
	store, ok := h.proposals.(mergePreviewStore)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Merge previews unavailable"})
		return
	}
	out, err := store.ExecuteMerge(c.Request.Context(), tenant, proposal, actor, in)
	if writeMergePreviewError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"merge": out})
}
func mergePreviewProposal(c *gin.Context) (uuid.UUID, bool) {
	if c.Param("id") == "" {
		return uuid.Nil, true
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid proposal ID"})
		return uuid.Nil, false
	}
	return id, true
}
func writeMergePreviewError(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, services.ErrMergeSelection):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_merge_selection", "message": err.Error()})
	case errors.Is(err, services.ErrMergeProposalNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Merge selection not found"})
	case errors.Is(err, services.ErrMergePreviewChanged), errors.Is(err, services.ErrMergeFieldResolution), errors.Is(err, services.ErrMergeKeptSeparate), errors.Is(err, services.ErrMergeCandidateNotInProposal):
		c.JSON(http.StatusConflict, gin.H{"error": "merge_conflict", "message": err.Error(), "refresh_required": true})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to prepare or execute merge"})
	}
	return true
}
