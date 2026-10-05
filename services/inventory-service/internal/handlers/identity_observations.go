package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type IdentityObservationHandler struct{ service *services.AssetService }

func NewIdentityObservationHandler(service *services.AssetService) *IdentityObservationHandler {
	return &IdentityObservationHandler{service: service}
}

func (h *IdentityObservationHandler) Detail(c *gin.Context) {
	tenant, ok := autoScanTenant(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid observation ID"})
		return
	}
	out, err := h.service.GetIdentityObservation(c.Request.Context(), tenant, id)
	if writeObservationError(c, err) {
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *IdentityObservationHandler) Confirm(c *gin.Context) { h.decide(c, "confirmed") }
func (h *IdentityObservationHandler) Link(c *gin.Context)    { h.decide(c, "linked") }
func (h *IdentityObservationHandler) Dismiss(c *gin.Context) { h.decide(c, "dismissed") }

func (h *IdentityObservationHandler) decide(c *gin.Context, action string) {
	tenant, actor, ok := tenantAndUser(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid observation ID"})
		return
	}
	var input services.ObservationDecisionInput
	if err := c.ShouldBindJSON(&input); err != nil || strings.TrimSpace(input.Reason) == "" || (action == "linked" && (input.AssetID == nil || *input.AssetID == uuid.Nil)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "A reason is required; linking also requires an asset ID"})
		return
	}
	out, err := h.service.DecideIdentityObservation(c.Request.Context(), tenant, id, actor, action, input)
	if writeObservationError(c, err) {
		return
	}
	c.JSON(http.StatusOK, out)
}

func writeObservationError(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	status, _, message := observationErrorResponse(err)
	c.JSON(status, gin.H{"error": message})
	return true
}

// observationErrorResponse is the one mapping from a decision error to a
// status, a stable code and the message the single-item endpoints have always
// sent. The bulk endpoint reports each item through it, so an item in a batch
// fails in exactly the words the same decision would have on its own.
func observationErrorResponse(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, services.ErrObservationNotFound):
		return http.StatusNotFound, "not_found", "Observation or asset not found"
	case errors.Is(err, services.ErrObservationProvisionalMerge):
		// The body is the machine-readable CODE, not a sentence: the UI
		// switches on it to open merge review, and a prose message would tie
		// that behaviour to wording somebody will reasonably reword ( D8).
		return http.StatusConflict, "provisional_item_requires_merge_review", "provisional_item_requires_merge_review"
	case errors.Is(err, services.ErrObservationChanged):
		return http.StatusConflict, "observation_changed", err.Error()
	case errors.Is(err, services.ErrObservationAllowance):
		return http.StatusPaymentRequired, "asset_allowance_reached", err.Error()
	case errors.Is(err, services.ErrObservationNotReady):
		return http.StatusUnprocessableEntity, "not_ready_to_confirm", err.Error()
	default:
		return http.StatusInternalServerError, "internal_error", "Unable to process identity observation"
	}
}

// BulkObservationDecisionRequest is POST /discovery/observations/bulk.
type BulkObservationDecisionRequest struct {
	Action string      `json:"action" binding:"required,oneof=confirm dismiss link"`
	IDs    []uuid.UUID `json:"ids" binding:"required,min=1,max=200"`
	Reason string      `json:"reason" binding:"required,max=2000"`
	Name   string      `json:"name,omitempty" binding:"max=255"`
}

type BulkObservationResult struct {
	ID      uuid.UUID `json:"id"`
	Outcome string    `json:"outcome"`
	Status  int       `json:"status"`
	Code    string    `json:"code,omitempty"`
	Message string    `json:"message"`
	AssetID string    `json:"asset_id,omitempty"`
}

type BulkObservationResponse struct {
	BatchID uuid.UUID               `json:"batch_id"`
	Results []BulkObservationResult `json:"results"`
}

// Bulk confirms, links (to the owner the table suggested) or dismisses up to 200 observations with one reason. The
// response is 200 whenever the request itself was valid: each item's own
// status is in its result, and a failed item never fails the batch.
func (h *IdentityObservationHandler) Bulk(c *gin.Context) {
	tenant, actor, ok := tenantAndUser(c)
	if !ok {
		return
	}
	var req BulkObservationDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Reason) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An action (confirm, link or dismiss), 1 to 200 observation IDs and a reason are required"})
		return
	}
	batch, items, err := h.service.BulkDecideIdentityObservations(c.Request.Context(), tenant, actor, req.Action, req.IDs,
		services.ObservationDecisionInput{Reason: req.Reason, Name: req.Name})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out := BulkObservationResponse{BatchID: batch, Results: make([]BulkObservationResult, 0, len(items))}
	for _, item := range items {
		r := BulkObservationResult{ID: item.ID, Outcome: "ok", Status: http.StatusOK, Message: "Dismissed"}
		switch req.Action {
		case "confirm":
			r.Message = "Confirmed"
			r.AssetID = item.Result.AssetID
		case "link":
			r.Message = "Linked"
			r.AssetID = item.Result.AssetID
		}
		if item.Err != nil {
			r.Outcome, r.AssetID = "failed", ""
			r.Status, r.Code, r.Message = observationErrorResponse(item.Err)
			if errors.Is(item.Err, context.Canceled) || errors.Is(item.Err, context.DeadlineExceeded) {
				r.Status, r.Code, r.Message = http.StatusServiceUnavailable, "cancelled", "The request ended before this observation was decided"
			}
			if r.Status == http.StatusInternalServerError {
				log.Printf("[IdentityObservationHandler] bulk %s of observation %s (batch %s) failed: %v", req.Action, item.ID, batch, item.Err)
			}
		}
		out.Results = append(out.Results, r)
	}
	c.JSON(http.StatusOK, out)
}

func (h *IdentityObservationHandler) Summary(c *gin.Context) {
	tenant, ok := autoScanTenant(c)
	if !ok {
		return
	}
	out, err := h.service.IdentitySummary(c.Request.Context(), tenant)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to read identity coverage"})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *IdentityObservationHandler) List(c *gin.Context) {
	tenant, ok := autoScanTenant(c)
	if !ok {
		return
	}
	q := struct {
		State        string `form:"state" binding:"oneof=unresolved linked conflict dismissed expired all"`
		Page         int    `form:"page" binding:"min=1"`
		PageSize     int    `form:"page_size" binding:"min=1,max=100"`
		AssetID      string `form:"asset_id"`
		NetworkScope string `form:"network_scope"`
		Source       string `form:"source" binding:"max=255"`
		Query        string `form:"q" binding:"max=200"`
		Sort         string `form:"sort" binding:"omitempty,oneof=last_seen_desc last_seen_asc host network needs"`
	}{State: "unresolved", Page: 1, PageSize: 50}
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid observation filters"})
		return
	}
	var assetID *uuid.UUID
	if q.AssetID != "" {
		id, err := uuid.Parse(q.AssetID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
			return
		}
		assetID = &id
	}
	if q.NetworkScope != "" {
		if _, err := uuid.Parse(q.NetworkScope); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid network ID"})
			return
		}
	}
	// `needs` is repeatable AND accepts a comma list, so both
	// ?needs=a&needs=b and ?needs=a,b work.
	var needs []string
	for _, raw := range c.QueryArray("needs") {
		for _, n := range strings.Split(raw, ",") {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if !slices.Contains(services.ObservationNeedsValues, n) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid needs filter"})
				return
			}
			needs = append(needs, n)
		}
	}
	out, err := h.service.ListIdentityObservationsFiltered(c.Request.Context(), tenant, services.ObservationListFilter{
		State: q.State, Page: q.Page, PageSize: q.PageSize, AssetID: assetID, Needs: needs,
		NetworkScope: strings.ToLower(q.NetworkScope), Source: q.Source, Query: q.Query, Sort: q.Sort,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to read identity observations"})
		return
	}
	c.JSON(http.StatusOK, out)
}
