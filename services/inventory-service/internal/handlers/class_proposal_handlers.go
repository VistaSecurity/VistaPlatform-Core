// Package handlers: the class-proposal surface — Approvals' third row kind
// after merges and relationships (workstream 2.10b, ADR-0004 D6 + ADR-0008 D3).
package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// classProposalStore is the narrow slice of ClassProposalService this handler
// calls — narrow so the contract tests can drive the real router with a stub and
// no database.
type classProposalStore interface {
	ListPending(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]services.ClassProposalView, int, error)
	Decide(ctx context.Context, tenantID, proposalID, actorUserID uuid.UUID, accept bool, chosenClass string) (*services.ClassProposalView, error)
}

// ClassProposalHandler serves the class-proposal endpoints.
type ClassProposalHandler struct {
	proposals classProposalStore
}

// NewClassProposalHandler wires the handler.
func NewClassProposalHandler(proposals classProposalStore) *ClassProposalHandler {
	return &ClassProposalHandler{proposals: proposals}
}

// ListClassProposals handles GET /approvals/classes[?status=pending].
func (h *ClassProposalHandler) ListClassProposals(c *gin.Context) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return
	}
	// `status` is accepted and only `pending` is served, exactly as the
	// relationship queue does it. A queue of DECIDED proposals is a different
	// product — it is the asset's History — and answering 200 with pending rows
	// for `status=accepted` would be the API agreeing to a question it did not
	// answer.
	if s := c.Query("status"); s != "" && s != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid status",
			"message": "the proposal queue serves status=pending; decided class proposals are in the asset's History",
		})
		return
	}
	limit := atoiOr(c.Query("limit"), 0)
	offset := atoiOr(c.Query("offset"), 0)

	proposals, total, err := h.proposals.ListPending(c.Request.Context(), tenantID, limit, offset)
	if writeClassProposalError(c, err) {
		return
	}
	appliedLimit, appliedOffset := services.ClampClassProposalPage(limit, offset)
	c.JSON(http.StatusOK, gin.H{
		"class_proposals": proposals,
		// `total` is the count to display. The array stops at the page size,
		// which is how the merge queue once told a tenant with 132 proposals
		// that it had 50.
		"total":  total,
		"limit":  appliedLimit,
		"offset": appliedOffset,
	})
}

// classDecisionRequest is the optional body of an accept.
type classDecisionRequest struct {
	// ClassKey is which class to take. Required only when the proposal has no
	// single proposed class — the rules conflicted and offered a choice — and
	// otherwise optional. When given it must be one the proposal offers: the
	// server refuses to reclassify an asset as something no rule argued for.
	ClassKey string `json:"class_key"`
}

// AcceptClassProposal handles POST /approvals/classes/:id/accept.
func (h *ClassProposalHandler) AcceptClassProposal(c *gin.Context) {
	h.decide(c, true)
}

// RejectClassProposal handles POST /approvals/classes/:id/reject.
func (h *ClassProposalHandler) RejectClassProposal(c *gin.Context) {
	h.decide(c, false)
}

func (h *ClassProposalHandler) decide(c *gin.Context, accept bool) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	proposalID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid class proposal ID"})
		return
	}
	var body classDecisionRequest
	if c.Request.Body != nil && c.Request.ContentLength > 0 {
		// A malformed body is refused rather than ignored. Silently dropping it
		// would accept the PROPOSED class while the reviewer believed they had
		// chosen a different one.
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "message": err.Error()})
			return
		}
	}

	proposal, err := h.proposals.Decide(c.Request.Context(), tenantID, proposalID, userID, accept, body.ClassKey)
	if writeClassProposalError(c, err) {
		return
	}

	// WHICH class was applied to WHICH asset, on the argument that was made —
	// not "POST …/accept, 200" (X5-09). `chosen_class_key` is the reviewer's
	// override when they picked from a tie, empty when they took what was
	// proposed, and the two are different decisions.
	event := "asset.class_proposal.rejected"
	if accept {
		event = "asset.class_proposal.accepted"
	}
	metadata := map[string]any{
		"actor":            "user",
		"chosen_class_key": strings.TrimSpace(body.ClassKey),
	}
	if proposal != nil {
		metadata["asset_id"] = proposal.AssetID.String()
		metadata["proposed_class_key"] = proposal.ProposedClassKey
		metadata["current_class_key"] = proposal.CurrentClassKey
		metadata["source"] = proposal.Source
		metadata["source_kind"] = proposal.ProposedClassSourceKind
		metadata["source_ref"] = proposal.ProposedClassSourceRef
		metadata["confidence"] = proposal.Confidence
		metadata["rule_ids"] = proposal.RuleIDs
	}
	auditProposalDecision(c, event, "class_proposal", proposalID, metadata)

	c.JSON(http.StatusOK, gin.H{"class_proposal": proposal})
}

// writeClassProposalError maps the service's sentinels onto status codes,
// reporting whether it wrote a response.
//
// Already-decided is 409 and not 404 for the reason the merge queue found: a
// second click on a stale page has to say what happened, and "no such proposal"
// says the row never existed.
func writeClassProposalError(c *gin.Context, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, services.ErrClassProposalNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Class proposal not found", "message": err.Error()})
	case errors.Is(err, services.ErrClassProposalDecided):
		c.JSON(http.StatusConflict, gin.H{"error": "Already decided", "message": err.Error()})
	case errors.Is(err, services.ErrClassProposalNeedsChoice),
		errors.Is(err, services.ErrClassNotInProposal):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid class", "message": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Request failed", "message": err.Error()})
	}
	return true
}
