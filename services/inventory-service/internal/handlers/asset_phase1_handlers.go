// Package handlers: the phase-1 asset read surface — sub-resources, the class
// taxonomy, saved views, and the merge-proposal decisions.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
)

// AssetPhase1Handler serves the endpoints the asset model added: an asset's
// endpoints and identifiers as sub-resources, the class taxonomy, saved views,
// and the merge-proposal queue.
type AssetPhase1Handler struct {
	assets     assetChildStore
	classes    assetClassStore
	savedViews savedViewStore
	proposals  mergeProposalStore
}

// The four stores are INTERFACES, each the narrow slice of one service this
// handler calls. Narrow on purpose: the contract tests construct the handler
// with stubs and no database, and a wide interface would make them declare
// methods these paths never call — which is how a stub stops resembling the
// thing it stands in for.
type (
	assetChildStore interface {
		GetAssetEndpoints(tenantID, assetID uuid.UUID) ([]models.Endpoint, error)
		GetAssetIdentifiers(tenantID, assetID uuid.UUID) ([]models.Identifier, error)
	}
	assetClassStore interface {
		List(ctx context.Context, tenantID uuid.UUID) ([]services.AssetClass, error)
	}
	savedViewStore interface {
		List(ctx context.Context, tenantID, userID uuid.UUID, target string) ([]services.SavedView, error)
		Get(ctx context.Context, tenantID, userID, id uuid.UUID) (*services.SavedView, error)
		Create(ctx context.Context, tenantID, userID uuid.UUID, in services.SavedViewInput) (*services.SavedView, error)
		Update(ctx context.Context, tenantID, userID, id uuid.UUID, in services.SavedViewInput) (*services.SavedView, error)
		Delete(ctx context.Context, tenantID, userID, id uuid.UUID) error
	}
	mergeProposalStore interface {
		ListPending(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]services.MergeProposalView, int, error)
		ListAutoAccepted(ctx context.Context, tenantID uuid.UUID, limit int) ([]services.MergeProposalView, error)
		Accept(ctx context.Context, tenantID, proposalID, survivorID, actorUserID uuid.UUID) (*services.MergeProposalView, error)
		KeepSeparate(ctx context.Context, tenantID, proposalID, actorUserID uuid.UUID) (*services.MergeProposalView, error)
	}
)

// NewAssetPhase1Handler wires the handler.
func NewAssetPhase1Handler(
	assets assetChildStore,
	classes assetClassStore,
	savedViews savedViewStore,
	proposals mergeProposalStore,
) *AssetPhase1Handler {
	return &AssetPhase1Handler{assets: assets, classes: classes, savedViews: savedViews, proposals: proposals}
}

// ----------------------------------------------------------- sub-resources --

// GetAssetEndpoints handles GET /assets/:id/endpoints.
func (h *AssetPhase1Handler) GetAssetEndpoints(c *gin.Context) {
	tenantID, assetID, ok := tenantAndAsset(c)
	if !ok {
		return
	}
	endpoints, err := h.assets.GetAssetEndpoints(tenantID, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve endpoints"})
		return
	}
	// An empty array is a REAL answer here — an at-rest cloud resource has no
	// endpoint at all — so it is returned as [] rather than 404.
	c.JSON(http.StatusOK, gin.H{"endpoints": endpoints})
}

// GetAssetIdentifiers handles GET /assets/:id/identifiers.
func (h *AssetPhase1Handler) GetAssetIdentifiers(c *gin.Context) {
	tenantID, assetID, ok := tenantAndAsset(c)
	if !ok {
		return
	}
	identifiers, err := h.assets.GetAssetIdentifiers(tenantID, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve identifiers"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"identifiers": identifiers})
}

// GetAssetClasses handles GET /asset-classes.
func (h *AssetPhase1Handler) GetAssetClasses(c *gin.Context) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return
	}
	classes, err := h.classes.List(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve asset classes"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"classes": classes})
}

// ------------------------------------------------------------ saved views --

// ListSavedViews handles GET /saved-views[?target=].
func (h *AssetPhase1Handler) ListSavedViews(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	views, err := h.savedViews.List(c.Request.Context(), tenantID, userID, c.Query("target"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve saved views"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved_views": views})
}

// GetSavedView handles GET /saved-views/:id.
func (h *AssetPhase1Handler) GetSavedView(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid saved view ID"})
		return
	}
	view, err := h.savedViews.Get(c.Request.Context(), tenantID, userID, id)
	if writeSavedViewError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved_view": view})
}

// CreateSavedView handles POST /saved-views.
func (h *AssetPhase1Handler) CreateSavedView(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	var in services.SavedViewInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	view, err := h.savedViews.Create(c.Request.Context(), tenantID, userID, in)
	if writeSavedViewError(c, err) {
		return
	}
	c.JSON(http.StatusCreated, gin.H{"saved_view": view})
}

// UpdateSavedView handles PUT /saved-views/:id.
func (h *AssetPhase1Handler) UpdateSavedView(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid saved view ID"})
		return
	}
	var in services.SavedViewInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	view, err := h.savedViews.Update(c.Request.Context(), tenantID, userID, id, in)
	if writeSavedViewError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved_view": view})
}

// DeleteSavedView handles DELETE /saved-views/:id.
func (h *AssetPhase1Handler) DeleteSavedView(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid saved view ID"})
		return
	}
	if writeSavedViewError(c, h.savedViews.Delete(c.Request.Context(), tenantID, userID, id)) {
		return
	}
	c.Status(http.StatusNoContent)
}

// ------------------------------------------------------- merge proposals --

// ListMergeProposals handles GET /approvals/merge-proposals[?limit=&offset=].
//
// The envelope carries `total` alongside the page. Without it the only count a
// caller has is the length of the array it just received, which stops at the
// page size — so a tenant with 300 contested identities reads "50 awaiting
// review" and a reviewer works a queue that never gets shorter.
func (h *AssetPhase1Handler) ListMergeProposals(c *gin.Context) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return
	}
	limit, offset := services.MergeProposalPageSize, 0
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			offset = n
		}
	}
	proposals, total, err := h.proposals.ListPending(c.Request.Context(), tenantID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve merge proposals"})
		return
	}
	// Echo the page the server actually used, not the one that was asked for:
	// the limit is clamped, and a caller paginating off an unclamped number
	// would skip rows.
	appliedLimit, appliedOffset := services.ClampMergeProposalPage(limit, offset)
	c.JSON(http.StatusOK, gin.H{
		"merge_proposals": proposals,
		"total":           total,
		"limit":           appliedLimit,
		"offset":          appliedOffset,
	})
}

// ListAutoAcceptedMerges handles GET /approvals/merge-proposals/auto-accepted[?limit=].
//
// What the MATCHER merged without asking, in the last thirty days. It is not a
// work queue — nothing here needs deciding, and everything here already
// happened — it is the record that makes an unattended capability visible to
// the human who enabled it, with the score and the model's reasons beside each
// one. A tenant whose threshold is zero (the default) always gets an empty list,
// because nothing can have been auto-accepted.
func (h *AssetPhase1Handler) ListAutoAcceptedMerges(c *gin.Context) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return
	}
	limit := services.MergeProposalPageSize
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	merges, err := h.proposals.ListAutoAccepted(c.Request.Context(), tenantID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve auto-accepted merges"})
		return
	}
	if merges == nil {
		// `[]`, never `null`. A tenant on the default threshold ALWAYS has an
		// empty list, so this is the common case, not the edge one — and a
		// client that has to distinguish null from [] before it can render
		// "nothing" will eventually forget to.
		merges = []services.MergeProposalView{}
	}
	c.JSON(http.StatusOK, gin.H{
		"merges": merges,
		// The window is echoed rather than assumed by the client: the heading
		// says "last 30 days" and it has to be the same 30 the server used.
		"window_days": services.AutoAcceptedWindowDays,
	})
}

// AcceptMergeProposal handles POST /approvals/merge-proposals/:id/accept.
//
// The body names the SURVIVOR. It is required and must be one of the proposal's
// candidates: merging is destructive and irreversible-ish (the source is
// archived, not deleted), so the server never picks. A UI that showed two cards
// and then merged into "the first one" would be choosing for the reviewer.
func (h *AssetPhase1Handler) AcceptMergeProposal(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	proposalID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid merge proposal ID"})
		return
	}
	var body struct {
		SurvivorAssetID string `json:"survivor_asset_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"message": "survivor_asset_id names the asset the merge keeps, and must be one of the proposal's candidates",
		})
		return
	}
	survivorID, err := uuid.Parse(body.SurvivorAssetID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid survivor_asset_id"})
		return
	}
	view, err := h.proposals.Accept(c.Request.Context(), tenantID, proposalID, survivorID, userID)
	if writeMergeProposalError(c, err) {
		return
	}
	auditProposalDecision(c, "asset.merge.accepted", "merge_proposal", proposalID, mergeAuditMetadata(view, map[string]any{
		"decision":          "accept",
		"survivor_asset_id": survivorID.String(),
	}))
	c.JSON(http.StatusOK, gin.H{"merge_proposal": view})
}

// KeepMergeProposalSeparate handles POST /approvals/merge-proposals/:id/keep-separate.
//
// It resolves the PROPOSAL and nothing else. The observation asset stays
// pending ordinary approval: the reviewer answered "this is not that", not
// "this belongs in inventory".
func (h *AssetPhase1Handler) KeepMergeProposalSeparate(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	proposalID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid merge proposal ID"})
		return
	}
	view, err := h.proposals.KeepSeparate(c.Request.Context(), tenantID, proposalID, userID)
	if writeMergeProposalError(c, err) {
		return
	}
	auditProposalDecision(c, "asset.merge.kept_separate", "merge_proposal", proposalID, mergeAuditMetadata(view, map[string]any{
		"decision": "keep_separate",
	}))
	c.JSON(http.StatusOK, gin.H{"merge_proposal": view})
}

// mergeAuditMetadata is the argument a merge decision was made on, in the same
// shape auditAutoAcceptedMerge records for the MACHINE path.
func mergeAuditMetadata(view *services.MergeProposalView, extra map[string]any) map[string]any {
	if view == nil {
		return extra
	}
	m := map[string]any{
		"actor":       "user",
		"score":       view.AcceptedScore,
		"model_id":    view.ModelID,
		"source":      view.Source,
		"source_kind": view.SourceKind,
		"reason":      view.Reason,
	}
	candidates := make([]string, 0, len(view.Candidates))
	for _, cand := range view.Candidates {
		candidates = append(candidates, cand.AssetID.String())
	}
	m["candidates"] = candidates
	if view.ObservationAssetID != nil {
		m["observation_asset_id"] = view.ObservationAssetID.String()
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// ------------------------------------------------------------- plumbing --

func tenantFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	return id, true
}

func tenantAndUser(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	v, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return uuid.Nil, uuid.Nil, false
	}
	userID, ok := v.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, userID, true
}

func tenantAndAsset(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, assetID, true
}

// writeSavedViewError maps a service error onto a status, and returns true when
// it wrote a response.
//
// A query that does not validate answers 400 with the FULL diagnostic list of
// §10 — code, message, span and suggestion, per error — because the caller is a
// person typing a query and a caret is the whole point. Flattening them into
// one string is what "invalid query" looks like from the inside.
func writeSavedViewError(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	if writeQueryError(c, err) {
		return true
	}
	switch {
	case errors.Is(err, services.ErrSavedViewNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Saved view not found"})
	case errors.Is(err, services.ErrSavedViewDuplicate):
		c.JSON(http.StatusConflict, gin.H{"error": "A saved view with that name already exists"})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	return true
}

func writeMergeProposalError(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, services.ErrMergeProposalNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Merge proposal not found"})
	case errors.Is(err, services.ErrMergeProposalResolved):
		c.JSON(http.StatusConflict, gin.H{"error": "This merge proposal has already been decided"})
	case errors.Is(err, services.ErrMergeCandidateNotInProposal):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid survivor_asset_id",
			"message": "the chosen asset is not one of this proposal's candidates",
		})
	case errors.Is(err, services.ErrMergeSurvivorArchived):
		// 409, not 400: the request was valid when the page was rendered. Some
		// OTHER decision archived this candidate since, which is a conflict
		// with the world rather than a malformed request.
		c.JSON(http.StatusConflict, gin.H{
			"error":   "The chosen survivor is archived",
			"message": "that candidate has been archived or merged away since this page was loaded; pick a live one",
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decide merge proposal"})
	}
	return true
}

// writeQueryError renders a query-language failure as 400 with the structured
// diagnostics. It is shared by every endpoint that accepts a query.
func writeQueryError(c *gin.Context, err error) bool {
	qe, ok := services.AsQueryError(err)
	if !ok {
		return false
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"error":  "Invalid query",
		"query":  qe.Query,
		"errors": renderQueryErrors(qe.Errors),
	})
	return true
}

// renderQueryErrors flattens the diagnostics into the wire shape §10 fixes:
// {code, message, span:{start,end}, suggestion?}.
func renderQueryErrors(list queryerr.List) []gin.H {
	out := make([]gin.H, 0, len(list))
	for _, e := range list {
		item := gin.H{
			"code":    string(e.Code),
			"message": e.Message,
			"span":    gin.H{"start": e.Span.Start, "end": e.Span.End},
		}
		if e.Suggestion != "" {
			item["suggestion"] = e.Suggestion
		}
		out = append(out, item)
	}
	return out
}
