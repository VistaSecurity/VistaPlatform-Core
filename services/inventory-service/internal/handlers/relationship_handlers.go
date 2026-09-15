// Package handlers: the relationship surface — ADR-0003's edges, the
// neighbourhood the map draws, the impact closure, and the proposal queue.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// relationshipStore is the narrow slice of RelationshipService this handler
// calls — narrow so the contract tests can stub it without a database and
// without declaring methods these paths never reach.
type relationshipStore interface {
	ListForAsset(ctx context.Context, tenantID, assetID uuid.UUID, opts services.RelationshipListOptions) ([]services.RelationshipEdge, int, error)
	Neighbourhood(ctx context.Context, tenantID, assetID uuid.UUID, depth int, includePending bool) (*services.Neighbourhood, error)
	Impact(ctx context.Context, tenantID, assetID uuid.UUID, direction string, depth int) (*services.ImpactResult, error)
	Declare(ctx context.Context, tenantID, assetID, actorUserID uuid.UUID, in services.DeclaredEdgeInput) (*services.RelationshipEdge, error)
	Delete(ctx context.Context, tenantID, assetID, edgeID, actorUserID uuid.UUID) error
	ListProposals(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]services.RelationshipEdge, int, error)
	Decide(ctx context.Context, tenantID, edgeID, actorUserID uuid.UUID, accept bool) (*services.RelationshipEdge, error)
}

// RelationshipHandler serves the relationship endpoints.
type RelationshipHandler struct {
	edges relationshipStore
}

// NewRelationshipHandler wires the handler.
func NewRelationshipHandler(edges relationshipStore) *RelationshipHandler {
	return &RelationshipHandler{edges: edges}
}

// ------------------------------------------------------------- the edges --

// ListAssetRelationships handles
// GET /infrastructure-assets/:id/relationships[?direction=&type=&status=&limit=&offset=].
func (h *RelationshipHandler) ListAssetRelationships(c *gin.Context) {
	tenantID, assetID, ok := tenantAndAsset(c)
	if !ok {
		return
	}
	opts := services.RelationshipListOptions{
		Direction: c.Query("direction"),
		Type:      c.Query("type"),
		Status:    c.Query("status"),
		Limit:     atoiOr(c.Query("limit"), 0),
		Offset:    atoiOr(c.Query("offset"), 0),
	}
	if _, valid := services.NormalizeDirection(opts.Direction); !valid {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid direction",
			"message": "direction must be out, in or both",
		})
		return
	}
	if opts.Type != "" && !relationships.Type(opts.Type).Valid() {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Unknown relationship type",
			"message": "type must be one of the ten relationship types",
			"types":   relationships.Strings(),
		})
		return
	}
	if opts.Status != "" && !validEdgeStatus(opts.Status) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid status",
			"message": "status must be pending, active, rejected or stale",
		})
		return
	}

	edges, total, err := h.edges.ListForAsset(c.Request.Context(), tenantID, assetID, opts)
	if writeRelationshipError(c, err) {
		return
	}
	limit, offset := services.ClampRelationshipPage(opts.Limit, opts.Offset)
	c.JSON(http.StatusOK, gin.H{
		// An asset with no edges answers `[]` and 200, not 404. "Nothing is
		// attached to this" is a real and common answer — most of inventory is
		// a leaf — and a 404 would say the asset is missing.
		"relationships": edges,
		"total":         total,
		"limit":         limit,
		"offset":        offset,
	})
}

// GetNeighbourhood handles
// GET /infrastructure-assets/:id/neighbourhood[?depth=&include_pending=].
func (h *RelationshipHandler) GetNeighbourhood(c *gin.Context) {
	tenantID, assetID, ok := tenantAndAsset(c)
	if !ok {
		return
	}
	depth := atoiOr(c.Query("depth"), services.DefaultNeighbourhoodDepth)
	if depth < 1 || depth > services.MaxNeighbourhoodDepth {
		// Refused rather than silently clamped, at BOTH ends. A caller that
		// asked for five hops and was given three without being told would draw
		// a map missing two layers and present it as complete; a caller that
		// asked for zero and was given the default two would be handed a graph
		// it did not ask for and had no way to know was not its own.
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Depth is out of range",
			"message": "depth must be between 1 and " + strconv.Itoa(services.MaxNeighbourhoodDepth),
		})
		return
	}
	includePending := c.Query("include_pending") == "true"

	graph, err := h.edges.Neighbourhood(c.Request.Context(), tenantID, assetID, depth, includePending)
	if writeRelationshipError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"neighbourhood": graph})
}

// GetImpact handles GET /infrastructure-assets/:id/impact[?direction=&depth=].
func (h *RelationshipHandler) GetImpact(c *gin.Context) {
	tenantID, assetID, ok := tenantAndAsset(c)
	if !ok {
		return
	}
	if _, valid := services.NormalizeImpactDirection(c.Query("direction")); !valid {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid direction",
			"message": "direction must be upstream or downstream",
		})
		return
	}
	depth := atoiOr(c.Query("depth"), services.DefaultImpactDepth)
	if depth < 1 || depth > services.MaxImpactDepth {
		// Refused at both ends, for the reason GetNeighbourhood gives.
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Depth is out of range",
			"message": "depth must be between 1 and " + strconv.Itoa(services.MaxImpactDepth),
		})
		return
	}

	result, err := h.edges.Impact(c.Request.Context(), tenantID, assetID, c.Query("direction"), depth)
	if writeRelationshipError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"impact": result})
}

// CreateAssetRelationship handles POST /infrastructure-assets/:id/relationships.
func (h *RelationshipHandler) CreateAssetRelationship(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}
	var body struct {
		Type        string         `json:"type" binding:"required"`
		PeerAssetID string         `json:"peer_asset_id" binding:"required"`
		Direction   string         `json:"direction"`
		Attributes  map[string]any `json:"attributes"`
		Confidence  *float64       `json:"confidence"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"message": "type and peer_asset_id are required",
			"types":   relationships.Strings(),
		})
		return
	}
	peerID, err := uuid.Parse(body.PeerAssetID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid peer_asset_id"})
		return
	}

	edge, err := h.edges.Declare(c.Request.Context(), tenantID, assetID, userID, services.DeclaredEdgeInput{
		Type:        body.Type,
		PeerAssetID: peerID,
		Direction:   body.Direction,
		Attributes:  body.Attributes,
		Confidence:  body.Confidence,
	})
	if writeRelationshipError(c, err) {
		return
	}
	c.JSON(http.StatusCreated, gin.H{"relationship": edge})
}

// DeleteAssetRelationship handles
// DELETE /infrastructure-assets/:id/relationships/:edgeId.
func (h *RelationshipHandler) DeleteAssetRelationship(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}
	edgeID, err := uuid.Parse(c.Param("edgeId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid relationship ID"})
		return
	}
	if err := h.edges.Delete(c.Request.Context(), tenantID, assetID, edgeID, userID); writeRelationshipError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Relationship deleted"})
}

// -------------------------------------------------------------- proposals --

// ListRelationshipProposals handles GET /approvals/relationships[?status=pending].
func (h *RelationshipHandler) ListRelationshipProposals(c *gin.Context) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return
	}
	// `status` is accepted and only `pending` is served. A queue of decided
	// proposals is a different product (it is the history), and answering 200
	// with pending rows for `status=active` would be the API agreeing to a
	// question it did not answer.
	if s := c.Query("status"); s != "" && s != services.EdgeStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid status",
			"message": "the proposal queue serves status=pending; decided relationships are on the asset's Relationships tab and in its History",
		})
		return
	}
	limit := atoiOr(c.Query("limit"), 0)
	offset := atoiOr(c.Query("offset"), 0)

	proposals, total, err := h.edges.ListProposals(c.Request.Context(), tenantID, limit, offset)
	if writeRelationshipError(c, err) {
		return
	}
	appliedLimit, appliedOffset := services.ClampRelationshipPage(limit, offset)
	c.JSON(http.StatusOK, gin.H{
		"relationship_proposals": proposals,
		// `total` is the count to display. The array stops at the page size,
		// which is how the merge queue once told a tenant with 132 proposals
		// that it had 50.
		"total":  total,
		"limit":  appliedLimit,
		"offset": appliedOffset,
	})
}

// AcceptRelationshipProposal handles POST /approvals/relationships/:edgeId/accept.
func (h *RelationshipHandler) AcceptRelationshipProposal(c *gin.Context) {
	h.decide(c, true)
}

// RejectRelationshipProposal handles POST /approvals/relationships/:edgeId/reject.
func (h *RelationshipHandler) RejectRelationshipProposal(c *gin.Context) {
	h.decide(c, false)
}

func (h *RelationshipHandler) decide(c *gin.Context, accept bool) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	edgeID, err := uuid.Parse(c.Param("edgeId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid relationship ID"})
		return
	}
	edge, err := h.edges.Decide(c.Request.Context(), tenantID, edgeID, userID, accept)
	if writeRelationshipError(c, err) {
		return
	}

	// WHICH edge between WHICH two assets, and on what evidence (X5-09). The
	// route and status alone say a proposal was decided but not which claim
	// about the tenant's topology now stands.
	event := "asset.relationship_proposal.rejected"
	if accept {
		event = "asset.relationship_proposal.accepted"
	}
	metadata := map[string]any{"actor": "user"}
	if edge != nil {
		metadata["relationship_type"] = edge.Type
		metadata["source_kind"] = edge.SourceKind
		metadata["source_ref"] = edge.SourceRef
		metadata["confidence"] = edge.Confidence
		metadata["observation_count"] = edge.ObservationCount
		metadata["status"] = edge.Status
		metadata["from_asset_id"] = edge.FromAssetID.String()
		metadata["to_asset_id"] = edge.ToAssetID.String()
	}
	auditProposalDecision(c, event, "asset_relationship", edgeID, metadata)

	c.JSON(http.StatusOK, gin.H{"relationship": edge})
}

// --------------------------------------------------------------- plumbing --

func validEdgeStatus(s string) bool {
	switch s {
	case services.EdgeStatusPending, services.EdgeStatusActive,
		services.EdgeStatusRejected, services.EdgeStatusStale:
		return true
	default:
		return false
	}
}

func atoiOr(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

// writeRelationshipError maps a service error onto a status and returns true
// when it wrote a response.
//
// Each mapping carries the REASON in `message`, not just a code. "409" on a
// delete tells a user nothing; "this edge is measured, and the collector that
// saw it would re-create it" tells them why the button did not work and what
// would.
func writeRelationshipError(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, services.ErrRelationshipNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Relationship not found"})
	case errors.Is(err, services.ErrRelationshipPeerNotFound):
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Peer asset not found",
			"message": "peer_asset_id must name an asset of this tenant",
		})
	case errors.Is(err, services.ErrRelationshipNotDeclared):
		// 409, not 403. The request was well formed and the caller is
		// permitted; it is the EDGE that cannot be deleted.
		c.JSON(http.StatusConflict, gin.H{
			"error": "Only a declared relationship can be deleted",
			"message": "this edge was observed rather than asserted, so deleting it would only last until the next " +
				"collection run. A measured edge is retired by its collector ceasing to observe it, or rejected as a proposal.",
			"detail": err.Error(),
		})
	case errors.Is(err, services.ErrRelationshipEndPending):
		// 409, not 400: the request is well formed and will become valid on its
		// own the moment the named asset is approved.
		c.JSON(http.StatusConflict, gin.H{
			"error": "An end of this relationship is still awaiting approval",
			"message": "a relationship can only be confirmed between two approved assets — approve the asset named in " +
				"`detail` in Discovery → Approvals, which confirms what was observed about it",
			"detail": err.Error(),
		})
	case errors.Is(err, services.ErrRelationshipDecided):
		c.JSON(http.StatusConflict, gin.H{
			"error":   "This relationship has already been decided",
			"message": "someone else answered this proposal since the page was loaded",
			"detail":  err.Error(),
		})
	case errors.Is(err, services.ErrRelationshipExists):
		c.JSON(http.StatusConflict, gin.H{
			"error":   "That relationship already exists",
			"message": "the same pair already carries an edge of this type; a pair may carry several types but only one of each",
		})
	case errors.Is(err, services.ErrRelationshipSelfEdge):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "An asset cannot have a relationship with itself",
			"message": "a self-edge is meaningless in all ten types and usually means one host was matched twice under two identifiers",
		})
	case errors.Is(err, services.ErrRelationshipUnknownType):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Unknown relationship type",
			"message": err.Error(),
			"types":   relationships.Strings(),
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read relationships"})
	}
	return true
}
