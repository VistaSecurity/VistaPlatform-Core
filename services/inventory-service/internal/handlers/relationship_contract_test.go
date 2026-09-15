package handlers

// Contract tests for the relationship surface (ADR-0003, workstream 2.8).
//
// Same harness as asset_phase1_contract_test.go: the REAL gin handlers over
// httptest with an in-memory stub, every response body validated against
// api/openapi/inventory-service.openapi.yaml.
//
// The route table here mirrors cmd/main.go's v2 registrations EXACTLY, because
// a handler tested on a path nobody serves is a test of nothing —
// spec_route_table_contract_test.go guards the other half of that.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// --- stub -------------------------------------------------------------------

type stubRelationshipStore struct {
	edges     []services.RelationshipEdge
	total     int
	one       *services.RelationshipEdge
	graph     *services.Neighbourhood
	impact    *services.ImpactResult
	err       error
	deleteErr error

	// What the handler actually asked for, so a test can assert the clamp and
	// the parameter mapping rather than trusting an echo the handler computed
	// separately.
	gotOpts           services.RelationshipListOptions
	gotDepth          int
	gotIncludePending bool
	gotDirection      string
	gotAccept         bool
	gotLimit          int
	gotOffset         int
}

func (s *stubRelationshipStore) ListForAsset(_ context.Context, _, _ uuid.UUID, opts services.RelationshipListOptions) ([]services.RelationshipEdge, int, error) {
	s.gotOpts = opts
	return s.edges, s.total, s.err
}

func (s *stubRelationshipStore) Neighbourhood(_ context.Context, _, _ uuid.UUID, depth int, includePending bool) (*services.Neighbourhood, error) {
	s.gotDepth, s.gotIncludePending = depth, includePending
	return s.graph, s.err
}

func (s *stubRelationshipStore) Impact(_ context.Context, _, _ uuid.UUID, direction string, depth int) (*services.ImpactResult, error) {
	s.gotDirection, s.gotDepth = direction, depth
	return s.impact, s.err
}

func (s *stubRelationshipStore) Declare(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, services.DeclaredEdgeInput) (*services.RelationshipEdge, error) {
	return s.one, s.err
}

func (s *stubRelationshipStore) Delete(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return s.deleteErr
}

func (s *stubRelationshipStore) ListProposals(_ context.Context, _ uuid.UUID, limit, offset int) ([]services.RelationshipEdge, int, error) {
	s.gotLimit, s.gotOffset = limit, offset
	return s.edges, s.total, s.err
}

func (s *stubRelationshipStore) Decide(_ context.Context, _, _ uuid.UUID, _ uuid.UUID, accept bool) (*services.RelationshipEdge, error) {
	s.gotAccept = accept
	return s.one, s.err
}

func newRelationshipEngine(h *RelationshipHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/inventory-service/infrastructure-assets/:id/relationships", h.ListAssetRelationships)
	grp.POST("/inventory-service/infrastructure-assets/:id/relationships", h.CreateAssetRelationship)
	grp.DELETE("/inventory-service/infrastructure-assets/:id/relationships/:edgeId", h.DeleteAssetRelationship)
	grp.GET("/inventory-service/infrastructure-assets/:id/neighbourhood", h.GetNeighbourhood)
	grp.GET("/inventory-service/infrastructure-assets/:id/impact", h.GetImpact)
	grp.GET("/inventory-service/approvals/relationships", h.ListRelationshipProposals)
	grp.POST("/inventory-service/approvals/relationships/:edgeId/accept", h.AcceptRelationshipProposal)
	grp.POST("/inventory-service/approvals/relationships/:edgeId/reject", h.RejectRelationshipProposal)
	return r
}

func assetPath(id uuid.UUID, suffix string) string {
	return "/api/v2/inventory-service/infrastructure-assets/" + id.String() + suffix
}

func sampleEdge() services.RelationshipEdge {
	now := time.Now().UTC()
	peer := services.RelationshipPeer{
		AssetID: uuid.New(), DisplayName: "db-01.example.test", ClassKey: "managed_database",
		AssetStatus: "monitoring", PrimaryIdentifier: "fqdn:db-01.example.test",
	}
	return services.RelationshipEdge{
		ID: uuid.New(), TenantID: uuid.New(), FromAssetID: uuid.New(), ToAssetID: peer.AssetID,
		Type: string(relationships.DependsOn), Direction: services.DirectionOut, Label: "depends_on",
		SourceKind: services.SourceKindMeasured, SourceRef: "sensor:abc", Confidence: 0.9,
		Status: services.EdgeStatusActive, Attributes: map[string]any{"port": 5432},
		FirstSeenAt: now, LastSeenAt: now, ObservationCount: 3, Peer: &peer,
	}
}

// --- the one-hop list --------------------------------------------------------

func TestContract_ListAssetRelationships_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubRelationshipStore{edges: []services.RelationshipEdge{sampleEdge()}, total: 1}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/relationships"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RelationshipListResponse", w.Body.Bytes())
}

// TestContract_ListAssetRelationships_EmptyIsAnAnswer: most of inventory is a
// leaf. An asset with no edges answers `[]` and 200 — not 404, and not `null`.
func TestContract_ListAssetRelationships_EmptyIsAnAnswer(t *testing.T) {
	sv := loadSpec(t)
	store := &stubRelationshipStore{edges: []services.RelationshipEdge{}, total: 0}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/relationships"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; an asset with no relationships is not a missing asset", w.Code)
	}
	sv.assertConforms(t, "RelationshipListResponse", w.Body.Bytes())
	if strings.Contains(w.Body.String(), "null") {
		t.Errorf("the empty list must marshal as [], not null: %s", w.Body.String())
	}
}

// TestContract_ListAssetRelationships_TotalIsNotThePageLength is the merge
// queue's lesson applied here: a tenant with 132 of something was told it had
// 50, because the count came off the array.
func TestContract_ListAssetRelationships_TotalIsNotThePageLength(t *testing.T) {
	store := &stubRelationshipStore{edges: []services.RelationshipEdge{sampleEdge()}, total: 132}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/relationships"), nil)
	if !strings.Contains(w.Body.String(), `"total":132`) {
		t.Errorf("the envelope must carry the real total, not the page length: %s", w.Body.String())
	}
}

func TestContract_ListAssetRelationships_ClampsThePage(t *testing.T) {
	store := &stubRelationshipStore{edges: []services.RelationshipEdge{}}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/relationships?limit=9999&offset=-4"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	limit, offset := services.ClampRelationshipPage(store.gotOpts.Limit, store.gotOpts.Offset)
	if limit != services.RelationshipPageSize || offset != 0 {
		t.Errorf("an out-of-range page must fall back to the default, got limit=%d offset=%d", limit, offset)
	}
	if !strings.Contains(w.Body.String(), `"limit":`+strconv.Itoa(services.RelationshipPageSize)) {
		t.Errorf("the response must echo the limit actually applied: %s", w.Body.String())
	}
}

func TestContract_ListAssetRelationships_RejectsNonsense(t *testing.T) {
	for _, q := range []string{"?direction=sideways", "?type=eats", "?status=maybe"} {
		store := &stubRelationshipStore{edges: []services.RelationshipEdge{}}
		w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
			assetPath(uuid.New(), "/relationships"+q), nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 — an unrecognised filter must be refused, "+
				"not silently ignored and answered with the unfiltered set", q, w.Code)
		}
	}
}

// --- neighbourhood -----------------------------------------------------------

func sampleNeighbourhood() *services.Neighbourhood {
	root := uuid.New()
	return &services.Neighbourhood{
		RootAssetID: root, Depth: 2, IncludePending: false,
		Nodes: []services.NeighbourhoodNode{
			{AssetID: root, DisplayName: "web-01.example.test", ClassKey: "server", AssetStatus: "monitoring", Depth: 0, IsRoot: true},
			{AssetID: uuid.New(), DisplayName: "db-01.example.test", ClassKey: "managed_database", AssetStatus: "monitoring", Depth: 1},
		},
		Edges:      []services.RelationshipEdge{sampleEdge()},
		TotalNodes: 2, TotalEdges: 1,
		NodeCap: services.NeighbourhoodNodeCap, EdgeCap: services.NeighbourhoodEdgeCap,
	}
}

func TestContract_GetNeighbourhood_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubRelationshipStore{graph: sampleNeighbourhood()}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/neighbourhood"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NeighbourhoodResponse", w.Body.Bytes())
	if store.gotDepth != services.DefaultNeighbourhoodDepth {
		t.Errorf("default depth = %d, want %d", store.gotDepth, services.DefaultNeighbourhoodDepth)
	}
	if store.gotIncludePending {
		t.Errorf("pending edges must be opt-in: a graph that draws an unagreed edge like the rest states it as fact")
	}
}

func TestContract_GetNeighbourhood_IncludePendingIsOptIn(t *testing.T) {
	store := &stubRelationshipStore{graph: sampleNeighbourhood()}
	do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/neighbourhood?include_pending=true"), nil)
	if !store.gotIncludePending {
		t.Errorf("include_pending=true must reach the service")
	}
}

// TestContract_GetNeighbourhood_RefusesDepthOverTheCap: refused, not clamped. A
// caller handed three hops when it asked for five draws a map missing two
// layers and presents it as complete.
func TestContract_GetNeighbourhood_RefusesDepthOverTheCap(t *testing.T) {
	store := &stubRelationshipStore{graph: sampleNeighbourhood()}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/neighbourhood?depth=9"), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for depth past the cap", w.Code)
	}
	if store.gotDepth != 0 {
		t.Errorf("the service must not be called at all for a refused depth, got depth=%d", store.gotDepth)
	}
}

// TestContract_Relationships_RefusesDepthBelowOne: refused at the BOTTOM of the
// range too, and for the same reason it is refused at the top.
//
// `depth=0` used to fall through to the service, which clamped it to the
// default — so a caller asking for zero hops was handed a two-hop graph it had
// not asked for and had no way to tell was not its own. The spec says
// `minimum: 1`; the handler now says so as well.
func TestContract_Relationships_RefusesDepthBelowOne(t *testing.T) {
	for _, path := range []string{
		"/neighbourhood?depth=0", "/neighbourhood?depth=-1",
		"/impact?depth=0", "/impact?depth=-3",
	} {
		t.Run(path, func(t *testing.T) {
			store := &stubRelationshipStore{graph: sampleNeighbourhood(), impact: sampleImpact()}
			w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
				assetPath(uuid.New(), path), nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if store.gotDepth != 0 {
				t.Errorf("the service must not be called at all for a refused depth, got depth=%d", store.gotDepth)
			}
		})
	}
}

// TestContract_GetNeighbourhood_TruncationIsReported is the cap's honesty
// check at the wire.
func TestContract_GetNeighbourhood_TruncationIsReported(t *testing.T) {
	sv := loadSpec(t)
	g := sampleNeighbourhood()
	g.Truncated = true
	g.TotalNodes = 4211
	store := &stubRelationshipStore{graph: g}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/neighbourhood?depth=3"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	sv.assertConforms(t, "NeighbourhoodResponse", w.Body.Bytes())
	body := w.Body.String()
	if !strings.Contains(body, `"truncated":true`) {
		t.Errorf("a capped graph must say so: %s", body)
	}
	if !strings.Contains(body, `"total_nodes":4211`) {
		t.Errorf("a capped graph must still report the REAL size, or a caller cannot see what it is missing: %s", body)
	}
}

// --- impact ------------------------------------------------------------------

func sampleImpact() *services.ImpactResult {
	return &services.ImpactResult{
		RootAssetID: uuid.New(), Direction: services.ImpactDownstream, Depth: 6,
		Types: relationships.ImpactBearingStrings(),
		Nodes: []services.NeighbourhoodNode{
			{AssetID: uuid.New(), DisplayName: "app-01.example.test", ClassKey: "application", AssetStatus: "monitoring", Depth: 1},
		},
		CountsByDepth: []services.ImpactDepthCount{{Depth: 1, Count: 1}},
		Total:         1, NodeCap: services.ImpactNodeCap,
	}
}

func TestContract_GetImpact_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubRelationshipStore{impact: sampleImpact()}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/impact"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ImpactResponse", w.Body.Bytes())
	if store.gotDepth != services.DefaultImpactDepth {
		t.Errorf("default depth = %d, want %d (ADR-0003 D5)", store.gotDepth, services.DefaultImpactDepth)
	}
}

// TestContract_GetImpact_EchoesTheVocabulary: "what depends on this" over eight
// types and over ten are different questions.
func TestContract_GetImpact_EchoesTheVocabulary(t *testing.T) {
	store := &stubRelationshipStore{impact: sampleImpact()}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/impact"), nil)
	body := w.Body.String()
	if strings.Contains(body, `"connects_to"`) {
		t.Errorf("connects_to is not impact-bearing and must not appear in the echoed vocabulary: %s", body)
	}
	if !strings.Contains(body, `"depends_on"`) {
		t.Errorf("the echoed vocabulary must name the types actually walked: %s", body)
	}
}

func TestContract_GetImpact_RejectsBadDirectionAndDepth(t *testing.T) {
	for _, q := range []string{"?direction=outwards", "?depth=99"} {
		store := &stubRelationshipStore{impact: sampleImpact()}
		w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
			assetPath(uuid.New(), "/impact"+q), nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, w.Code)
		}
	}
}

func TestContract_GetImpact_UpstreamReachesTheService(t *testing.T) {
	store := &stubRelationshipStore{impact: sampleImpact()}
	do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		assetPath(uuid.New(), "/impact?direction=upstream"), nil)
	if store.gotDirection != services.ImpactUpstream {
		t.Errorf("direction reaching the service = %q, want upstream", store.gotDirection)
	}
}

// --- declare and delete ------------------------------------------------------

func TestContract_CreateAssetRelationship_201(t *testing.T) {
	sv := loadSpec(t)
	e := sampleEdge()
	e.SourceKind = services.SourceKindDeclared
	store := &stubRelationshipStore{one: &e}
	body := strings.NewReader(`{"type":"depends_on","peer_asset_id":"` + uuid.New().String() + `"}`)
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodPost,
		assetPath(uuid.New(), "/relationships"), body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RelationshipResponse", w.Body.Bytes())
}

func TestContract_CreateAssetRelationship_RejectsAnUnknownType(t *testing.T) {
	store := &stubRelationshipStore{err: services.ErrRelationshipUnknownType}
	body := strings.NewReader(`{"type":"eats","peer_asset_id":"` + uuid.New().String() + `"}`)
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodPost,
		assetPath(uuid.New(), "/relationships"), body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	// The refusal names the vocabulary. A 400 that does not say what IS allowed
	// leaves a caller guessing at ten values.
	if !strings.Contains(w.Body.String(), "runs_on") {
		t.Errorf("the refusal must list the vocabulary: %s", w.Body.String())
	}
}

func TestContract_CreateAssetRelationship_ConflictOnDuplicate(t *testing.T) {
	store := &stubRelationshipStore{err: services.ErrRelationshipExists}
	body := strings.NewReader(`{"type":"depends_on","peer_asset_id":"` + uuid.New().String() + `"}`)
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodPost,
		assetPath(uuid.New(), "/relationships"), body)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

// TestContract_DeleteAssetRelationship_MeasuredIs409 is the rule that matters:
// deleting an observation would appear to work and then silently undo itself on
// the next collection run.
func TestContract_DeleteAssetRelationship_MeasuredIs409(t *testing.T) {
	store := &stubRelationshipStore{deleteErr: services.ErrRelationshipNotDeclared}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodDelete,
		assetPath(uuid.New(), "/relationships/"+uuid.New().String()), nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for a non-declared edge; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "collection run") {
		t.Errorf("the 409 must say WHY, not just refuse: %s", w.Body.String())
	}
}

func TestContract_DeleteAssetRelationship_DeclaredIs200(t *testing.T) {
	store := &stubRelationshipStore{}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodDelete,
		assetPath(uuid.New(), "/relationships/"+uuid.New().String()), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestContract_DeleteAssetRelationship_404(t *testing.T) {
	store := &stubRelationshipStore{deleteErr: services.ErrRelationshipNotFound}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodDelete,
		assetPath(uuid.New(), "/relationships/"+uuid.New().String()), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// --- proposals ---------------------------------------------------------------

func sampleProposal() services.RelationshipEdge {
	e := sampleEdge()
	e.SourceKind = services.SourceKindInferred
	e.SourceRef = "matcher"
	e.Status = services.EdgeStatusPending
	e.Direction = ""
	from := services.RelationshipPeer{AssetID: e.FromAssetID, DisplayName: "app-01.example.test", ClassKey: "application", AssetStatus: "monitoring"}
	to := services.RelationshipPeer{AssetID: e.ToAssetID, DisplayName: "db-01.example.test", ClassKey: "managed_database", AssetStatus: "monitoring"}
	e.Peer = nil
	e.From, e.To = &from, &to
	return e
}

func TestContract_ListRelationshipProposals_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubRelationshipStore{edges: []services.RelationshipEdge{sampleProposal()}, total: 1}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		"/api/v2/inventory-service/approvals/relationships", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RelationshipProposalListResponse", w.Body.Bytes())
	// Both ends decorated: a reviewer on Approvals has no asset page around
	// them, and "something depends on something" is not reviewable.
	body := w.Body.String()
	if !strings.Contains(body, `"from":`) || !strings.Contains(body, `"to":`) {
		t.Errorf("a proposal must decorate BOTH ends: %s", body)
	}
}

func TestContract_ListRelationshipProposals_EmptyIsAnAnswer(t *testing.T) {
	sv := loadSpec(t)
	store := &stubRelationshipStore{edges: []services.RelationshipEdge{}, total: 0}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		"/api/v2/inventory-service/approvals/relationships?status=pending", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	sv.assertConforms(t, "RelationshipProposalListResponse", w.Body.Bytes())
	if strings.Contains(w.Body.String(), "null") {
		t.Errorf("the empty list must marshal as [], not null: %s", w.Body.String())
	}
}

func TestContract_ListRelationshipProposals_RefusesAnotherStatus(t *testing.T) {
	store := &stubRelationshipStore{edges: []services.RelationshipEdge{}}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodGet,
		"/api/v2/inventory-service/approvals/relationships?status=active", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — answering 200 with PENDING rows for status=active "+
			"would be the API agreeing to a question it did not answer", w.Code)
	}
}

func TestContract_DecideRelationshipProposal_200(t *testing.T) {
	sv := loadSpec(t)
	for _, tc := range []struct {
		action string
		accept bool
		status string
	}{
		{"accept", true, services.EdgeStatusActive},
		{"reject", false, services.EdgeStatusRejected},
	} {
		t.Run(tc.action, func(t *testing.T) {
			e := sampleProposal()
			e.Status = tc.status
			store := &stubRelationshipStore{one: &e}
			w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodPost,
				"/api/v2/inventory-service/approvals/relationships/"+uuid.New().String()+"/"+tc.action, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			sv.assertConforms(t, "RelationshipResponse", w.Body.Bytes())
			if store.gotAccept != tc.accept {
				t.Errorf("the service was told accept=%v, want %v — accept and reject must not "+
					"both route to the same decision", store.gotAccept, tc.accept)
			}
		})
	}
}

func TestContract_DecideRelationshipProposal_409WhenAlreadyDecided(t *testing.T) {
	store := &stubRelationshipStore{err: services.ErrRelationshipDecided}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodPost,
		"/api/v2/inventory-service/approvals/relationships/"+uuid.New().String()+"/accept", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

// TestContract_DecideRelationshipProposal_409WhenAnEndIsPending.
//
// ADR-0003 D1: an edge with a pending endpoint is itself pending, so accepting
// one cannot confirm it. 409 rather than 400 — the request is well formed and
// becomes valid on its own once the named asset is approved — and the reason
// travels in the body, because "409" alone tells a user nothing about which
// asset to go and approve.
func TestContract_DecideRelationshipProposal_409WhenAnEndIsPending(t *testing.T) {
	store := &stubRelationshipStore{err: services.ErrRelationshipEndPending}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodPost,
		"/api/v2/inventory-service/approvals/relationships/"+uuid.New().String()+"/accept", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "awaiting approval") {
		t.Errorf("the body must say WHY, not just refuse: %s", w.Body.String())
	}
}

func TestContract_DecideRelationshipProposal_404(t *testing.T) {
	store := &stubRelationshipStore{err: services.ErrRelationshipNotFound}
	w := do(newRelationshipEngine(NewRelationshipHandler(store)), http.MethodPost,
		"/api/v2/inventory-service/approvals/relationships/"+uuid.New().String()+"/reject", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// TestContract_Relationships_BadUUIDsAre400 — a malformed id must not reach the
// service as uuid.Nil, which RLS would then refuse in a way that reads as a
// server fault.
func TestContract_Relationships_BadUUIDsAre400(t *testing.T) {
	store := &stubRelationshipStore{edges: []services.RelationshipEdge{}}
	eng := newRelationshipEngine(NewRelationshipHandler(store))
	for _, path := range []string{
		"/api/v2/inventory-service/infrastructure-assets/not-a-uuid/relationships",
		"/api/v2/inventory-service/infrastructure-assets/not-a-uuid/neighbourhood",
		"/api/v2/inventory-service/infrastructure-assets/not-a-uuid/impact",
	} {
		if w := do(eng, http.MethodGet, path, nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, w.Code)
		}
	}
	w := do(eng, http.MethodDelete,
		"/api/v2/inventory-service/infrastructure-assets/"+uuid.New().String()+"/relationships/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("a malformed edge id: status = %d, want 400", w.Code)
	}
}
