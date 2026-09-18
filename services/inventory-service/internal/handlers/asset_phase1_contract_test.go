package handlers

// Contract tests for the phase-1 asset surface: the endpoint and identifier
// sub-resources, the class taxonomy, saved views, and the merge-proposal
// decisions.
//
// Same guardrail as asset_contract_test.go, whose harness (loadSpec, do) this
// shares: the REAL gin handlers over httptest with in-memory stubs, and every
// response body validated against the schema in
// api/openapi/inventory-service.openapi.yaml.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// --- stubs -----------------------------------------------------------------

type stubChildStore struct {
	endpoints   []models.Endpoint
	identifiers []models.Identifier
	err         error
}

func (s *stubChildStore) GetAssetEndpoints(uuid.UUID, uuid.UUID) ([]models.Endpoint, error) {
	return s.endpoints, s.err
}

func (s *stubChildStore) GetAssetIdentifiers(uuid.UUID, uuid.UUID) ([]models.Identifier, error) {
	return s.identifiers, s.err
}

type stubClassStore struct {
	classes []services.AssetClass
	err     error
}

func (s *stubClassStore) List(context.Context, uuid.UUID) ([]services.AssetClass, error) {
	return s.classes, s.err
}

type stubSavedViewStore struct {
	views  []services.SavedView
	one    *services.SavedView
	err    error
	delErr error
}

func (s *stubSavedViewStore) List(context.Context, uuid.UUID, uuid.UUID, string) ([]services.SavedView, error) {
	return s.views, s.err
}
func (s *stubSavedViewStore) Get(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*services.SavedView, error) {
	return s.one, s.err
}
func (s *stubSavedViewStore) Create(context.Context, uuid.UUID, uuid.UUID, services.SavedViewInput) (*services.SavedView, error) {
	return s.one, s.err
}
func (s *stubSavedViewStore) Update(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, services.SavedViewInput) (*services.SavedView, error) {
	return s.one, s.err
}
func (s *stubSavedViewStore) Delete(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return s.delErr
}

type stubProposalStore struct {
	list  []services.MergeProposalView
	total int
	one   *services.MergeProposalView
	err   error

	// gotLimit/gotOffset record the page the handler asked for, so a test can
	// assert the clamp rather than trusting the echo.
	gotLimit  int
	gotOffset int

	// autoAccepted backs ListAutoAccepted, which is a different list from
	// `list`: what the matcher already merged, not what is awaiting a decision.
	autoAccepted []services.MergeProposalView
}

func (s *stubProposalStore) ListPending(_ context.Context, _ uuid.UUID, limit, offset int) ([]services.MergeProposalView, int, error) {
	s.gotLimit, s.gotOffset = limit, offset
	return s.list, s.total, s.err
}
func (s *stubProposalStore) Accept(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (*services.MergeProposalView, error) {
	return s.one, s.err
}
func (s *stubProposalStore) KeepSeparate(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*services.MergeProposalView, error) {
	return s.one, s.err
}

func (s *stubProposalStore) ListAutoAccepted(_ context.Context, _ uuid.UUID, limit int) ([]services.MergeProposalView, error) {
	s.gotLimit = limit
	return s.autoAccepted, s.err
}

func newPhase1Engine(h *AssetPhase1Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/inventory-service/infrastructure-assets/:id/endpoints", h.GetAssetEndpoints)
	grp.GET("/inventory-service/infrastructure-assets/:id/identifiers", h.GetAssetIdentifiers)
	grp.GET("/inventory-service/asset-classes", h.GetAssetClasses)
	grp.GET("/inventory-service/saved-views", h.ListSavedViews)
	grp.POST("/inventory-service/saved-views", h.CreateSavedView)
	grp.GET("/inventory-service/saved-views/:id", h.GetSavedView)
	grp.PUT("/inventory-service/saved-views/:id", h.UpdateSavedView)
	grp.DELETE("/inventory-service/saved-views/:id", h.DeleteSavedView)
	grp.GET("/inventory-service/approvals/merge-proposals", h.ListMergeProposals)
	grp.GET("/inventory-service/approvals/merge-proposals/auto-accepted", h.ListAutoAcceptedMerges)
	grp.POST("/inventory-service/approvals/merge-proposals/:id/accept", h.AcceptMergeProposal)
	grp.POST("/inventory-service/approvals/merge-proposals/:id/keep-separate", h.KeepMergeProposalSeparate)
	return r
}

// --- sub-resources ---------------------------------------------------------

func TestContract_GetAssetEndpoints_200(t *testing.T) {
	sv := loadSpec(t)
	port := 443
	addr := "198.51.100.10"
	h := NewAssetPhase1Handler(&stubChildStore{endpoints: []models.Endpoint{{
		ID: uuid.New(), TenantID: uuid.New(), AssetID: uuid.New(),
		Address: &addr, Port: &port, Transport: "tcp", Protocol: strPtr("TLS"),
		Status: "active", SourceKind: "measured",
		FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
	}}}, nil, nil, nil)

	w := do(newPhase1Engine(h), http.MethodGet,
		"/api/v2/inventory-service/infrastructure-assets/"+uuid.New().String()+"/endpoints", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetEndpointListResponse", w.Body.Bytes())
}

// TestContract_GetAssetEndpoints_EmptyIsAnAnswer: an at-rest cloud resource has
// no endpoint, and the endpoint list says so with `[]` and a 200 — not a 404,
// and not `null`.
func TestContract_GetAssetEndpoints_EmptyIsAnAnswer(t *testing.T) {
	sv := loadSpec(t)
	h := NewAssetPhase1Handler(&stubChildStore{endpoints: []models.Endpoint{}}, nil, nil, nil)

	w := do(newPhase1Engine(h), http.MethodGet,
		"/api/v2/inventory-service/infrastructure-assets/"+uuid.New().String()+"/endpoints", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; an asset with no endpoints is not a missing asset", w.Code)
	}
	sv.assertConforms(t, "AssetEndpointListResponse", w.Body.Bytes())
	if strings.Contains(w.Body.String(), "null") {
		t.Errorf("the empty list must marshal as [], not null: %s", w.Body.String())
	}
}

func TestContract_GetAssetIdentifiers_200(t *testing.T) {
	sv := loadSpec(t)
	h := NewAssetPhase1Handler(&stubChildStore{identifiers: []models.Identifier{{
		ID: uuid.New(), AssetID: uuid.New(), Kind: "fqdn", Value: "web-01.example.test",
		SourceKind: "measured", Confidence: 1,
		FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
	}}}, nil, nil, nil)

	w := do(newPhase1Engine(h), http.MethodGet,
		"/api/v2/inventory-service/infrastructure-assets/"+uuid.New().String()+"/identifiers", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetIdentifierListResponse", w.Body.Bytes())
}

func TestContract_ListAssetClasses_200(t *testing.T) {
	sv := loadSpec(t)
	h := NewAssetPhase1Handler(nil, &stubClassStore{classes: []services.AssetClass{{
		Key: "server", Parent: "computer", Path: "hardware.computer.server",
		Label: "Server", Icon: "Server", CycloneDXType: "device",
		IdentifierPrecedence: []string{"serial_number", "fqdn"}, IsFixed: true,
	}}}, nil, nil)

	w := do(newPhase1Engine(h), http.MethodGet, "/api/v2/inventory-service/asset-classes", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetClassListResponse", w.Body.Bytes())
}

// --- saved views -----------------------------------------------------------

func sampleSavedView() *services.SavedView {
	return &services.SavedView{
		ID: uuid.New(), TenantID: uuid.New(), Name: "Production servers",
		Target: "asset", Query: "class:server and environment:production",
		OwnerUserID: uuid.New(), IsShared: false,
		CreatedAt: "2026-09-11T12:00:00Z", UpdatedAt: "2026-09-11T12:00:00Z",
	}
}

func TestContract_SavedViews_ListGetCreateUpdateDelete(t *testing.T) {
	sv := loadSpec(t)
	view := sampleSavedView()
	store := &stubSavedViewStore{views: []services.SavedView{*view}, one: view}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, store, nil))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/saved-views", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SavedViewListResponse", w.Body.Bytes())

	w = do(eng, http.MethodGet, "/api/v2/inventory-service/saved-views/"+view.ID.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SavedViewResponse", w.Body.Bytes())

	body := strings.NewReader(`{"name":"Production servers","query":"class:server"}`)
	w = do(eng, http.MethodPost, "/api/v2/inventory-service/saved-views", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SavedViewResponse", w.Body.Bytes())

	body = strings.NewReader(`{"name":"Production servers","query":"class:server"}`)
	w = do(eng, http.MethodPut, "/api/v2/inventory-service/saved-views/"+view.ID.String(), body)
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SavedViewResponse", w.Body.Bytes())

	w = do(eng, http.MethodDelete, "/api/v2/inventory-service/saved-views/"+view.ID.String(), nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
}

// TestContract_SavedViews_400CarriesTheDiagnostics is the shape that makes the
// query language usable: one entry per problem, each with a span into the text
// the caller submitted. A single flattened message is what "invalid query"
// looks like from the inside, and it is what this asserts against.
func TestContract_SavedViews_400CarriesTheDiagnostics(t *testing.T) {
	sv := loadSpec(t)
	// The REAL service, so the error is the real one — a stub returning a
	// hand-made QueryError would be asserting my own fixture.
	store := services.NewSavedViewService(nil)
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, store, nil))

	body := strings.NewReader(`{"name":"Broken","query":"hostnaem:web-1"}`)
	w := do(eng, http.MethodPost, "/api/v2/inventory-service/saved-views", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "QueryError", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), "unknown_field") {
		t.Errorf("the diagnostic code must reach the client: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "hostname") {
		t.Errorf("the suggestion must reach the client: %s", w.Body.String())
	}
}

func TestContract_SavedViews_404AndConflict(t *testing.T) {
	notFound := newPhase1Engine(NewAssetPhase1Handler(nil, nil,
		&stubSavedViewStore{err: services.ErrSavedViewNotFound}, nil))
	w := do(notFound, http.MethodGet, "/api/v2/inventory-service/saved-views/"+uuid.New().String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}

	dup := newPhase1Engine(NewAssetPhase1Handler(nil, nil,
		&stubSavedViewStore{err: services.ErrSavedViewDuplicate}, nil))
	w = do(dup, http.MethodPost, "/api/v2/inventory-service/saved-views",
		strings.NewReader(`{"name":"Taken","query":""}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}

// --- merge proposals -------------------------------------------------------

func sampleMergeProposal() services.MergeProposalView {
	observation := uuid.New()
	candidate := uuid.New()
	return services.MergeProposalView{
		ID: uuid.New(), TenantID: uuid.New(), Status: "pending",
		Reason: "two kinds matched different assets", Source: "sensor", SourceKind: "measured",
		ProposedAt: time.Now().UTC(), ObservationAssetID: &observation,
		Observation: &services.MergeCandidateView{
			AssetID: observation, DisplayName: "web01.example.test",
			ClassKey: "server", ClassLabel: "Server", AssetStatus: "pending_approval",
			MatchedIdentifiers: []map[string]any{},
		},
		Candidates: []services.MergeCandidateView{{
			AssetID: candidate, DisplayName: "web-01.example.test",
			ClassKey: "server", ClassLabel: "Server", AssetStatus: "monitoring",
			MatchedIdentifiers: []map[string]any{{"kind": "mac_address", "value": "aa:bb:cc:dd:ee:ff"}},
		}},
	}
}

func TestContract_MergeProposals_ListAcceptKeepSeparate(t *testing.T) {
	sv := loadSpec(t)
	proposal := sampleMergeProposal()
	store := &stubProposalStore{list: []services.MergeProposalView{proposal}, total: 1, one: &proposal}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/approvals/merge-proposals", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MergeProposalListResponse", w.Body.Bytes())

	body := strings.NewReader(`{"survivor_asset_id":"` + proposal.Candidates[0].AssetID.String() + `"}`)
	w = do(eng, http.MethodPost,
		"/api/v2/inventory-service/approvals/merge-proposals/"+proposal.ID.String()+"/accept", body)
	if w.Code != http.StatusOK {
		t.Fatalf("accept status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MergeProposalResponse", w.Body.Bytes())

	w = do(eng, http.MethodPost,
		"/api/v2/inventory-service/approvals/merge-proposals/"+proposal.ID.String()+"/keep-separate", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("keep-separate status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MergeProposalResponse", w.Body.Bytes())
}

// TestContract_MergeProposals_AcceptRequiresASurvivor: merging is destructive,
// so the server never picks. A body with no survivor is a 400, not a merge into
// whichever candidate happened to be first.
func TestContract_MergeProposals_AcceptRequiresASurvivor(t *testing.T) {
	proposal := sampleMergeProposal()
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil,
		&stubProposalStore{one: &proposal}))

	for _, body := range []string{`{}`, `{"survivor_asset_id":""}`, `{"survivor_asset_id":"not-a-uuid"}`} {
		w := do(eng, http.MethodPost,
			"/api/v2/inventory-service/approvals/merge-proposals/"+proposal.ID.String()+"/accept",
			strings.NewReader(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, w.Code)
		}
	}
}

func TestContract_MergeProposals_ErrorStatuses(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{services.ErrMergeProposalNotFound, http.StatusNotFound},
		{services.ErrMergeProposalResolved, http.StatusConflict},
		{services.ErrMergeObservationMissing, http.StatusConflict},
		{services.ErrMergeCandidateNotInProposal, http.StatusBadRequest},
		{errors.New("boom"), http.StatusInternalServerError},
	} {
		eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, &stubProposalStore{err: tc.err}))
		w := do(eng, http.MethodPost,
			"/api/v2/inventory-service/approvals/merge-proposals/"+uuid.New().String()+"/accept",
			strings.NewReader(`{"survivor_asset_id":"`+uuid.New().String()+`"}`))
		if w.Code != tc.want {
			t.Errorf("%v: status = %d, want %d; body=%s", tc.err, w.Code, tc.want, w.Body.String())
		}
	}
}

// TestContract_MergeProposals_ListCarriesTheTotalAndHonoursThePage: the count a
// reviewer reads must be the number of proposals awaiting them, not the number
// that fit on the page. With `total` missing, a caller has only
// `merge_proposals.length` — which is the page size — so a tenant with 300
// contested identities is told 50 and works a queue that never gets shorter.
func TestContract_MergeProposals_ListCarriesTheTotalAndHonoursThePage(t *testing.T) {
	sv := loadSpec(t)
	page := make([]services.MergeProposalView, 0, 3)
	for i := 0; i < 3; i++ {
		page = append(page, sampleMergeProposal())
	}
	store := &stubProposalStore{list: page, total: 317}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))

	w := do(eng, http.MethodGet,
		"/api/v2/inventory-service/approvals/merge-proposals?limit=3&offset=12", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MergeProposalListResponse", w.Body.Bytes())

	var got struct {
		Proposals []json.RawMessage `json:"merge_proposals"`
		Total     int               `json:"total"`
		Limit     int               `json:"limit"`
		Offset    int               `json:"offset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Total != 317 {
		t.Errorf("total = %d, want 317 (the count, not the page)", got.Total)
	}
	if len(got.Proposals) != 3 {
		t.Errorf("page length = %d, want 3", len(got.Proposals))
	}
	if store.gotLimit != 3 || store.gotOffset != 12 {
		t.Errorf("store saw limit=%d offset=%d, want 3/12", store.gotLimit, store.gotOffset)
	}
	if got.Limit != 3 || got.Offset != 12 {
		t.Errorf("echo limit=%d offset=%d, want 3/12", got.Limit, got.Offset)
	}
}

// TestContract_MergeProposals_LimitIsCapped: the cap is what makes the page a
// page. A caller asking for 10000 gets the default, and the ECHO says so — a
// caller that paginated off its own unclamped number would skip rows.
func TestContract_MergeProposals_LimitIsCapped(t *testing.T) {
	for _, tc := range []struct {
		query              string
		wantLimit, wantOff int
	}{
		{"", services.MergeProposalPageSize, 0},
		{"?limit=10000", services.MergeProposalPageSize, 0},
		{"?limit=0", services.MergeProposalPageSize, 0},
		{"?limit=-5", services.MergeProposalPageSize, 0},
		{"?limit=" + strconv.Itoa(services.MergeProposalMaxPageSize), services.MergeProposalMaxPageSize, 0},
		{"?limit=nonsense", services.MergeProposalPageSize, 0},
		{"?offset=-3", services.MergeProposalPageSize, 0},
		{"?limit=25&offset=25", 25, 25},
	} {
		store := &stubProposalStore{list: []services.MergeProposalView{}}
		eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))
		w := do(eng, http.MethodGet,
			"/api/v2/inventory-service/approvals/merge-proposals"+tc.query, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%q: status = %d; body=%s", tc.query, w.Code, w.Body.String())
		}
		var got struct {
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%q: decode: %v", tc.query, err)
		}
		if got.Limit != tc.wantLimit || got.Offset != tc.wantOff {
			t.Errorf("%q: echo limit=%d offset=%d, want %d/%d",
				tc.query, got.Limit, got.Offset, tc.wantLimit, tc.wantOff)
		}
	}
}
