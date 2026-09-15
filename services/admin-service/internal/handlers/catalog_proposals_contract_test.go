package handlers

// Contract test for the Enricher seam's HTTP surface: /admin/catalogs/eol/**.
//
// The REAL gin handlers run over httptest with in-memory stubs — no database,
// no provider, no gap runner — and every response body is validated against
// api/openapi/admin-service.openapi.yaml through the shared harness in
// contract_harness_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/catalogs"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// --- stubs ------------------------------------------------------------------

type stubProposalStore struct {
	proposals []catalogs.Proposal
	total     int64
	listErr   error
	lastQuery catalogs.ProposalQuery

	misses     []catalogs.Miss
	missTotal  int64
	missErr    error
	lastMissQ  catalogs.MissQuery
	reviewed   *catalogs.Proposal
	reviewErr  error
	eolEntryID string
	reviewers  []catalogs.Reviewer
}

func (s *stubProposalStore) ListProposals(_ context.Context, q catalogs.ProposalQuery) ([]catalogs.Proposal, int64, error) {
	s.lastQuery = q
	return s.proposals, s.total, s.listErr
}

func (s *stubProposalStore) AcceptProposal(_ context.Context, _ string, r catalogs.Reviewer) (*catalogs.Proposal, string, error) {
	s.reviewers = append(s.reviewers, r)
	if s.reviewErr != nil {
		return nil, "", s.reviewErr
	}
	return s.reviewed, s.eolEntryID, nil
}

func (s *stubProposalStore) RejectProposal(_ context.Context, _ string, r catalogs.Reviewer) (*catalogs.Proposal, error) {
	s.reviewers = append(s.reviewers, r)
	if s.reviewErr != nil {
		return nil, s.reviewErr
	}
	return s.reviewed, nil
}

func (s *stubProposalStore) ListMisses(_ context.Context, q catalogs.MissQuery) ([]catalogs.Miss, int64, error) {
	s.lastMissQ = q
	return s.misses, s.missTotal, s.missErr
}

type stubEnrichRunner struct {
	available bool
	err       error
	runs      int
	invokers  []string
}

func (r *stubEnrichRunner) Available() bool { return r.available }
func (r *stubEnrichRunner) RunDetached(invoker string) error {
	r.runs++
	r.invokers = append(r.invokers, invoker)
	return r.err
}

type stubSeamEnricher struct {
	facts        []seams.Fact
	matched      bool
	missRecorded bool
	err          error
	asked        []seams.EnrichmentSubject
}

func (e *stubSeamEnricher) Lookup(_ context.Context, s seams.EnrichmentSubject) (catalogs.LookupResult, error) {
	e.asked = append(e.asked, s)
	if e.err != nil {
		return catalogs.LookupResult{}, e.err
	}
	return catalogs.LookupResult{Facts: e.facts, Matched: e.matched, MissRecorded: e.missRecorded}, nil
}

// --- engine -----------------------------------------------------------------

func proposalEngine(store CatalogProposalStore, runner CatalogEnrichRunner, enricher CatalogLookup, av CatalogEnrichAvailability) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase)
	grp.POST("/admin/catalogs/eol/lookup", LookupEOL(enricher))
	grp.GET("/admin/catalogs/eol/proposals", ListEOLProposals(store))
	grp.POST("/admin/catalogs/eol/proposals/:id/accept", AcceptEOLProposal(store))
	grp.POST("/admin/catalogs/eol/proposals/:id/reject", RejectEOLProposal(store))
	grp.GET("/admin/catalogs/eol/misses", ListCatalogMisses(store))
	grp.POST("/admin/catalogs/eol/enrich", RunCatalogEnrichment(runner))
	grp.GET("/admin/catalogs/eol/enrich/availability", GetCatalogEnrichAvailability(av))
	return r
}

const proposalBase = apiBase + "/admin/catalogs/eol"

func sampleProposal(status string) catalogs.Proposal {
	vendor, version := "Cisco", "17.9.4a"
	eol := time.Date(2027, time.April, 30, 0, 0, 0, 0, time.UTC)
	created := time.Date(2026, time.September, 11, 6, 0, 0, 0, time.UTC)
	return catalogs.Proposal{
		ID: "a1b2c3d4-0000-4000-8000-000000000001", ProductKind: "os",
		Vendor: &vendor, Product: "IOS-XE", Version: &version,
		Cycle: "17.9", EOLDate: &eol,
		SourceURL: "https://www.cisco.com/eol", ModelID: "claude-x",
		SourceKind: "inferred", Confidence: 0, Status: status,
		CreatedAt: created, UpdatedAt: created,
	}
}

// --- lookup -----------------------------------------------------------------

func TestContract_LookupEOL_200_hit(t *testing.T) {
	sv := loadSpec(t)
	enricher := &stubSeamEnricher{matched: true, facts: []seams.Fact{{
		Proposal:  seams.NewLookupProposal(seams.SourceKindImported, "catalog:eol:row-1"),
		Key:       "eol.os.date",
		Value:     "2029-05-31",
		SourceURL: "https://endoflife.date/ubuntu",
	}}}
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{}, enricher, CatalogEnrichAvailability{})

	w := doRequest(eng, http.MethodPost, proposalBase+"/lookup",
		strings.NewReader(`{"product_kind":"os","vendor":"Canonical","product":"Ubuntu","version":"24.04"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolLookupResponse", w.Body.Bytes())

	// All four provenance fields reach the wire. A response that dropped
	// source_ref would show a date with no way back to the row that stated it.
	var body struct {
		Facts []struct {
			SourceKind string  `json:"source_kind"`
			SourceRef  string  `json:"source_ref"`
			Confidence float64 `json:"confidence"`
			SourceURL  string  `json:"source_url"`
		} `json:"facts"`
		Matched bool `json:"matched"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !body.Matched || len(body.Facts) != 1 {
		t.Fatalf("body = %+v", body)
	}
	if body.Facts[0].SourceKind != "imported" || body.Facts[0].SourceRef != "catalog:eol:row-1" {
		t.Errorf("provenance = %+v", body.Facts[0])
	}
	if body.Facts[0].SourceURL == "" {
		t.Error("the citation did not reach the wire")
	}
	if len(enricher.asked) != 1 || enricher.asked[0].Model != "Ubuntu" {
		t.Errorf("subject passed through = %+v", enricher.asked)
	}
}

func TestContract_LookupEOL_200_miss(t *testing.T) {
	sv := loadSpec(t)
	// nil facts, not an empty slice — the handler must still render `[]`.
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{},
		&stubSeamEnricher{missRecorded: true}, CatalogEnrichAvailability{})

	w := doRequest(eng, http.MethodPost, proposalBase+"/lookup", strings.NewReader(`{"product":"widget"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolLookupResponse", w.Body.Bytes())
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(body["facts"]) != "[]" {
		t.Fatalf("facts = %s, want []", body["facts"])
	}
	if string(body["matched"]) != "false" {
		t.Fatalf("matched = %s, want false", body["matched"])
	}
	if string(body["miss_recorded"]) != "true" {
		t.Fatalf("miss_recorded = %s, want true", body["miss_recorded"])
	}
}

// The answer this endpoint could not give: a catalogue row MATCHED and states
// no end-of-life date.
//
// It used to report `matched: false` — derived from the empty fact list — with
// the message "The catalogues have nothing for this product. It has been added
// to the gap list." That named the wrong problem AND asserted a write that had
// not happened, since a matched row records no miss. The two booleans are what
// make the four outcomes of one 200 distinguishable.
func TestContract_LookupEOL_200_matchedButNoDate(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{},
		&stubSeamEnricher{matched: true}, CatalogEnrichAvailability{})

	w := doRequest(eng, http.MethodPost, proposalBase+"/lookup", strings.NewReader(`{"product":"widget"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolLookupResponse", w.Body.Bytes())

	var body struct {
		Facts        []json.RawMessage `json:"facts"`
		Matched      bool              `json:"matched"`
		MissRecorded bool              `json:"miss_recorded"`
		Message      string            `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !body.Matched || len(body.Facts) != 0 {
		t.Fatalf("body = %+v, want matched with no facts", body)
	}
	if body.MissRecorded {
		t.Error("a matched row is not a gap and must not be reported as counted")
	}
	if strings.Contains(body.Message, "gap list") {
		t.Errorf("message = %q; it must not claim a gap-list write that did not happen", body.Message)
	}
	if !strings.Contains(body.Message, "no end-of-life date") {
		t.Errorf("message = %q; it must say what is actually missing", body.Message)
	}
}

// Nothing matched and the gap list could not be written. Distinguished from the
// ordinary miss, because "it is on the list now" is the operator's next step
// and it would be false here.
func TestContract_LookupEOL_200_missNotRecorded(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{},
		&stubSeamEnricher{}, CatalogEnrichAvailability{})

	w := doRequest(eng, http.MethodPost, proposalBase+"/lookup", strings.NewReader(`{"product":"widget"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolLookupResponse", w.Body.Bytes())

	var body struct {
		MissRecorded bool   `json:"miss_recorded"`
		Message      string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.MissRecorded {
		t.Fatal("miss_recorded must be false when nothing was written")
	}
	if !strings.Contains(body.Message, "could not be updated") {
		t.Errorf("message = %q; it must not claim the product is on the gap list", body.Message)
	}
}

func TestContract_LookupEOL_400(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	// "___" is TrimSpace-non-empty and normalises to nothing, so the lookup
	// would resolve nothing, record nothing, and answer as an unexplained miss.
	// Refusing it here is what keeps the four 200 outcomes exhaustive.
	for _, body := range []string{`{}`, `{"product":"  "}`, `{"product":"___"}`, `{"product":"x","product_kind":"firmware"}`, `not json`} {
		w := doRequest(eng, http.MethodPost, proposalBase+"/lookup", strings.NewReader(body))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400", body, w.Code)
		}
		sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	}
}

func TestContract_LookupEOL_500(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{},
		&stubSeamEnricher{err: errors.New("connection refused")}, CatalogEnrichAvailability{})
	w := doRequest(eng, http.MethodPost, proposalBase+"/lookup", strings.NewReader(`{"product":"ubuntu"}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- proposals list ---------------------------------------------------------

func TestContract_ListEOLProposals_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubProposalStore{proposals: []catalogs.Proposal{sampleProposal("pending")}, total: 1}
	eng := proposalEngine(store, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})

	w := doRequest(eng, http.MethodGet, proposalBase+"/proposals?status=pending&page=2&page_size=25", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolProposalListResponse", w.Body.Bytes())
	if store.lastQuery.Status != "pending" || store.lastQuery.Page != 2 || store.lastQuery.PageSize != 25 {
		t.Fatalf("filters were not passed through: %+v", store.lastQuery)
	}
}

func TestContract_ListEOLProposals_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{proposals: nil}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	w := doRequest(eng, http.MethodGet, proposalBase+"/proposals", nil)
	sv.assertConforms(t, "EolProposalListResponse", w.Body.Bytes())
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(body["proposals"]) != "[]" {
		t.Fatalf("proposals = %s, want []", body["proposals"])
	}
}

func TestContract_ListEOLProposals_400_badStatus(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	w := doRequest(eng, http.MethodGet, proposalBase+"/proposals?status=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListEOLProposals_500(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{listErr: errors.New("boom")}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	w := doRequest(eng, http.MethodGet, proposalBase+"/proposals", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- accept / reject --------------------------------------------------------

func TestContract_AcceptEOLProposal_200(t *testing.T) {
	sv := loadSpec(t)
	accepted := sampleProposal("accepted")
	store := &stubProposalStore{reviewed: &accepted, eolEntryID: "b1b2c3d4-0000-4000-8000-000000000009"}
	eng := proposalEngine(store, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})

	w := doRequest(eng, http.MethodPost, proposalBase+"/proposals/"+accepted.ID+"/accept", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolProposalReviewResponse", w.Body.Bytes())

	// The catalogue row the proposal became is named, which is what makes
	// "where did this row come from" answerable from either end.
	var body struct {
		EOLEntryID string `json:"eol_entry_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.EOLEntryID != store.eolEntryID {
		t.Errorf("eol_entry_id = %q, want %q", body.EOLEntryID, store.eolEntryID)
	}
}

func TestContract_RejectEOLProposal_200(t *testing.T) {
	sv := loadSpec(t)
	rejected := sampleProposal("rejected")
	eng := proposalEngine(&stubProposalStore{reviewed: &rejected}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})

	w := doRequest(eng, http.MethodPost, proposalBase+"/proposals/"+rejected.ID+"/reject", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolProposalReviewResponse", w.Body.Bytes())

	// Nothing was written, so there is no catalogue row to name.
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := body["eol_entry_id"]; ok {
		t.Error("a rejection reported a catalogue row id")
	}
}

// The two review failures are different situations with different fixes.
func TestContract_ReviewEOLProposal_404_and_409(t *testing.T) {
	sv := loadSpec(t)
	cases := map[error]int{
		catalogs.ErrProposalNotFound: http.StatusNotFound,
		catalogs.ErrProposalReviewed: http.StatusConflict,
		// Also a state refusal, also 409: the row exists and cannot be accepted
		// as it stands. 500 would read as "our fault, try again" and send an
		// operator looking in the wrong place for a proposal that will never be
		// acceptable.
		catalogs.ErrProposalUncitable: http.StatusConflict,
	}
	for storeErr, want := range cases {
		for _, action := range []string{"accept", "reject"} {
			eng := proposalEngine(&stubProposalStore{reviewErr: storeErr}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
			w := doRequest(eng, http.MethodPost, proposalBase+"/proposals/x/"+action, nil)
			if w.Code != want {
				t.Fatalf("%v on %s: status = %d, want %d", storeErr, action, w.Code, want)
			}
			sv.assertConforms(t, "LegacyError", w.Body.Bytes())
		}
	}
}

// The acting admin reaches the store, so the stored row can name who decided.
func TestContract_ReviewEOLProposal_carriesTheReviewer(t *testing.T) {
	accepted := sampleProposal("accepted")
	store := &stubProposalStore{reviewed: &accepted}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", "11111111-2222-3333-4444-555555555555")
		c.Set("email", "admin@example.com")
		c.Next()
	})
	r.Group(apiBase).POST("/admin/catalogs/eol/proposals/:id/accept", AcceptEOLProposal(store))

	w := doRequest(r, http.MethodPost, proposalBase+"/proposals/x/accept", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(store.reviewers) != 1 || store.reviewers[0].Email != "admin@example.com" {
		t.Fatalf("reviewer = %+v, want the authenticated admin", store.reviewers)
	}
}

// --- gap list ---------------------------------------------------------------

func TestContract_ListCatalogMisses_200(t *testing.T) {
	sv := loadSpec(t)
	vendor := "Cisco"
	store := &stubProposalStore{
		misses: []catalogs.Miss{
			{ID: "c1b2c3d4-0000-4000-8000-000000000001", ProductKind: "os", Vendor: &vendor,
				Product: "IOS-XE", MissCount: 412,
				FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()},
			// The nullable-everything row: no vendor, no version, never asked
			// about. This is the shape the contract most needs pinned.
			{ID: "c1b2c3d4-0000-4000-8000-000000000002", ProductKind: "software",
				Product: "widget", MissCount: 1,
				FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()},
		},
		missTotal: 2,
	}
	eng := proposalEngine(store, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	w := doRequest(eng, http.MethodGet, proposalBase+"/misses?page=3&page_size=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CatalogMissListResponse", w.Body.Bytes())
	if store.lastMissQ.Page != 3 || store.lastMissQ.PageSize != 10 {
		t.Fatalf("paging was not passed through: %+v", store.lastMissQ)
	}
}

func TestContract_ListCatalogMisses_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{misses: nil}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	w := doRequest(eng, http.MethodGet, proposalBase+"/misses", nil)
	sv.assertConforms(t, "CatalogMissListResponse", w.Body.Bytes())
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(body["misses"]) != "[]" {
		t.Fatalf("misses = %s, want []", body["misses"])
	}
}

func TestContract_ListCatalogMisses_500(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{missErr: errors.New("boom")}, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	w := doRequest(eng, http.MethodGet, proposalBase+"/misses", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- enrich trigger + availability ------------------------------------------

func TestContract_RunCatalogEnrichment_202(t *testing.T) {
	sv := loadSpec(t)
	runner := &stubEnrichRunner{available: true}
	eng := proposalEngine(&stubProposalStore{}, runner, &stubSeamEnricher{}, CatalogEnrichAvailability{Available: true})
	w := doRequest(eng, http.MethodPost, proposalBase+"/enrich", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CatalogEnrichRunResponse", w.Body.Bytes())
	if runner.runs != 1 {
		t.Fatalf("runs = %d, want 1", runner.runs)
	}
}

// The acting admin reaches the runner, and therefore every provider call the
// pass makes (D4.7: which USER or rule invoked it). Without it a run a person
// asked for is recorded against the nightly rule name, and the audit trail is
// the only place that answer survives.
func TestContract_RunCatalogEnrichment_carriesTheInvoker(t *testing.T) {
	runner := &stubEnrichRunner{available: true}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", "b0b0b0b0-0000-4000-8000-00000000beef")
		c.Next()
	})
	r.POST(apiBase+"/admin/catalogs/eol/enrich", RunCatalogEnrichment(runner))

	w := doRequest(r, http.MethodPost, proposalBase+"/enrich", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	if len(runner.invokers) != 1 || runner.invokers[0] != "b0b0b0b0-0000-4000-8000-00000000beef" {
		t.Fatalf("invokers = %v, want the acting admin", runner.invokers)
	}
}

func TestContract_RunCatalogEnrichment_409_busy(t *testing.T) {
	sv := loadSpec(t)
	eng := proposalEngine(&stubProposalStore{},
		&stubEnrichRunner{available: true, err: catalogs.ErrEnrichBusy}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	w := doRequest(eng, http.MethodPost, proposalBase+"/enrich", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A Core deployment gets 503 from a route that EXISTS, not a 404 it cannot
// distinguish from a broken build.
func TestContract_RunCatalogEnrichment_503_core(t *testing.T) {
	sv := loadSpec(t)
	for _, runner := range []CatalogEnrichRunner{
		&stubEnrichRunner{available: false},
		&stubEnrichRunner{available: true, err: catalogs.ErrNoProposer},
	} {
		eng := proposalEngine(&stubProposalStore{}, runner, &stubSeamEnricher{}, CatalogEnrichAvailability{})
		w := doRequest(eng, http.MethodPost, proposalBase+"/enrich", nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
		}
		sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	}
}

func TestContract_GetCatalogEnrichAvailability_200(t *testing.T) {
	sv := loadSpec(t)
	cases := []struct {
		name       string
		in         CatalogEnrichAvailability
		wantReason string
	}{
		// The zero value is the honest Core answer: a caller that wires
		// nothing reports unavailable rather than available by omission.
		{"the zero value is Core", CatalogEnrichAvailability{}, "edition"},
		{"explicit edition", CatalogEnrichAvailability{Reason: "edition", Provider: "none"}, "edition"},
		{"configured but unreachable", CatalogEnrichAvailability{Reason: "no_provider", Provider: "none"}, "no_provider"},
		{"available", CatalogEnrichAvailability{Available: true, Provider: "anthropic"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := proposalEngine(&stubProposalStore{}, &stubEnrichRunner{}, &stubSeamEnricher{}, tc.in)
			w := doRequest(eng, http.MethodGet, proposalBase+"/enrich/availability", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			sv.assertConforms(t, "CatalogEnrichAvailability", w.Body.Bytes())
			var body struct {
				Available bool   `json:"available"`
				Reason    string `json:"reason"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if body.Available != tc.in.Available || body.Reason != tc.wantReason {
				t.Fatalf("body = %+v, want available=%v reason=%q", body, tc.in.Available, tc.wantReason)
			}
		})
	}
}
