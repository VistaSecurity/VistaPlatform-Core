package handlers

// Contract tests for the learned matcher's API surfaces (workstream 4.6): the
// score, the model id and the explanation on a merge proposal, the
// auto-accepted list, and the tenant threshold under Settings.
//
// Same harness as asset_phase1_contract_test.go — the REAL gin handlers over
// httptest, every response validated against
// api/openapi/inventory-service.openapi.yaml.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// scoredMergeProposal is a proposal a matcher ranked: a score, the model that
// produced it, and the score's working.
func scoredMergeProposal(autoAccepted bool) services.MergeProposalView {
	p := sampleMergeProposal()
	p.ModelID = "matcher-logreg-v1"
	p.SourceRef = "matcher:learned"
	p.Candidates[0].Score = 0.93
	p.Candidates[0].Reason = "a one-per-asset identifier matches, and 2 other signals"
	p.Candidates[0].Explanation = []services.MergeScoreFactor{
		{Feature: "id_match_singleton", Label: "a one-per-asset identifier matches", Value: 1, Weight: 2.98, Contribution: 2.98},
		{Feature: "segment_match", Label: "same network segment", Value: 1, Weight: 0.93, Contribution: 0.93},
		{Feature: "recency", Label: "seen less than a day apart", Value: 0.98, Weight: 1.13, Contribution: 1.1},
	}
	if autoAccepted {
		accepted := p.Candidates[0].AssetID
		p.AutoAccepted = true
		p.AcceptedAssetID = &accepted
		p.AcceptedScore = 0.93
		p.AcceptedModelID = "matcher-logreg-v1"
		p.AcceptedSourceRef = "matcher:learned"
		// An auto-accepted proposal wrote the observation into an existing
		// asset, so there is no third asset and no observation card.
		p.ObservationAssetID = nil
		p.Observation = nil
	}
	return p
}

// Phase 5: the two records' score against EACH OTHER survives the
// envelope and conforms to the spec, with the ids it is about.
func TestContract_MergeProposals_CarryThePairScore(t *testing.T) {
	sv := loadSpec(t)
	proposal := scoredMergeProposal(false)
	second := services.MergeCandidateView{
		AssetID: uuid.New(), DisplayName: "web-01b.example.test", ClassKey: "server", AssetStatus: "monitoring",
		MatchedIdentifiers: []map[string]any{{"kind": "ip_address", "value": "198.51.100.10"}}, Score: 0.41,
	}
	proposal.Candidates = append(proposal.Candidates, second)
	proposal.PairScore = 0.12
	proposal.PairAssetIDs = []uuid.UUID{proposal.Candidates[0].AssetID, second.AssetID}
	proposal.PairReason = "they share an address but no hardware address — the address may have passed to another device"
	store := &stubProposalStore{list: []services.MergeProposalView{proposal}, total: 1}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/approvals/merge-proposals", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MergeProposalListResponse", w.Body.Bytes())
	var body struct {
		MergeProposals []struct {
			PairScore    float64  `json:"pair_score"`
			PairAssetIDs []string `json:"pair_asset_ids"`
			PairReason   string   `json:"pair_reason"`
		} `json:"merge_proposals"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.MergeProposals) != 1 {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	got := body.MergeProposals[0]
	if got.PairScore != 0.12 || len(got.PairAssetIDs) != 2 || got.PairAssetIDs[1] != second.AssetID.String() || got.PairReason == "" {
		t.Errorf("pair = %+v, want the score, both ids and the reason", got)
	}
}

// The explanation and the model id must survive the envelope. A score the UI
// can render but cannot explain is a score a reviewer can only rubber-stamp,
// which is the failure the evidence on a proposal exists to prevent.
func TestContract_MergeProposals_CarryScoreModelIDAndExplanation(t *testing.T) {
	sv := loadSpec(t)
	proposal := scoredMergeProposal(false)
	store := &stubProposalStore{list: []services.MergeProposalView{proposal}, total: 1}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/approvals/merge-proposals", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MergeProposalListResponse", w.Body.Bytes())

	var body struct {
		MergeProposals []struct {
			ModelID    string `json:"model_id"`
			SourceRef  string `json:"source_ref"`
			Candidates []struct {
				Score       float64 `json:"score"`
				Reason      string  `json:"reason"`
				Explanation []struct {
					Feature      string  `json:"feature"`
					Label        string  `json:"label"`
					Contribution float64 `json:"contribution"`
				} `json:"explanation"`
			} `json:"candidates"`
		} `json:"merge_proposals"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.MergeProposals) != 1 {
		t.Fatalf("proposals = %d, want 1", len(body.MergeProposals))
	}
	got := body.MergeProposals[0]
	if got.ModelID != "matcher-logreg-v1" || got.SourceRef != "matcher:learned" {
		t.Errorf("provenance = %q/%q, want the matcher's", got.ModelID, got.SourceRef)
	}
	if got.Candidates[0].Score != 0.93 {
		t.Errorf("score = %v, want 0.93", got.Candidates[0].Score)
	}
	if len(got.Candidates[0].Explanation) != 3 {
		t.Fatalf("explanation has %d factors, want 3", len(got.Candidates[0].Explanation))
	}
	if got.Candidates[0].Explanation[0].Label == "" {
		t.Error("the leading factor has no label; a feature name is not an explanation")
	}
}

// A candidate nothing scored carries NO explanation key — not an empty array.
// An empty array reads as "we looked and there was nothing to say", which is a
// different claim from "nothing scored this".
func TestContract_MergeProposals_UnscoredCandidateHasNoExplanation(t *testing.T) {
	sv := loadSpec(t)
	proposal := sampleMergeProposal()
	store := &stubProposalStore{list: []services.MergeProposalView{proposal}, total: 1}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/approvals/merge-proposals", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MergeProposalListResponse", w.Body.Bytes())
	if strings.Contains(w.Body.String(), `"explanation"`) {
		t.Errorf("an unscored candidate carried an explanation key: %s", w.Body.String())
	}
}

func TestContract_AutoAcceptedMerges_List(t *testing.T) {
	sv := loadSpec(t)
	store := &stubProposalStore{autoAccepted: []services.MergeProposalView{scoredMergeProposal(true)}}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/approvals/merge-proposals/auto-accepted", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AutoAcceptedMergeListResponse", w.Body.Bytes())

	var body struct {
		Merges []struct {
			AutoAccepted    bool   `json:"auto_accepted"`
			AcceptedModelID string `json:"accepted_model_id"`
		} `json:"merges"`
		WindowDays int `json:"window_days"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.WindowDays != services.AutoAcceptedWindowDays {
		t.Errorf("window_days = %d, want %d: the heading and the query must agree",
			body.WindowDays, services.AutoAcceptedWindowDays)
	}
	if len(body.Merges) != 1 || !body.Merges[0].AutoAccepted {
		t.Fatalf("merges = %+v, want one marked auto-accepted", body.Merges)
	}
	if body.Merges[0].AcceptedModelID == "" {
		t.Error("an auto-accepted merge does not name the model that decided it")
	}
}

// The list carries two kinds of row ( Phase 4): both conform to the
// schema, each says who decided it, and a rule row carries its evidence and its
// survivor while a matcher row carries neither.
func TestContract_AutoAcceptedMerges_CarriesDecidedByAndRuleEvidence(t *testing.T) {
	sv := loadSpec(t)

	matcher := scoredMergeProposal(true)
	matcher.DecidedBy = services.DecidedByMatcher

	rule := sampleMergeProposal()
	survivor := rule.Candidates[0].AssetID
	rule.Status = "merged"
	rule.DecidedBy = services.DecidedByRule
	rule.RuleEvidence = []string{"same MAC seen directly by a sensor", "same network segment"}
	rule.MergedInto = &survivor
	rule.ObservationAssetID = nil
	rule.Observation = nil

	store := &stubProposalStore{autoAccepted: []services.MergeProposalView{rule, matcher}}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/approvals/merge-proposals/auto-accepted", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AutoAcceptedMergeListResponse", w.Body.Bytes())

	var body struct {
		Merges []struct {
			DecidedBy    string   `json:"decided_by"`
			RuleEvidence []string `json:"rule_evidence"`
			MergedInto   string   `json:"merged_into"`
		} `json:"merges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Merges) != 2 {
		t.Fatalf("merges = %d, want 2", len(body.Merges))
	}
	if r := body.Merges[0]; r.DecidedBy != "rule" || len(r.RuleEvidence) != 2 || r.MergedInto != survivor.String() {
		t.Errorf("rule row = %+v, want decided_by=rule with 2 evidence lines and the survivor %s", r, survivor)
	}
	if m := body.Merges[1]; m.DecidedBy != "matcher" || len(m.RuleEvidence) != 0 {
		t.Errorf("matcher row = %+v, want decided_by=matcher and no evidence", m)
	}
}

// A tenant on the default threshold of zero can never have an auto-accepted
// merge, so the list is empty — and empty is an ARRAY, not null, or the UI
// renders a spinner forever.
func TestContract_AutoAcceptedMerges_EmptyIsAnArray(t *testing.T) {
	sv := loadSpec(t)
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, &stubProposalStore{}))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/approvals/merge-proposals/auto-accepted", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AutoAcceptedMergeListResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"merges":[]`) {
		t.Errorf("empty list rendered as %s, want []", w.Body.String())
	}
}

func TestContract_AutoAcceptedMerges_StoreError_500(t *testing.T) {
	store := &stubProposalStore{err: errors.New("boom")}
	eng := newPhase1Engine(NewAssetPhase1Handler(nil, nil, nil, store))
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/approvals/merge-proposals/auto-accepted", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

// --- the tenant threshold --------------------------------------------------

type stubIdentificationSettings struct {
	settings services.IdentificationSettings
	err      error

	// received is the update the handler handed the service, verbatim: what was
	// SENT and what was left nil is the whole point of the partial-update
	// contract, and only the raw value shows it.
	received services.IdentificationSettingsUpdate
	setCalls int
}

func (s *stubIdentificationSettings) Get(context.Context, uuid.UUID) (services.IdentificationSettings, error) {
	return s.settings, s.err
}

func (s *stubIdentificationSettings) Update(_ context.Context, _, _ uuid.UUID, in services.IdentificationSettingsUpdate) (services.IdentificationSettings, error) {
	s.setCalls++
	s.received = in
	if s.err != nil {
		return services.IdentificationSettings{}, s.err
	}
	// Mirror the real service's merge so a response built from this stub is the
	// EFFECTIVE settings — both fields — whichever was sent.
	if in.AutoAcceptThreshold != nil {
		s.settings.AutoAcceptThreshold = *in.AutoAcceptThreshold
	}
	if in.AutoMergeExisting != nil {
		s.settings.AutoMergeExisting = *in.AutoMergeExisting
	}
	s.settings.Version++
	return s.settings, nil
}

func newIdentificationSettingsEngine(h *IdentificationSettingsHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/inventory-service/settings/identification", h.GetIdentificationSettings)
	grp.PUT("/inventory-service/settings/identification", h.UpdateIdentificationSettings)
	return r
}

func TestContract_IdentificationSettings_GetDefaultsToNever(t *testing.T) {
	sv := loadSpec(t)
	store := &stubIdentificationSettings{}
	eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(store, "matcher-logreg-v1"))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/settings/identification", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IdentificationSettingsResponse", w.Body.Bytes())

	var body struct {
		Identification struct {
			AutoAcceptThreshold float64 `json:"auto_accept_threshold"`
			MatcherModelID      string  `json:"matcher_model_id"`
		} `json:"identification"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Identification.AutoAcceptThreshold != 0 {
		t.Errorf("threshold = %v, want 0: a tenant who has not decided has decided no",
			body.Identification.AutoAcceptThreshold)
	}
	if body.Identification.MatcherModelID != "matcher-logreg-v1" {
		t.Errorf("matcher_model_id = %q; the page cannot say what the threshold is a threshold on",
			body.Identification.MatcherModelID)
	}
}

// With no matcher configured, nothing is scored and the threshold cannot fire
// whatever it is set to. The response says so by omitting the model id, so the
// page can explain rather than showing a control that looks live.
func TestContract_IdentificationSettings_NoMatcherOmitsTheModelID(t *testing.T) {
	sv := loadSpec(t)
	eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(&stubIdentificationSettings{}, ""))

	w := do(eng, http.MethodGet, "/api/v2/inventory-service/settings/identification", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IdentificationSettingsResponse", w.Body.Bytes())
	if strings.Contains(w.Body.String(), "matcher_model_id") {
		t.Errorf("a build with no matcher still named one: %s", w.Body.String())
	}
}

func TestContract_IdentificationSettings_Update(t *testing.T) {
	sv := loadSpec(t)
	store := &stubIdentificationSettings{}
	eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(store, "matcher-logreg-v1"))

	w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/identification",
		strings.NewReader(`{"auto_accept_threshold":0.95}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IdentificationSettingsResponse", w.Body.Bytes())
	if store.received.AutoAcceptThreshold == nil || *store.received.AutoAcceptThreshold != 0.95 {
		t.Errorf("the service was asked for %v, want 0.95", store.received.AutoAcceptThreshold)
	}
	if store.received.AutoMergeExisting != nil {
		t.Errorf("a threshold-only body reached the service with auto_merge_existing = %v; "+
			"an unsent field must arrive as nil, not as false", *store.received.AutoMergeExisting)
	}
}

// Zero is a REAL value here — "turn auto-accept off" — and must reach the
// service, not be read as "the field was omitted". They mean opposite things
// and a plain float64 in the request body renders both as 0.
func TestContract_IdentificationSettings_ZeroTurnsItOff(t *testing.T) {
	store := &stubIdentificationSettings{settings: services.IdentificationSettings{AutoAcceptThreshold: 0.9}}
	eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(store, "matcher-logreg-v1"))

	w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/identification",
		strings.NewReader(`{"auto_accept_threshold":0}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if store.setCalls != 1 || store.received.AutoAcceptThreshold == nil || *store.received.AutoAcceptThreshold != 0 {
		t.Fatalf("setting the threshold to 0 called the service %d times with %v; "+
			"a tenant turning auto-accept OFF must not be mistaken for a caller who sent nothing",
			store.setCalls, store.received.AutoAcceptThreshold)
	}
}

// The rule-merge switch ( Phase 4) rides the same endpoint. The GET carries
// the EFFECTIVE value, always present (the schema requires it), so the page
// never has to render "unset".
func TestContract_IdentificationSettings_GetCarriesAutoMergeExisting(t *testing.T) {
	sv := loadSpec(t)
	for _, on := range []bool{true, false} {
		store := &stubIdentificationSettings{settings: services.IdentificationSettings{AutoMergeExisting: on}}
		eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(store, "matcher-logreg-v1"))
		w := do(eng, http.MethodGet, "/api/v2/inventory-service/settings/identification", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
		}
		sv.assertConforms(t, "IdentificationSettingsResponse", w.Body.Bytes())
		var body struct {
			Identification struct {
				AutoMergeExisting *bool `json:"auto_merge_existing"`
			} `json:"identification"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// false must be PRESENT, not omitted: an omitempty on this field would
		// render "off" as "unset", and the page would show the default.
		if body.Identification.AutoMergeExisting == nil || *body.Identification.AutoMergeExisting != on {
			t.Errorf("auto_merge_existing = %v, want %v (body=%s)", body.Identification.AutoMergeExisting, on, w.Body.String())
		}
	}
}

// PARTIAL update, direction one: only the toggle is sent. The threshold must
// reach the service as NIL (leave it alone) — not as 0, which would turn the
// tenant's auto-accept off because they flipped an unrelated switch — and the
// response must still report the stored threshold.
//
// MUTATION: make the body's AutoAcceptThreshold a plain float64 and this fails.
func TestContract_IdentificationSettings_ToggleOnlyLeavesTheThresholdAlone(t *testing.T) {
	sv := loadSpec(t)
	store := &stubIdentificationSettings{settings: services.IdentificationSettings{AutoAcceptThreshold: 0.9, AutoMergeExisting: true}}
	eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(store, "matcher-logreg-v1"))

	w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/identification",
		strings.NewReader(`{"auto_merge_existing":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IdentificationSettingsResponse", w.Body.Bytes())
	if store.received.AutoAcceptThreshold != nil {
		t.Errorf("a toggle-only body reached the service with a threshold of %v; an unsent field must be nil", *store.received.AutoAcceptThreshold)
	}
	if store.received.AutoMergeExisting == nil || *store.received.AutoMergeExisting {
		t.Errorf("false was not delivered as false: %v", store.received.AutoMergeExisting)
	}
	if !strings.Contains(w.Body.String(), `"auto_accept_threshold":0.9`) {
		t.Errorf("the response lost the stored threshold: %s", w.Body.String())
	}
}

// Direction two, and both at once.
func TestContract_IdentificationSettings_BothFieldsAreDeliveredTogether(t *testing.T) {
	store := &stubIdentificationSettings{}
	eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(store, "matcher-logreg-v1"))
	w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/identification",
		strings.NewReader(`{"auto_accept_threshold":0.8,"auto_merge_existing":true}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if store.received.AutoAcceptThreshold == nil || *store.received.AutoAcceptThreshold != 0.8 ||
		store.received.AutoMergeExisting == nil || !*store.received.AutoMergeExisting {
		t.Errorf("service received %+v", store.received)
	}
}

func TestContract_IdentificationSettings_RejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"missing field":            `{}`,
		"not a number":             `{"auto_accept_threshold":"high"}`,
		"malformed":                `{`,
		"rule-merge not a boolean": `{"auto_merge_existing":"yes"}`,
		// null is "nobody said", and a body that says nothing must not report
		// success — it would look like a saved change that changed nothing.
		"only nulls": `{"auto_accept_threshold":null,"auto_merge_existing":null}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			store := &stubIdentificationSettings{}
			eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(store, "matcher-logreg-v1"))
			w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/identification", strings.NewReader(payload))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if store.setCalls != 0 {
				t.Error("a rejected request still reached the service")
			}
		})
	}
}

// Out of range is REFUSED, not clamped. "We rounded your number" is not an
// acceptable answer on the setting that decides whether two of a tenant's
// assets may be merged unasked.
func TestContract_IdentificationSettings_OutOfRangeIsRefused(t *testing.T) {
	for _, payload := range []string{`{"auto_accept_threshold":1.5}`, `{"auto_accept_threshold":-0.5}`} {
		store := &stubIdentificationSettings{err: services.ErrInvalidAutoAcceptThreshold}
		eng := newIdentificationSettingsEngine(NewIdentificationSettingsHandler(store, "matcher-logreg-v1"))
		w := do(eng, http.MethodPut, "/api/v2/inventory-service/settings/identification", strings.NewReader(payload))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", payload, w.Code, w.Body.String())
		}
	}
}
