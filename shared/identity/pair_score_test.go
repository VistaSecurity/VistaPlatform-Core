package identity_test

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

// Phase 5 — matcher v2 at the engine: what rank hands the seam, the pair
// score, and the proposal as a training sample. None of it decides anything.

// recordingMatcher remembers what the seam was shown, and answers the rank call
// and the pair call with different scores so a test can tell them apart.
type recordingMatcher struct {
	rank     map[string]float64 // asset id → score, for the rank call
	pair     float64            // every later call scores this
	calls    int
	observed []seams.Observation
	existing [][]seams.AssetSummary
}

func (m *recordingMatcher) Match(_ context.Context, o seams.Observation, existing []seams.AssetSummary) ([]seams.MatchScore, error) {
	m.calls++
	m.observed = append(m.observed, o)
	m.existing = append(m.existing, existing)
	var out []seams.MatchScore
	for _, a := range existing {
		s := m.pair
		if m.calls == 1 {
			s = m.rank[a.ID]
		}
		if s == 0 {
			continue
		}
		out = append(out, seams.MatchScore{
			Proposal: seams.NewProposal("test-matcher-v2", "matcher:recording", s),
			AssetID:  a.ID, Score: s, Reason: "recorded",
		})
	}
	return out, nil
}

// twoRecordsOneSighting builds the shape pair scoring exists for: record A by a
// serial and a MAC, record B by a hostname, two MACs and a DIFFERENT serial, and
// an observation carrying A's serial and B's SECOND MAC. Both records are in
// service, so nothing about approval stands between them and an auto-accept.
func twoRecordsOneSighting(t *testing.T, e *identity.Engine, repo interface {
	SetStatus(identity.AssetRef, string)
}) (a, b identity.Resolution, o identity.Observation) {
	t.Helper()
	a = mustResolve(t, e, obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-PAIR-A"), id(identity.KindMACAddress, "0a:00:00:00:0a:01")))
	b = mustResolve(t, e, obs(assetclass.KeyServer,
		scoped(identity.KindHostname, "pair-host-b", "segment-1"),
		id(identity.KindSerialNumber, "SN-PAIR-B"),
		id(identity.KindMACAddress, "0a:00:00:00:0b:01"),
		id(identity.KindMACAddress, "0a:00:00:00:0b:02"),
	))
	repo.SetStatus(a.Asset, identity.StatusMonitoring)
	repo.SetStatus(b.Asset, identity.StatusMonitoring)
	o = obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-PAIR-A"),
		id(identity.KindMACAddress, "0A:00:00:00:0B:02"), // B's second MAC, spelled as a collector might
	)
	return a, b, o
}

// The real model: the two records disagree on a serial, so whatever the
// sighting says about each of them, the RECORDS score at or under the singleton
// ceiling — "scored, and scored as two things". Below the candidate that shares
// the sighting's serial, which is what proves the pair was scored as a pair (A
// against B) and not as a copy of a candidate's own score.
func TestPairScoreIsTheTwoRecordsAgainstEachOther(t *testing.T) {
	e, repo := newEngine(t, identity.Config{Matcher: seams.NewLearnedMatcher()})
	a, b, o := twoRecordsOneSighting(t, e, repo)

	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	props := repo.Proposals()
	if len(props) != 1 {
		t.Fatalf("proposals = %d, want 1", len(props))
	}
	p := props[0]
	if p.PairScore <= 0 || p.PairScore > matcher.SingletonConflictCeiling {
		t.Errorf("pair score = %v, want scored and at most the singleton ceiling %v: the two records carry different serials",
			p.PairScore, matcher.SingletonConflictCeiling)
	}
	for _, c := range p.Candidates {
		if c.Ref.ID == a.Asset.ID && c.Score <= p.PairScore {
			t.Errorf("record A (sharing the sighting's serial) scored %v, not above the pair's %v", c.Score, p.PairScore)
		}
	}
	want := []string{res.Candidates[0].Ref.ID, res.Candidates[1].Ref.ID}
	if !reflect.DeepEqual(p.PairAssetIDs, want) {
		t.Errorf("pair ids = %v, want the two top-ranked candidates in rank order %v", p.PairAssetIDs, want)
	}
	got := []string{p.PairAssetIDs[0], p.PairAssetIDs[1]}
	sort.Strings(got)
	ab := []string{a.Asset.ID, b.Asset.ID}
	sort.Strings(ab)
	if !reflect.DeepEqual(got, ab) {
		t.Errorf("pair ids = %v, want the two records %v", p.PairAssetIDs, ab)
	}
	if p.PairReason == "" {
		t.Error("a pair score with no reason can only be rubber-stamped")
	}
}

// ADR-0008 D5: the pair score is advisory. A pair the model is SURE about does
// not turn a below-threshold proposal into an auto-accept, and does not change
// the outcome at all.
func TestPairScoreDecidesNothing(t *testing.T) {
	m := &recordingMatcher{rank: map[string]float64{}, pair: 0.99}
	e, repo := newEngine(t, identity.Config{Matcher: m, AutoAcceptThreshold: 0.5})
	a, b, o := twoRecordsOneSighting(t, e, repo)
	m.calls, m.observed, m.existing = 0, nil, nil
	m.rank[a.Asset.ID], m.rank[b.Asset.ID] = 0.3, 0.2

	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeConflict || res.AutoAccepted {
		t.Fatalf("outcome = %s (auto-accepted %v): a 0.99 PAIR score below-threshold candidates must not merge anything",
			res.Outcome, res.AutoAccepted)
	}
	props := repo.Proposals()
	if len(props) != 1 || props[0].AutoAccepted {
		t.Fatalf("proposals = %+v, want one, not auto-accepted", props)
	}
	if props[0].PairScore != 0.99 {
		t.Errorf("pair score = %v, want the matcher's 0.99 recorded as evidence", props[0].PairScore)
	}
	if m.calls != 2 {
		t.Errorf("the seam was consulted %d times, want 2 (the candidates, then the pair)", m.calls)
	}
}

// What the seam is shown: EVERY value of a kind (v1 kept whichever it met last,
// so a candidate whose second MAC agreed scored as a disagreement), normalised
// like the stored values, with the derived ones and the generic names marked.
func TestRankShowsTheSeamEveryValueAndTheMarks(t *testing.T) {
	m := &recordingMatcher{rank: map[string]float64{}}
	e, repo := newEngine(t, identity.Config{Matcher: m})
	_, b, o := twoRecordsOneSighting(t, e, repo)
	derived := identity.Identifier{
		Kind: identity.KindMACAddress, Value: "0a:00:00:00:0c:01", Confidence: 0.9,
		Source: identity.Source{Kind: identity.SourceInferred, Ref: "derived:eui64:2001:db8::800:ff:fe00:c01"},
	}
	generic := scoped(identity.KindHostname, "iphone", "segment-1")
	generic.Generic = true
	o.Identifiers = append(o.Identifiers, derived, generic)
	m.calls, m.observed, m.existing = 0, nil, nil

	mustResolve(t, e, o)
	if m.calls == 0 {
		t.Fatal("the matcher was never consulted")
	}
	seen := m.observed[0]
	if got := seen.Identifiers[string(identity.KindMACAddress)]; !containsAll(got, "0a:00:00:00:0b:02", "0a:00:00:00:0c:01") {
		t.Errorf("observation MACs shown to the seam = %v, want both, normalised", got)
	}
	if got := seen.DerivedIdentifiers[string(identity.KindMACAddress)]; !reflect.DeepEqual(got, []string{"0a:00:00:00:0c:01"}) {
		t.Errorf("derived MACs shown to the seam = %v, want only the derived one", got)
	}
	if !reflect.DeepEqual(seen.GenericNames, []string{"iphone"}) {
		t.Errorf("generic names shown to the seam = %v, want [iphone]", seen.GenericNames)
	}
	var bSummary *seams.AssetSummary
	for i := range m.existing[0] {
		if m.existing[0][i].ID == b.Asset.ID {
			bSummary = &m.existing[0][i]
		}
	}
	if bSummary == nil {
		t.Fatal("record B was not shown to the seam")
	}
	if got := bSummary.Identifiers[string(identity.KindMACAddress)]; !containsAll(got, "0a:00:00:00:0b:01", "0a:00:00:00:0b:02") {
		t.Errorf("record B's MACs shown to the seam = %v, want both", got)
	}
}

// The proposal is a complete training sample (lossless export): the
// observation's own identifiers with their marks, its context, and each
// candidate as it was compared — recorded even when NO matcher scored anything,
// because a reviewer's answer to an unscored question is still a label.
func TestProposalCarriesTheObservationAndTheCandidatesAsCompared(t *testing.T) {
	e, repo := newEngine(t, identity.Config{Matcher: seams.NullMatcher{}})
	a, b, o := twoRecordsOneSighting(t, e, repo)
	derived := identity.Identifier{
		Kind: identity.KindMACAddress, Value: "0a:00:00:00:0c:01", Confidence: 0.9,
		Source: identity.Source{Kind: identity.SourceInferred, Ref: "derived:serial:0a000000c01"},
	}
	o.Identifiers = append(o.Identifiers, derived)

	mustResolve(t, e, o)
	props := repo.Proposals()
	if len(props) != 1 {
		t.Fatalf("proposals = %d, want 1", len(props))
	}
	p := props[0]
	if p.PairScore != 0 || p.PairAssetIDs != nil || p.PairReason != "" {
		t.Errorf("pair = %v %v %q under the null matcher, want unscored", p.PairScore, p.PairAssetIDs, p.PairReason)
	}
	byKey := map[string]identity.Identifier{}
	for _, id := range p.ObservationIdentifiers {
		byKey[string(id.Kind)+"="+id.Value] = id
	}
	for _, k := range []string{"serial_number=SN-PAIR-A", "mac_address=0a:00:00:00:0b:02", "mac_address=0a:00:00:00:0c:01"} {
		if _, ok := byKey[k]; !ok {
			t.Errorf("observation identifiers %v lack %s (normalised)", p.ObservationIdentifiers, k)
		}
	}
	if !byKey["mac_address=0a:00:00:00:0c:01"].Inferred() {
		t.Error("the derived MAC is not marked derived on the proposal")
	}
	if byKey["mac_address=0a:00:00:00:0b:02"].Inferred() {
		t.Error("an observed MAC is marked derived on the proposal")
	}
	if p.ObservationContext == nil || p.ObservationContext.Class != assetclass.KeyServer ||
		p.ObservationContext.SourceKind != string(identity.SourceMeasured) || p.ObservationContext.SeenAt.IsZero() {
		t.Errorf("observation context = %+v, want the class, source kind and time the matcher saw", p.ObservationContext)
	}
	for _, c := range p.Candidates {
		if c.Snapshot == nil {
			t.Fatalf("candidate %s has no snapshot", c.Ref.ID)
		}
		want := len(repo.Identifiers(identity.AssetRef{TenantID: tenant, ID: c.Ref.ID}))
		if c.Ref.ID == a.Asset.ID || c.Ref.ID == b.Asset.ID {
			if len(c.Snapshot.Identifiers) != want {
				t.Errorf("candidate %s snapshot has %d identifiers, the record has %d", c.Ref.ID, len(c.Snapshot.Identifiers), want)
			}
		}
		if c.Snapshot.Class != assetclass.KeyServer {
			t.Errorf("candidate %s snapshot class = %q", c.Ref.ID, c.Snapshot.Class)
		}
	}
}

// The fold (A3) carries the pair like a candidate score: the strictly higher
// one wins with its ids and reason, in either arrival order, and the
// observation's identifiers become the union.
func TestFoldKeepsTheHigherPairScoreAndTheUnion(t *testing.T) {
	serial := id(identity.KindSerialNumber, "SN-F")
	mac := id(identity.KindMACAddress, "0a:00:00:00:0f:01")
	low := identity.MergeProposal{
		PairScore: 0.2, PairAssetIDs: []string{"a", "b"}, PairReason: "low",
		ObservationIdentifiers: []identity.Identifier{serial},
	}
	high := identity.MergeProposal{
		PairScore: 0.7, PairAssetIDs: []string{"b", "a"}, PairReason: "high",
		ObservationIdentifiers: []identity.Identifier{mac, serial},
	}
	unscored := identity.MergeProposal{ObservationIdentifiers: []identity.Identifier{mac}}
	for name, got := range map[string]identity.MergeProposal{
		"low then high":      identity.FoldMergeProposal(low, high),
		"high then low":      identity.FoldMergeProposal(high, low),
		"high then unscored": identity.FoldMergeProposal(high, unscored),
	} {
		if got.PairScore != 0.7 || got.PairReason != "high" || !reflect.DeepEqual(got.PairAssetIDs, []string{"b", "a"}) {
			t.Errorf("%s: pair = %v %q %v, want the higher 0.7 with its reason and ids", name, got.PairScore, got.PairReason, got.PairAssetIDs)
		}
		if len(got.ObservationIdentifiers) != 2 {
			t.Errorf("%s: observation identifiers = %v, want the union of two", name, got.ObservationIdentifiers)
		}
	}
}

func containsAll(have []string, want ...string) bool {
	in := map[string]bool{}
	for _, h := range have {
		in[h] = true
	}
	for _, w := range want {
		if !in[w] {
			return false
		}
	}
	return true
}
