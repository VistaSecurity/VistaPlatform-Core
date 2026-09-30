package identity_test

// Phase 2 — derived identifiers vote, with guards.
//
// A MAC worked out from an EUI-64 IPv6 address or a MAC-shaped serial reaches
// the engine as an identifier whose Source.Kind is `inferred`. These tests
// drive the real Engine.Resolve over the in-memory store and pin each guard;
// the mutation that makes each one fail is named on the test. Every MAC here
// is invented (the OUI table is never consulted by the engine) and every
// address is RFC 5737 / RFC 3849.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const (
	derivedMAC1 = "a0:b2:c3:d4:e5:f1"
	derivedMAC2 = "a0:b2:c3:d4:e5:f2"
	derivedRef  = "derived:eui64:2001:db8::a2b2:c3ff:fed4:e5f1"
)

// inferredMAC is what an emitter hands the engine for a derived MAC.
func inferredMAC(value, ref string) identity.Identifier {
	return identity.Identifier{
		Kind: identity.KindMACAddress, Value: value, Confidence: 0.9,
		Source: identity.Source{Kind: identity.SourceInferred, Ref: ref},
	}
}

func storedSource(t *testing.T, ids []identity.Identifier, kind identity.Kind, value string) identity.Source {
	t.Helper()
	for _, i := range ids {
		if i.Kind == kind && i.Value == value {
			return i.Source
		}
	}
	t.Fatalf("%s=%s not stored; have %+v", kind, value, ids)
	return identity.Source{}
}

// ── provenance ─────────────────────────────────────────────────────────────

// TestDerived_ProvenanceReachesTheStore: the engine keeps an inferred
// identifier's own source and ref (so asset_identifiers can say "derived from
// …"), and ignores any OTHER per-identifier source — a caller can weaken an
// identifier's provenance, never strengthen it.
// Mutation: restore `n.Source = obs.Source` in Resolve → the derived MAC is
// stored `measured` and the first assertion fails.
func TestDerived_ProvenanceReachesTheStore(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	claimsDeclared := id(identity.KindSerialNumber, "SN-DERIVE-1")
	claimsDeclared.Source = identity.Source{Kind: identity.SourceDeclared, Ref: "a caller pretending"}
	noRef := inferredMAC(derivedMAC2, "")

	res := mustResolve(t, e, obs(assetclass.KeyServer, claimsDeclared, inferredMAC(derivedMAC1, derivedRef), noRef))
	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created (the serial is real evidence)", res.Outcome)
	}
	held := repo.Identifiers(res.Asset)
	if got := storedSource(t, held, identity.KindMACAddress, derivedMAC1); got.Kind != identity.SourceInferred || got.Ref != derivedRef {
		t.Errorf("derived MAC stored with %+v, want inferred / %s", got, derivedRef)
	}
	if got := storedSource(t, held, identity.KindMACAddress, derivedMAC2); got.Kind != identity.SourceInferred || got.Ref != "sensor" {
		t.Errorf("derived MAC with no ref stored with %+v, want inferred / the observation's ref", got)
	}
	if got := storedSource(t, held, identity.KindSerialNumber, "SN-DERIVE-1"); got.Kind != identity.SourceMeasured {
		t.Errorf("a per-identifier `declared` source was honoured (%+v); only `inferred` may be set by a caller", got)
	}
}

// TestDerived_ObservedAndDerivedSameValueKeepsNativeProvenance: one sighting
// carrying the same MAC twice, derived first and observed second, stores it as
// OBSERVED.
// Mutation: drop the provenance swap in dedupeIdentifiers → stored inferred.
func TestDerived_ObservedAndDerivedSameValueKeepsNativeProvenance(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	res := mustResolve(t, e, obs(assetclass.KeyServer,
		inferredMAC(derivedMAC1, derivedRef),
		id(identity.KindMACAddress, derivedMAC1),
	))
	if got := storedSource(t, repo.Identifiers(res.Asset), identity.KindMACAddress, derivedMAC1); got.Kind != identity.SourceMeasured {
		t.Fatalf("stored %+v, want measured: the sighting observed this MAC", got)
	}
}

// ── guard 1: an inferred identifier never creates ──────────────────────────

// TestDerived_InferredOnlyObservationCannotCreate.
// Mutation: remove `&& !allInferred(attach)` in Resolve's default branch AND
// the allInferred refusal in resolveCreate → an asset is created.
func TestDerived_InferredOnlyObservationCannotCreate(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	_, err := e.Resolve(context.Background(), obs(assetclass.KeyServer, inferredMAC(derivedMAC1, derivedRef)))
	if !errors.Is(err, identity.ErrNoUsableIdentifier) {
		t.Fatalf("err = %v, want ErrNoUsableIdentifier", err)
	}
	if n := repo.AssetCount(); n != 0 {
		t.Fatalf("%d assets exist; a derived value minted a record", n)
	}
}

// TestDerived_ResolveCreateRefusesInferredOnly drives the create itself, past
// Resolve's routing, so the restatement at the INSERT is proven on its own.
// Mutation: remove the allInferred refusal in resolveCreate → created.
func TestDerived_ResolveCreateRefusesInferredOnly(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	o := obs(assetclass.KeyServer)
	_, err := e.ResolveCreateForTest(context.Background(), o, []identity.Identifier{inferredMAC(derivedMAC1, derivedRef)}, nil)
	if !errors.Is(err, identity.ErrNoUsableIdentifier) {
		t.Fatalf("err = %v, want ErrNoUsableIdentifier", err)
	}
	if n := repo.AssetCount(); n != 0 {
		t.Fatalf("%d assets exist", n)
	}
}

// TestDerived_AddingADerivedMACNeverTurnsASightingIntoACreate is the reason
// guard 1 routes rather than errors: a sighting whose only other evidence is
// owned by A (an address in a DHCP scope, which may not vote) was "another
// sighting of A" before it carried a derived MAC, and must not become an error
// or a new asset because of one.
// Mutation: remove `&& !allInferred(attach)` in Resolve's default branch →
// resolveCreate refuses and Resolve errors.
func TestDerived_AddingADerivedMACNeverTurnsASightingIntoACreate(t *testing.T) {
	e, repo := newEngine(t, identity.Config{DynamicScopes: map[string]bool{"seg-dhcp": true}})
	lease := scoped(identity.KindIPAddress, "192.0.2.44", "seg-dhcp")
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-A"), lease))

	res, err := e.Resolve(context.Background(), obs(assetclass.KeyServer, lease, inferredMAC(derivedMAC1, derivedRef)))
	if err != nil {
		t.Fatalf("Resolve: %v — a derived MAC made an ordinary sighting fail", err)
	}
	if res.Outcome == identity.OutcomeCreated || repo.AssetCount() != 1 {
		t.Fatalf("outcome %s with %d assets; a derived MAC created a record", res.Outcome, repo.AssetCount())
	}
	if hasKind(repo.Identifiers(a.Asset), identity.KindMACAddress) {
		t.Error("the derived MAC was attached to A through a lease-only link")
	}
}

// TestDerived_ConflictNeverCreatesAnAssetOfDerivedIdentifiers: a cross-kind
// conflict whose only UNOWNED identifier is derived opens the proposal and
// creates nothing — the observation asset would be held together by a
// derivation.
// Mutation: remove `|| allInferred(attach)` in conflictOutcome → a third asset
// carrying only the derived MAC.
func TestDerived_ConflictNeverCreatesAnAssetOfDerivedIdentifiers(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	_, _, o := conflictingObservations(t, e, repo)
	o.Identifiers = append(o.Identifiers, inferredMAC(derivedMAC1, derivedRef))

	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeConflict || res.Proposal.ID == "" {
		t.Fatalf("outcome %s, proposal %q; want a conflict with a proposal", res.Outcome, res.Proposal.ID)
	}
	if n := repo.AssetCount(); n != 2 {
		t.Fatalf("%d assets; the conflict created an asset whose only identifier is derived", n)
	}
	if !res.Asset.Zero() {
		t.Errorf("resolution names asset %s; want none", res.Asset.ID)
	}
}

// ── guard 2: native before inferred within a kind ──────────────────────────

// TestDerived_NativeDecidesBeforeInferred: A holds two MACs. A sighting lists
// a derived one FIRST and an observed one second; the observed one decides.
// Mutation: remove the native-first sort in groupByKind → the derived MAC
// decides and DecidedByInferred is true.
func TestDerived_NativeDecidesBeforeInferred(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, derivedMAC1), id(identity.KindMACAddress, derivedMAC2)))

	o := obs(assetclass.KeyServer, inferredMAC(derivedMAC2, derivedRef), id(identity.KindMACAddress, derivedMAC1))
	o.ObservedAt = observedAt.Add(time.Hour)
	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != a.Asset.ID {
		t.Fatalf("outcome %s on %s, want matched on A", res.Outcome, res.Asset.ID)
	}
	if res.DecidedByInferred {
		t.Fatal("a derived MAC decided while an observed MAC of the same kind matched")
	}
	for _, h := range repo.HistoryFor(a.Asset) {
		if _, ok := h.Changes["decided_by_inferred"]; ok {
			t.Errorf("history claims a derived decision: %+v", h.Changes)
		}
	}
}

// TestDerived_InferredMayOnlyConflictAfterANativeDecided: the observed MAC is
// A's and the derived MAC is B's. The observed one decides A; the derived one
// can only conflict — a proposal naming both, never a silent match on either.
// (Which of the two the walk met first does not survive into the proposal: the
// matcher re-ranks the candidates. The ordering itself is pinned by
// TestDerived_NativeDecidesBeforeInferred and, where it changes an outcome, by
// TestDerived_NativeDeciderStillMovesTheLease.)
func TestDerived_InferredMayOnlyConflictAfterANativeDecided(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, derivedMAC1)))
	b := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, derivedMAC2)))

	res := mustResolve(t, e, obs(assetclass.KeyServer, inferredMAC(derivedMAC2, derivedRef), id(identity.KindMACAddress, derivedMAC1)))
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	got := map[string]bool{}
	for _, c := range res.Candidates {
		got[c.Ref.ID] = true
	}
	if len(got) != 2 || !got[a.Asset.ID] || !got[b.Asset.ID] {
		t.Fatalf("candidates = %+v, want A and B", res.Candidates)
	}
	if len(repo.Identifiers(a.Asset)) != 1 || len(repo.Identifiers(b.Asset)) != 1 {
		t.Error("a MAC crossed between the candidates")
	}
}

// TestDerived_NativeDeciderStillMovesTheLease is guard 2 where it changes an
// outcome: B holds two MACs, and a direct sighting at A's DHCP address lists
// B's second MAC as DERIVED before its first MAC OBSERVED. The observed MAC
// decides, so the lease rule's "observed decider" condition holds and the
// address follows the MAC.
// Mutation: remove the native-first sort in groupByKind → the derived MAC
// decides, and the lease stays on A.
func TestDerived_NativeDeciderStillMovesTheLease(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	second := id(identity.KindMACAddress, "00:00:5e:00:53:1b")
	mustResolve(t, s.e, arpSighting(leaseAt.Add(2*time.Minute), leaseMACB, second))

	res := mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), inferredMAC(second.Value, "derived:eui64:2001:db8::200:5eff:fe00:531b"), leaseMACB, leaseAddr))
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.b.ID {
		t.Fatalf("resolution = %s on %s, want matched on B", res.Outcome, res.Asset.ID)
	}
	if res.DecidedByInferred {
		t.Fatal("the derived MAC decided although an observed MAC of the same kind matched")
	}
	if got := s.ownerOf(t, leaseAddr); got != s.b.ID {
		t.Fatalf("the lease is on %s, want it moved to B: an observed MAC decided", got)
	}
}

// TestDerived_InferredDecidesWhenNothingNativeMatched: with no observed MAC
// matching, a derived one may decide — that is the point of D3 — and both the
// resolution and the timeline say so.
func TestDerived_InferredDecidesWhenNothingNativeMatched(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, derivedMAC1)))

	o := obs(assetclass.KeyServer, inferredMAC(derivedMAC1, derivedRef), scoped(identity.KindIPAddress, "2001:db8::a2b2:c3ff:fed4:e5f1", identity.ScopeTenantDefault))
	o.ObservedAt = observedAt.Add(time.Hour)
	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != a.Asset.ID || res.DecidedBy != identity.KindMACAddress {
		t.Fatalf("resolution = %s on %s by %s, want matched on A by mac_address", res.Outcome, res.Asset.ID, res.DecidedBy)
	}
	if !res.DecidedByInferred {
		t.Error("DecidedByInferred = false; the resolution does not say the deciding MAC was derived")
	}
	if !hasChange(repo.HistoryFor(a.Asset), identity.ActionUpdated, "decided_by_inferred", derivedRef) {
		t.Error("A's timeline does not name the evidence the deciding MAC was derived from")
	}
	// The MAC A held as observed stays observed.
	if got := storedSource(t, repo.Identifiers(a.Asset), identity.KindMACAddress, derivedMAC1); got.Kind != identity.SourceMeasured {
		t.Errorf("A's observed MAC was relabelled %+v by a derived re-sighting", got)
	}
}

// TestDerived_InferredVersusNativeSerialIsAConflict is the spec's own test: a
// derived MAC matching A while an observed serial matches B is a proposal, not
// a silent match on either.
func TestDerived_InferredVersusNativeSerialIsAConflict(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, derivedMAC1)))
	b := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-B")))

	res := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-B"), inferredMAC(derivedMAC1, derivedRef)))
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	got := map[string]bool{}
	for _, c := range res.Candidates {
		got[c.Ref.ID] = true
	}
	if !got[a.Asset.ID] || !got[b.Asset.ID] {
		t.Fatalf("candidates = %+v, want A and B", res.Candidates)
	}
	if hasKind(repo.Identifiers(b.Asset), identity.KindMACAddress) || hasKind(repo.Identifiers(a.Asset), identity.KindSerialNumber) {
		t.Error("an identifier crossed between the two candidates")
	}
}

// ── guard 3: the unchanged rules still hold for a derived decider ──────────

// TestDerived_SingletonGuardStillContests: a derived MAC decides A, but the
// observation's observed serial disagrees with A's. Two serials are two
// things, whatever decided the match.
func TestDerived_SingletonGuardStillContests(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-A"), id(identity.KindMACAddress, derivedMAC1)))

	res := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-OTHER"), inferredMAC(derivedMAC1, derivedRef)))
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict: a derived MAC bypassed the singleton guard", res.Outcome)
	}
	for _, i := range repo.Identifiers(a.Asset) {
		if i.Kind == identity.KindSerialNumber && i.Value == "SN-OTHER" {
			t.Fatal("A now carries two serials")
		}
	}
}

// TestDerived_KeptSeparateStillHolds: a reviewer kept A (by MAC) and B (by
// hostname) apart. The same question arriving through a DERIVED MAC is the
// same question, and is not asked again.
func TestDerived_KeptSeparateStillHolds(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, derivedMAC1)))
	mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "build-7", "segment-1")))
	first := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, derivedMAC1), scoped(identity.KindHostname, "build-7", "segment-1")))
	if first.Outcome != identity.OutcomeConflict || first.Proposal.ID == "" {
		t.Fatalf("fixture: outcome %s, proposal %q", first.Outcome, first.Proposal.ID)
	}
	if err := repo.ResolveProposal(first.Proposal, "kept_separate", "reviewer-1", observedAt.Add(time.Hour)); err != nil {
		t.Fatalf("ResolveProposal: %v", err)
	}
	before := proposalCount(repo)

	o := obs(assetclass.KeyServer, inferredMAC(derivedMAC1, derivedRef), scoped(identity.KindHostname, "build-7", "segment-1"))
	o.ObservedAt = observedAt.Add(2 * time.Hour)
	res := mustResolve(t, e, o)
	if res.Suppressed == nil || proposalCount(repo) != before {
		t.Fatalf("outcome %s, suppressed %v, proposals %d → %d; a derived MAC re-opened a kept-separate pair",
			res.Outcome, res.Suppressed, before, proposalCount(repo))
	}
	if hasKind(repo.Identifiers(a.Asset), identity.KindHostname) {
		t.Error("the hostname crossed onto A")
	}
}

// TestDerived_DynamicAddressStillDoesNotVote: a derived MAC in a sighting does
// not license the address beside it to vote inside a DHCP scope.
func TestDerived_DynamicAddressStillDoesNotVote(t *testing.T) {
	e, _ := newEngine(t, identity.Config{DynamicScopes: map[string]bool{"seg-dhcp": true}})
	lease := scoped(identity.KindIPAddress, "192.0.2.45", "seg-dhcp")
	mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-A"), lease))
	b := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, derivedMAC1)))

	res := mustResolve(t, e, obs(assetclass.KeyServer, lease, inferredMAC(derivedMAC1, derivedRef)))
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != b.Asset.ID {
		t.Fatalf("outcome %s on %s, want matched on B by its MAC and no cross-kind conflict from the lease", res.Outcome, res.Asset.ID)
	}
}

// ── the lease rule: a derived decider moves no lease ───────────────────────

// TestDerived_InferredMACDoesNotMoveALease: B is matched by a MAC DERIVED from
// its IPv6 address while holding A's DHCP address. Every other condition of
// the lease rule holds (TestLease_AddressFollowsTheMAC is the positive control
// with an observed MAC), but a derivation is not direct evidence of who holds
// the lease now.
// Mutation: remove `decider.Inferred() ||` from leaseMoves → the lease moves.
func TestDerived_InferredMACDoesNotMoveALease(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	at := leaseAt.Add(time.Hour)

	res := mustResolve(t, s.e, arpSighting(at, inferredMAC(leaseMACB.Value, "derived:eui64:2001:db8::200:5eff:fe00:530b"), leaseAddr))
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.b.ID || !res.DecidedByInferred {
		t.Fatalf("resolution = %s on %s (inferred %v), want matched on B by the derived MAC", res.Outcome, res.Asset.ID, res.DecidedByInferred)
	}
	s.assertNotMoved(t, res, "the deciding MAC was derived, not observed")
}

// ── C1: a derived MAC still names a device ─────────────────────────────────

// TestDerived_AddressOnlyLinkCountsADerivedMAC: the C1 journey with the MAC
// DERIVED rather than seen. The sighting still names a device the provisional
// laptop does not hold, so the address-only link attaches nothing.
// Mutation: make carriesDeviceBinding skip inferred identifiers → the link is
// treated as naming no device, and the derived MAC is attached to the laptop.
func TestDerived_AddressOnlyLinkCountsADerivedMAC(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	laptopName := scoped(identity.KindHostname, "desk-laptop.local", segmentB)
	lease := scoped(identity.KindIPAddress, "198.51.100.40", segmentB)
	derived := inferredMAC(derivedMAC1, derivedRef)

	laptop := mustResolve(t, e, advert(advertAt, segmentB, laptopName, lease))
	if laptop.Outcome != identity.OutcomeProvisional {
		t.Fatalf("setup outcome = %s, want provisional", laptop.Outcome)
	}
	res := mustResolve(t, e, flow(advertAt.Add(time.Hour), segmentB, lease, derived))
	if res.Outcome != identity.OutcomeUnresolved || !res.Asset.Zero() {
		t.Fatalf("outcome %s on %q, want unresolved with no asset", res.Outcome, res.Asset.ID)
	}
	if refs := ownersOf(t, repo, derived); len(refs) != 0 {
		t.Fatalf("the derived MAC was attached to %s through a lease", refs[0].ID)
	}
	if !hasChange(repo.HistoryFor(laptop.Asset), identity.ActionUpdated, "address_only_link", true) {
		t.Error("no address_only_link entry on the laptop")
	}
}

// ── admission: a derived MAC establishes nothing ───────────────────────────

// TestDerived_AdmissionIgnoresDerivedIdentifiers: a direct, scoped sighting
// whose only MAC is derived is not "a directly observed interface".
// Mutation: remove the Inferred() skip in AssessAdmission → established by
// direct_scoped_interface.
func TestDerived_AdmissionIgnoresDerivedIdentifiers(t *testing.T) {
	o := identity.Observation{
		TenantID: tenant,
		Identifiers: []identity.Identifier{
			scoped(identity.KindIPAddress, "192.0.2.46", segmentD),
			inferredMAC(derivedMAC1, derivedRef),
		},
		Source:        identity.Source{Kind: identity.SourceMeasured, Ref: "sensor", Mode: identity.ModePassive},
		ObservedAt:    advertAt,
		Admission:     identity.AdmissionEvidence{Direct: true},
		DynamicScopes: map[string]bool{segmentD: true},
	}
	o.Network.SegmentID = segmentD
	d := identity.AssessAdmission(o)
	if d.Established {
		t.Fatalf("admission = %+v; a derived MAC established an entity", d)
	}
	if len(d.Reasons) != 1 || d.Reasons[0] != identity.ReasonDynamicAddressWithoutDeviceBinding {
		t.Errorf("reasons = %v, want %s", d.Reasons, identity.ReasonDynamicAddressWithoutDeviceBinding)
	}
	// Control: the same sighting with the MAC observed IS established.
	o.Identifiers[1] = id(identity.KindMACAddress, derivedMAC1)
	if d := identity.AssessAdmission(o); !d.Established {
		t.Fatalf("control: an observed MAC did not establish (%+v); the test proves nothing", d)
	}
}
