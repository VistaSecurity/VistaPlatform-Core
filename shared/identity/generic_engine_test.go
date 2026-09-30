package identity_test

// B2, part B — the engine's reaction to a generic name.
//
// Ingest marks a hostname many unrelated devices carry (`iphone`, `printer`,
// or one three or more of a tenant's assets hold) with Identifier.Generic
// (generic_names.go). These tests drive the three places the engine acts on
// the mark, through Resolve against the in-memory store:
//
//   - kindVotes: a generic name never decides a match;
//   - resolveContested / resolveConflict: an asset linked by a generic name
//     ALONE is not a candidate (none left → unresolved, one left → supporting);
//   - resolveSupporting / provisionalMatchMode: a generic name is never the
//     corroboration that fills a device identifier into another record.
//
// Every name is invented and every address is RFC 5737. Each test names the
// mutation that turns it red.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// generic is a hostname identifier as ingest hands it to the engine once
// identity.GenericNames has marked it.
func generic(value, scope string) identity.Identifier {
	return identity.Identifier{Kind: identity.KindHostname, Value: value, Scope: scope,
		Confidence: identity.GenericConfidence, Generic: true}
}

func normalized(t *testing.T, ident identity.Identifier) identity.Identifier {
	t.Helper()
	n, err := ident.Normalized()
	if err != nil {
		t.Fatalf("Normalized(%s): %v", ident.Value, err)
	}
	return n
}

func ownersIn(t *testing.T, repo identity.Repository, ident identity.Identifier) []identity.AssetRef {
	t.Helper()
	n := normalized(t, ident)
	refs, err := repo.FindByIdentifier(context.Background(), tenant, n.Kind, n.Value, n.Scope)
	if err != nil {
		t.Fatalf("FindByIdentifier(%s): %v", n.Value, err)
	}
	return refs
}

// ── effect 1: a generic name never decides ─────────────────────────────────

// TestGenericName_NeverDecidesAMatch: a phone record holds the default name
// `iphone`; a second phone announcing the same default name with its own MAC
// is a NEW asset, not a sighting of the first — and its MAC is not written onto
// the first phone. The name is still recorded (it stays the first phone's and
// is reported unattached here).
//
// The unmarked polarity is the control: an ordinary equal hostname still
// decides, as it always has. Without it the marked case could pass because
// names had stopped voting altogether.
//
// Mutation check: delete the `id.Generic` refusal in kindVotes → the marked
// case matches the first phone and attaches the second phone's MAC to it.
func TestGenericName_NeverDecidesAMatch(t *testing.T) {
	const seg = "seg-static"
	for _, tt := range []struct {
		name      string
		mark      bool
		wantMatch bool
	}{
		{"generic name", true, false},
		{"ordinary name (control)", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			name := scoped(identity.KindHostname, "iphone", seg)
			if tt.mark {
				name = generic("iphone", seg)
			}
			first := mustResolve(t, e, obs(assetclass.KeyUnknownHost, id(identity.KindMACAddress, "02:00:00:00:b2:01"), name))

			secondMAC := id(identity.KindMACAddress, "02:00:00:00:b2:02")
			o := obs(assetclass.KeyUnknownHost, name, secondMAC, scoped(identity.KindIPAddress, "192.0.2.52", seg))
			o.ObservedAt = observedAt.Add(time.Hour)
			res := mustResolve(t, e, o)

			if tt.wantMatch {
				if res.Outcome != identity.OutcomeMatched || res.Asset.ID != first.Asset.ID {
					t.Fatalf("control: outcome %s on %q, want matched on %s by the hostname", res.Outcome, res.Asset.ID, first.Asset.ID)
				}
				return
			}
			if res.Outcome != identity.OutcomeCreated || res.Asset.ID == first.Asset.ID {
				t.Fatalf("outcome %s on %q, want a NEW asset: a default name says nothing about which phone this is (the first is %s)",
					res.Outcome, res.Asset.ID, first.Asset.ID)
			}
			if refs := ownersIn(t, repo, secondMAC); len(refs) != 1 || refs[0].ID != res.Asset.ID {
				t.Errorf("the second phone's MAC is owned by %+v, want only the new asset %s", refs, res.Asset.ID)
			}
			if refs := ownersIn(t, repo, name); len(refs) != 1 || refs[0].ID != first.Asset.ID {
				t.Errorf("the name is owned by %+v, want still the first phone %s: it is recorded, not moved", refs, first.Asset.ID)
			}
			if !hasKind(res.Unattached, identity.KindHostname) {
				t.Errorf("unattached = %+v, want the name reported (it belongs to the first phone)", res.Unattached)
			}
			if n := proposalCount(repo); n != 0 {
				t.Errorf("%d proposals, want 0", n)
			}
		})
	}
}

// TestGenericName_ControllerSightingIsNotAConflict is the queue-noise shape of
// B2: a controller reports a phone by its MAC and the default name the phone
// announces, and that name already belongs to a DIFFERENT record. Before, the
// MAC decided one asset and the name another — a cross-kind conflict and a
// merge proposal between two phones because neither was renamed. Now the MAC
// decides, the name is reported unattached, and nobody is asked.
//
// Mutation check: delete the `id.Generic` refusal in kindVotes → a conflict and
// a proposal.
func TestGenericName_ControllerSightingIsNotAConflict(t *testing.T) {
	const seg = "seg-static"
	e, repo := newEngine(t, identity.Config{})
	phoneMAC := id(identity.KindMACAddress, "02:00:00:00:b2:10")
	phone := mustResolve(t, e, obs(assetclass.KeyUnknownHost, phoneMAC, scoped(identity.KindIPAddress, "192.0.2.10", seg)))
	other := mustResolve(t, e, obs(assetclass.KeyUnknownHost,
		id(identity.KindMACAddress, "02:00:00:00:b2:11"), generic("iphone", seg)))

	o := obs(assetclass.KeyUnknownHost, phoneMAC, generic("iphone", seg))
	o.Admission = identity.AdmissionEvidence{Direct: true, Authoritative: true}
	o.ObservedAt = observedAt.Add(time.Hour)
	res := mustResolve(t, e, o)

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != phone.Asset.ID {
		t.Fatalf("outcome %s on %q, want matched on the phone %s by its MAC (the other record is %s)",
			res.Outcome, res.Asset.ID, phone.Asset.ID, other.Asset.ID)
	}
	if res.DecidedBy != identity.KindMACAddress {
		t.Errorf("DecidedBy = %s, want mac_address", res.DecidedBy)
	}
	if n := proposalCount(repo); n != 0 || res.Proposal.ID != "" {
		t.Errorf("%d proposals, want 0: a shared default name is not a question", n)
	}
	if !hasKind(res.Unattached, identity.KindHostname) {
		t.Errorf("unattached = %+v, want the other record's name reported", res.Unattached)
	}
}

// TestGenericName_DuplicateCopyStillGeneric: an observation carrying one name
// twice, once marked and once not, keeps the mark. dedupeIdentifiers keeps the
// first copy; the mark is a judgement about the value, so it survives.
//
// Mutation check: drop the `Generic ||` merge in dedupeIdentifiers → the
// unmarked first copy votes and the observation matches the first phone.
func TestGenericName_DuplicateCopyStillGeneric(t *testing.T) {
	const seg = "seg-static"
	e, _ := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs(assetclass.KeyUnknownHost,
		id(identity.KindMACAddress, "02:00:00:00:b2:21"), generic("iphone", seg)))

	o := obs(assetclass.KeyUnknownHost,
		scoped(identity.KindHostname, "iphone", seg), generic("iphone", seg),
		id(identity.KindMACAddress, "02:00:00:00:b2:22"))
	o.ObservedAt = observedAt.Add(time.Hour)
	res := mustResolve(t, e, o)
	if res.Asset.ID == first.Asset.ID {
		t.Fatalf("outcome %s on the first phone %s: an unmarked duplicate of a generic name decided the match", res.Outcome, first.Asset.ID)
	}
}

// ── effect 2: a generic-only link is not a candidate ───────────────────────

// TestGenericName_DynamicScopeNoProposal is the spec's engine test: a sighting
// carrying `iphone` and an address in a DHCP scope, against two assets that
// each hold one of them — the name on one phone, the lease on another. Nothing
// may vote (a generic name never, a dynamic address never), so everything is
// contested. Before: a proposal asking whether two phones are one. Now: the
// name's asset is dropped, the lease's asset is the single candidate, and a
// lease alone links nothing ( C1) — unresolved, no asset, no proposal.
//
// Mutation check: delete the withoutGenericOnly pruning in resolveContested →
// a two-candidate proposal opens and this fails.
func TestGenericName_DynamicScopeNoProposal(t *testing.T) {
	const dyn = "seg-dhcp"
	e, repo := newEngine(t, identity.Config{DynamicScopes: map[string]bool{dyn: true}})
	named := mustResolve(t, e, obs(assetclass.KeyUnknownHost,
		id(identity.KindMACAddress, "02:00:00:00:b2:31"), generic("iphone", dyn)))
	lease := scoped(identity.KindIPAddress, "192.0.2.131", dyn)
	leased := mustResolve(t, e, obs(assetclass.KeyUnknownHost, id(identity.KindMACAddress, "02:00:00:00:b2:32"), lease))
	namedHeld, leasedHeld := len(repo.Identifiers(named.Asset)), len(repo.Identifiers(leased.Asset))

	o := obs(assetclass.KeyUnknownHost, generic("iphone", dyn), lease)
	o.ObservedAt = observedAt.Add(time.Hour)
	res := mustResolve(t, e, o)

	if n := proposalCount(repo); n != 0 || res.Proposal.ID != "" {
		t.Fatalf("%d proposals (outcome %s): a default name and a lease are no reason to ask whether two phones are one", n, res.Outcome)
	}
	if res.Outcome != identity.OutcomeUnresolved || !res.Asset.Zero() {
		t.Errorf("outcome %s on %q, want unresolved with no asset", res.Outcome, res.Asset.ID)
	}
	if got := len(repo.Identifiers(named.Asset)); got != namedHeld {
		t.Errorf("the named phone holds %d identifiers, want %d unchanged", got, namedHeld)
	}
	if got := len(repo.Identifiers(leased.Asset)); got != leasedHeld {
		t.Errorf("the leased phone holds %d identifiers, want %d unchanged", got, leasedHeld)
	}
	if !hasChange(repo.HistoryFor(leased.Asset), identity.ActionUpdated, "address_only_link", true) {
		t.Errorf("the lease holder's history does not record the address-only link: %v", historyActions(repo.HistoryFor(leased.Asset)))
	}
}

// TestGenericName_TwoHoldersOfTheNameNoProposal: every asset the observation
// links to is linked by the generic name alone — here two records both hold
// `iphone` — and the address it carries is nobody's. Relayed evidence cannot
// establish anything, so before this it was a proposal between the two
// records. Now there is no candidate at all: unresolved, nothing written.
//
// Mutation check: delete the withoutGenericOnly pruning in resolveContested →
// a proposal naming both records opens.
func TestGenericName_TwoHoldersOfTheNameNoProposal(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	name := generic("iphone.local", segmentD)
	a := mustResolve(t, e, advert(advertAt, segmentD, name, id(identity.KindMACAddress, "02:00:00:00:b2:41")))
	if a.Asset.Zero() {
		t.Fatalf("setup: outcome %s, want an asset holding the name", a.Outcome)
	}
	b, err := repo.CreateAsset(context.Background(), tenant, identity.NewAsset{
		ClassKey: assetclass.KeyUnknownHost, ClassSourceKind: identity.ClassSourceMeasured,
		DisplayName: "second phone", Status: identity.StatusPendingApproval,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor"},
		Identifiers: []identity.Identifier{normalized(t, id(identity.KindMACAddress, "02:00:00:00:b2:42"))},
		FirstSeenAt: advertAt, LastSeenAt: advertAt,
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	repo.Corrupt(tenant, normalized(t, name), b)
	addr := scoped(identity.KindIPAddress, "192.0.2.141", segmentD)

	res := mustResolve(t, e, advert(advertAt.Add(time.Hour), segmentD, name, addr))

	if n := len(repo.Proposals()); n != 0 {
		t.Fatalf("%d proposals (outcome %s), want 0: both records are linked by a default name alone", n, res.Outcome)
	}
	if res.Outcome != identity.OutcomeUnresolved || !res.Asset.Zero() {
		t.Errorf("outcome %s on %q, want unresolved with no asset", res.Outcome, res.Asset.ID)
	}
	if refs := ownersOf(t, repo, addr); len(refs) != 0 {
		t.Errorf("the address was attached to %s", refs[0].ID)
	}
}

// TestGenericName_RealLinkKeepsTheCandidate is the other polarity: an asset
// linked by a generic name AND a real identifier is still a candidate — the
// rule drops an asset whose ONLY link is generic, not every asset a generic
// name touches. Two records, each linked by its own address (one of them also
// by `iphone`), are still a question.
//
// Mutation check: make genericOnly true when ANY identifier in the link is
// generic → the first record is dropped, the second becomes supporting
// evidence, and no proposal opens.
func TestGenericName_RealLinkKeepsTheCandidate(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	name := generic("iphone.local", segmentB)
	addrA := scoped(identity.KindIPAddress, "192.0.2.151", segmentB)
	addrB := scoped(identity.KindIPAddress, "192.0.2.152", segmentB)
	a := mustResolve(t, e, advert(advertAt, segmentB, name, addrA))
	b := mustResolve(t, e, advert(advertAt, segmentB, scoped(identity.KindHostname, "hall-printer.local", segmentB), addrB))
	if a.Outcome != identity.OutcomeProvisional || b.Outcome != identity.OutcomeProvisional {
		t.Fatalf("setup outcomes %s, %s; want two provisional records", a.Outcome, b.Outcome)
	}

	res := mustResolve(t, e, flow(advertAt.Add(time.Hour), segmentB, name, addrA, addrB))

	if res.Outcome != identity.OutcomeConflict || len(res.Candidates) != 2 {
		t.Fatalf("outcome %s with %d candidates, want a conflict naming both records", res.Outcome, len(res.Candidates))
	}
	var aEvidence []identity.Identifier
	for _, c := range res.Candidates {
		if c.Ref.ID == a.Asset.ID {
			aEvidence = c.MatchedIdentifiers
		}
	}
	if !hasKind(aEvidence, identity.KindIPAddress) {
		t.Errorf("record A's evidence = %+v, want its address", aEvidence)
	}
	if n := len(repo.Proposals()); n != 1 {
		t.Errorf("%d proposals, want 1", n)
	}
}

// TestResolveConflict_DropsGenericOnlyCandidates drives the cross-kind conflict
// path's pruning directly. Through Resolve a generic name never votes, so the
// walk cannot hand resolveConflict a candidate linked by one alone; the rule
// is there for any evidence that reaches the path another way.
//
// Mutation check: delete the withoutGenericOnly pruning in resolveConflict →
// every case opens a proposal naming the generic-only record.
func TestResolveConflict_DropsGenericOnlyCandidates(t *testing.T) {
	const seg = "seg-static"
	ctx := context.Background()
	serial := normalized(t, id(identity.KindSerialNumber, "SN-B2-1"))
	mac := normalized(t, id(identity.KindMACAddress, "02:00:00:00:b2:51"))
	nameA := normalized(t, generic("iphone", seg))
	nameB := normalized(t, generic("printer", seg))

	for _, tt := range []struct {
		name          string
		link          map[string]identity.Identifier // asset label → its link
		wantOutcome   identity.Outcome
		wantProposal  int
		wantCandidate []string // labels, when a proposal opens
		wantAsset     string   // label, when supporting
	}{
		{"one real candidate left → supporting", map[string]identity.Identifier{"serial": serial, "nameA": nameA},
			identity.OutcomeSupporting, 0, nil, "serial"},
		{"none left → unresolved", map[string]identity.Identifier{"nameA": nameA, "nameB": nameB},
			identity.OutcomeUnresolved, 0, nil, ""},
		{"two real candidates left → proposal without the generic one",
			map[string]identity.Identifier{"serial": serial, "nameA": nameA, "mac": mac},
			identity.OutcomeConflict, 1, []string{"serial", "mac"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			refs := map[string]identity.AssetRef{}
			owners := map[string][]identity.AssetRef{}
			evidence := map[string][]identity.Identifier{}
			var ids []identity.Identifier
			var seq []string
			for _, label := range []string{"serial", "nameA", "nameB", "mac"} {
				ident, ok := tt.link[label]
				if !ok {
					continue
				}
				r := mustResolve(t, e, obs(assetclass.KeyServer, ident, id(identity.KindAgentID, "agent-"+label)))
				refs[label] = r.Asset
				owners[ident.Key()] = []identity.AssetRef{r.Asset}
				evidence[r.Asset.ID] = []identity.Identifier{ident}
				ids = append(ids, ident)
				seq = append(seq, r.Asset.ID)
			}
			o := obs(assetclass.KeyServer, ids...)
			o.ObservedAt = observedAt.Add(time.Hour)

			res, err := e.ResolveConflictForTest(ctx, o, ids, owners, evidence, seq)
			if err != nil {
				t.Fatalf("resolveConflict: %v", err)
			}
			if res.Outcome != tt.wantOutcome {
				t.Fatalf("outcome = %s, want %s", res.Outcome, tt.wantOutcome)
			}
			if n := proposalCount(repo); n != tt.wantProposal {
				t.Fatalf("%d proposals, want %d", n, tt.wantProposal)
			}
			if tt.wantAsset != "" && res.Asset.ID != refs[tt.wantAsset].ID {
				t.Errorf("resolved to %q, want %s", res.Asset.ID, refs[tt.wantAsset].ID)
			}
			if tt.wantAsset == "" && tt.wantProposal == 0 && !res.Asset.Zero() {
				t.Errorf("resolved to %q, want no asset", res.Asset.ID)
			}
			if tt.wantCandidate != nil {
				got := map[string]bool{}
				for _, c := range res.Candidates {
					got[c.Ref.ID] = true
				}
				if len(got) != len(tt.wantCandidate) {
					t.Errorf("candidates = %v, want %v", got, tt.wantCandidate)
				}
				for _, label := range tt.wantCandidate {
					if !got[refs[label].ID] {
						t.Errorf("candidate %s (%s) missing from %v", label, refs[label].ID, got)
					}
				}
			}
		})
	}
}

// ── provisional records: a generic name is not corroboration ───────────────

// TestGenericName_OnlyLinkToProvisionalAttachesNothing is the C1 wrong merge
// with a default name standing in for the lease. A relayed advert creates a
// provisional record for one phone (`iphone.local` at one address). A sighting
// of ANOTHER phone — same default name, its own MAC, a different address — is
// linked to that record by the name alone.
//
//   - Unverified (a traffic sighting): before, every identifier was
//     "supporting evidence" filling in the provisional sketch, so the second
//     phone's MAC landed on the first phone's record. Now: no link, nothing
//     written, no clock moved, no history.
//   - Established (the controller meets the second phone directly): before,
//     the name decided the match and "corroborated" the provisional record —
//     MAC attached, record promoted. Now: the name cannot decide, the second
//     phone is its own asset, the first stays provisional.
//
// Mutation checks: delete the genericOnly guard in resolveSupporting → the
// unverified case attaches the MAC; delete the `id.Generic` refusal in
// kindVotes → the established case corroborates the provisional record.
func TestGenericName_OnlyLinkToProvisionalAttachesNothing(t *testing.T) {
	name := generic("iphone.local", segmentB)
	firstAddr := scoped(identity.KindIPAddress, "192.0.2.161", segmentB)
	secondMAC := id(identity.KindMACAddress, "02:00:00:00:b2:62")
	secondAddr := scoped(identity.KindIPAddress, "192.0.2.162", segmentB)

	for _, tt := range []struct {
		name        string
		observation func(at time.Time) identity.Observation
	}{
		{"unverified sighting", func(at time.Time) identity.Observation {
			return flow(at, segmentB, name, secondMAC, secondAddr)
		}},
		{"established sighting", func(at time.Time) identity.Observation {
			o := direct(at, segmentB, name, secondMAC, secondAddr)
			o.Admission.Authoritative = true
			return o
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, repo := newProvisionalEngine(t, true)
			p := mustResolve(t, e, advert(advertAt, segmentB, name, firstAddr))
			if p.Outcome != identity.OutcomeProvisional {
				t.Fatalf("setup outcome = %s, want provisional", p.Outcome)
			}
			heldBefore := len(repo.Identifiers(p.Asset))
			historyBefore := len(repo.HistoryFor(p.Asset))

			res := mustResolve(t, e, tt.observation(advertAt.Add(time.Hour)))

			if res.Asset.ID == p.Asset.ID {
				t.Fatalf("outcome %s on the first phone's record %s: a default name linked two phones", res.Outcome, p.Asset.ID)
			}
			for _, ident := range []identity.Identifier{secondMAC, secondAddr} {
				for _, r := range ownersOf(t, repo, ident) {
					if r.ID == p.Asset.ID {
						t.Errorf("%s was attached to the first phone's record", ident.Value)
					}
				}
			}
			if n := len(repo.Identifiers(p.Asset)); n != heldBefore {
				t.Errorf("the first phone's record holds %d identifiers, want %d unchanged", n, heldBefore)
			}
			if got := repo.IdentityStatusOf(p.Asset); got != string(identity.IdentityProvisional) {
				t.Errorf("identity_status = %q, want still provisional: nothing corroborated it", got)
			}
			if got := repo.LastSeen(p.Asset); !got.Equal(advertAt) {
				t.Errorf("last_seen = %s, want %s unchanged", got, advertAt)
			}
			if n := len(repo.HistoryFor(p.Asset)); n != historyBefore {
				t.Errorf("the first phone's record gained %d history entries, want 0: %v", n-historyBefore, historyActions(repo.HistoryFor(p.Asset)))
			}
			if n := len(repo.Proposals()); n != 0 {
				t.Errorf("%d proposals, want 0", n)
			}
		})
	}
}

// TestGenericName_PlusLeaseIsStillALeaseLink: the provisional record holds the
// default name AND an address, and a sighting carries both plus a MAC. The name
// is not corroboration, so the link is the address alone and the address-only
// link rule ( C1) applies: nothing attached, history says why.
//
// Mutation check: hand leaseOnlyLink the raw link (generic name included)
// instead of withoutGeneric(link) → the name counts as corroboration and the
// MAC is attached to the provisional record.
func TestGenericName_PlusLeaseIsStillALeaseLink(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	name := generic("iphone.local", segmentB)
	addr := scoped(identity.KindIPAddress, "192.0.2.171", segmentB)
	mac := id(identity.KindMACAddress, "02:00:00:00:b2:71")
	p := mustResolve(t, e, advert(advertAt, segmentB, name, addr))
	if p.Outcome != identity.OutcomeProvisional {
		t.Fatalf("setup outcome = %s, want provisional", p.Outcome)
	}

	res := mustResolve(t, e, flow(advertAt.Add(time.Hour), segmentB, name, addr, mac))

	if res.Outcome != identity.OutcomeUnresolved || !res.Asset.Zero() {
		t.Fatalf("outcome %s on %q, want unresolved with no asset: the only real link is a lease", res.Outcome, res.Asset.ID)
	}
	if refs := ownersOf(t, repo, mac); len(refs) != 0 {
		t.Errorf("the MAC was attached to %s", refs[0].ID)
	}
	if !hasChange(repo.HistoryFor(p.Asset), identity.ActionUpdated, "address_only_link", true) {
		t.Errorf("no address_only_link entry on the record: %v", historyActions(repo.HistoryFor(p.Asset)))
	}
}

// TestProvisionalMatchMode_GenericNameIsNotCorroboration pins the established
// path's classifier directly: a match on a provisional record by address plus
// a generic name is an address-only match (hearsay yields), and a generic name
// alone corroborates nothing. The ordinary name is the control.
//
// Mutation check: delete `matched = withoutGeneric(matched)` in
// provisionalMatchMode → "address + generic name" corroborates.
func TestProvisionalMatchMode_GenericNameIsNotCorroboration(t *testing.T) {
	ctx := context.Background()
	e, repo := newEngine(t, identity.Config{})
	addr := normalized(t, scoped(identity.KindIPAddress, "192.0.2.181", "seg-static"))
	name := normalized(t, generic("iphone", "seg-static"))
	plain := normalized(t, scoped(identity.KindHostname, "desk-phone", "seg-static"))
	ref, err := repo.CreateAsset(ctx, tenant, identity.NewAsset{
		ClassKey: assetclass.KeyUnknownHost, ClassSourceKind: identity.ClassSourceMeasured,
		DisplayName: "iphone", Status: identity.StatusPendingApproval,
		IdentityStatus: string(identity.IdentityProvisional),
		Source:         identity.Source{Kind: identity.SourceMeasured, Ref: "sensor"},
		Identifiers:    []identity.Identifier{addr, name},
		FirstSeenAt:    observedAt, LastSeenAt: observedAt,
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	for _, tt := range []struct {
		name    string
		matched []identity.Identifier
		want    string
	}{
		{"address + generic name", []identity.Identifier{name, addr}, "yield"},
		{"generic name alone", []identity.Identifier{name}, "none"},
		{"address + ordinary name (control)", []identity.Identifier{plain, addr}, "corroborate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.ProvisionalMatchModeForTest(ctx, ref, tt.matched)
			if err != nil {
				t.Fatalf("provisionalMatchMode: %v", err)
			}
			if got != tt.want {
				t.Errorf("mode = %s, want %s", got, tt.want)
			}
		})
	}
}
