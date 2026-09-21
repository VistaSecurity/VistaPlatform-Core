package identity_test

// The provisional-inventory rules of D2/D3, driven through the real
// admission path: Engine.Resolve → ObservationRepository → the enforce-mode
// engine copy that carries the admission decision.
//
// Every test here sets Config.ProvisionalInventory explicitly. The last one
// sets it FALSE and asserts the pre- answer, which is what makes the rest
// of the suite's silence meaningful: the flag is the only thing standing
// between today's behaviour and these outcomes.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

const (
	segmentB = "seg-b"
	segmentD = "seg-dhcp"
)

var advertAt = time.Date(2026, 9, 20, 14, 2, 0, 0, time.UTC)

// admissionRepo is the memory store plus the four ObservationRepository
// methods and the allowance guard.
//
// It is here rather than on memory.Repository deliberately: adding those
// methods to the shared fake would put EVERY existing engine test on the
// durable-admission path, which is exactly the behaviour change this PR is
// supposed not to make. It records what it was told so a test can assert on
// the things the engine says to the store rather than only on what it returns
// — in particular that a provisional create never asks about the allowance,
// and that a corroborating observation is told to establish.
type admissionRepo struct {
	*memory.Repository

	mode      string
	allowance bool

	seq            int
	allowanceCalls int
	finished       []finishedObservation
}

type finishedObservation struct {
	observationID string
	resolution    identity.Resolution
	decision      identity.AdmissionDecision
	establish     bool
}

func newAdmissionRepo() *admissionRepo {
	return &admissionRepo{Repository: memory.New(), mode: "enforce", allowance: true}
}

func (r *admissionRepo) AdmissionMode(context.Context, string) (string, error) {
	return r.mode, nil
}

func (r *admissionRepo) StoreObservation(context.Context, identity.Observation, identity.AdmissionDecision) (string, error) {
	r.seq++
	return "observation-" + string(rune('a'+r.seq-1)), nil
}

func (r *admissionRepo) FinishObservation(_ context.Context, _ identity.Observation, id string,
	res identity.Resolution, decision identity.AdmissionDecision, establish bool) error {
	r.finished = append(r.finished, finishedObservation{
		observationID: id, resolution: res, decision: decision, establish: establish,
	})
	return nil
}

func (r *admissionRepo) PreserveObservationDismissal(context.Context, identity.Observation, string, identity.AdmissionDecision) (bool, error) {
	return false, nil
}

func (r *admissionRepo) CheckAdmissionAllowance(context.Context, string) (bool, error) {
	r.allowanceCalls++
	return r.allowance, nil
}

func (r *admissionRepo) lastFinished(t *testing.T) finishedObservation {
	t.Helper()
	if len(r.finished) == 0 {
		t.Fatal("the engine never finished an observation")
	}
	return r.finished[len(r.finished)-1]
}

// newProvisionalEngine builds an enforce-mode engine over a fresh store, with
// segment B configured as an eligible place to create a provisional asset.
func newProvisionalEngine(t *testing.T, on bool) (*identity.Engine, *admissionRepo) {
	t.Helper()
	repo := newAdmissionRepo()
	repo.SetProvisionalScope(tenant, segmentB, memory.ProvisionalScopeAnswer{Eligible: true})
	repo.SetProvisionalScope(tenant, segmentD, memory.ProvisionalScopeAnswer{Eligible: true})
	e, err := identity.New(identity.Config{
		Repo:                 repo,
		AdmissionEnabled:     true,
		ProvisionalInventory: on,
		DynamicScopes:        map[string]bool{segmentD: true},
	})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return e, repo
}

// advert is a relayed measured observation: a sensor on another VLAN repeating
// what it heard. It can never establish anything (AssessAdmission returns
// `unverified_relayed_advertisement`), which is the whole premise of D2.
func advert(at time.Time, segment string, ids ...identity.Identifier) identity.Observation {
	o := identity.Observation{
		TenantID:    tenant,
		Identifiers: ids,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:xps16-sensor-1", Mode: identity.ModePassive},
		ObservedAt:  at,
		Confidence:  0.6,
		Admission:   identity.AdmissionEvidence{Relayed: true},
	}
	o.Network.SegmentID = segment
	return o
}

// direct is a measured observation a collector on the device's own network
// took: with a MAC it establishes, which is what lets it corroborate.
func direct(at time.Time, segment string, ids ...identity.Identifier) identity.Observation {
	o := identity.Observation{
		TenantID:    tenant,
		Identifiers: ids,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:vlan-b-sensor", Mode: identity.ModeActive},
		ObservedAt:  at,
		Confidence:  0.95,
		Admission:   identity.AdmissionEvidence{Direct: true},
	}
	o.Network.SegmentID = segment
	return o
}

func historyActions(entries []identity.HistoryEntry) []identity.HistoryAction {
	out := make([]identity.HistoryAction, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Action)
	}
	return out
}

func hasChange(entries []identity.HistoryEntry, action identity.HistoryAction, key string, want any) bool {
	for _, e := range entries {
		if e.Action == action && e.Changes[key] == want {
			return true
		}
	}
	return false
}

// ── D2: an advertisement becomes a provisional asset ───────────────────────

// TestProvisionalAdvertThenDirectCorroboratesTheSameAsset is the two-sensor,
// two-VLAN journey of end to end: the item a tenant sees the moment an
// advert is heard is the SAME item that becomes established when a sensor on
// the device's own network meets it.
func TestProvisionalAdvertThenDirectCorroboratesTheSameAsset(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)

	first := mustResolve(t, e, advert(advertAt, segmentB,
		scoped(identity.KindHostname, "printer.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.50", segmentB)))

	if first.Outcome != identity.OutcomeProvisional {
		t.Fatalf("outcome = %s, want provisional: a relayed advert placed on a configured, "+
			"unambiguous segment is an inventory item nobody can see until it is one", first.Outcome)
	}
	if first.Asset.Zero() {
		t.Fatal("no asset: a provisional outcome with no asset is an observation with a new name")
	}
	if got := repo.IdentityStatusOf(first.Asset); got != string(identity.IdentityProvisional) {
		t.Errorf("identity_status = %q, want provisional", got)
	}
	if got := len(repo.Identifiers(first.Asset)); got != 2 {
		t.Errorf("identifiers = %d, want both the name and the address: %+v",
			got, repo.Identifiers(first.Asset))
	}
	if !hasChange(repo.HistoryFor(first.Asset), identity.ActionCreated, "identity_status", string(identity.IdentityProvisional)) {
		t.Errorf("the `created` entry does not record identity_status=provisional: %+v",
			repo.HistoryFor(first.Asset))
	}
	if repo.allowanceCalls != 0 {
		t.Errorf("CheckAdmissionAllowance was called %d time(s) creating a provisional asset; "+
			"a guess must not spend a customer's paid max_assets (#1898 D1)", repo.allowanceCalls)
	}

	second := mustResolve(t, e, direct(advertAt.Add(time.Hour), segmentB,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:01"),
		scoped(identity.KindHostname, "printer.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.50", segmentB)))

	if second.Outcome != identity.OutcomeMatched {
		t.Fatalf("outcome = %s, want matched", second.Outcome)
	}
	if second.Asset.ID != first.Asset.ID {
		t.Fatalf("direct evidence landed on %s, want the provisional asset %s — a second row is "+
			"the duplicate this rule exists to prevent", second.Asset.ID, first.Asset.ID)
	}
	if repo.AssetCount() != 1 {
		t.Errorf("asset count = %d, want 1", repo.AssetCount())
	}
	if n := len(repo.Identifiers(second.Asset)); n != 3 {
		t.Errorf("identifiers = %d, want the MAC attached as well: %+v", n, repo.Identifiers(second.Asset))
	}
	if !hasChange(repo.HistoryFor(second.Asset), identity.ActionUpdated, "corroborated_provisional", true) {
		t.Errorf("no `corroborated_provisional` in history: %+v", repo.HistoryFor(second.Asset))
	}
	last := repo.lastFinished(t)
	if !last.decision.Established || !last.establish {
		t.Errorf("FinishObservation(establish=%v, established=%v); the corroborating observation is "+
			"what promotes the provisional asset, and a store told otherwise never promotes it",
			last.establish, last.decision.Established)
	}
}

// TestProvisionalDirectThenAdvertIsSupportingEvidence is the same two pieces of
// evidence in the other order.
//
// The advert adds nothing to an ESTABLISHED asset — an alias nobody checked
// must not become part of an identity somebody did — but it is still another
// sighting, so it advances last-seen and links to the asset instead of sitting
// as evidence with no home.
func TestProvisionalDirectThenAdvertIsSupportingEvidence(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)

	established := mustResolve(t, e, direct(advertAt, segmentB,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:02"),
		scoped(identity.KindHostname, "printer.local", segmentB)))
	if established.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created", established.Outcome)
	}

	nameBefore := repo.Hostname(established.Asset)
	later := advertAt.Add(2 * time.Hour)
	repeated := advert(later, segmentB,
		scoped(identity.KindHostname, "printer.local", segmentB),
		id(identity.KindFQDN, "printer.corp.example"))
	// A better-quality name the advert made up. `attach nothing` has to mean
	// the names and endpoints too, or the rule holds in name only.
	repeated.Hostname = "printer.corp.example"
	repeated.Endpoints = []identity.EndpointObservation{{Address: "192.168.1.50", Port: 631, Transport: "tcp"}}
	res := mustResolve(t, e, repeated)

	if res.Outcome != identity.OutcomeSupporting {
		t.Fatalf("outcome = %s, want supporting", res.Outcome)
	}
	if res.Asset.ID != established.Asset.ID {
		t.Fatalf("supporting evidence named %s, want %s", res.Asset.ID, established.Asset.ID)
	}
	if repo.AssetCount() != 1 {
		t.Errorf("asset count = %d, want 1 — supporting evidence creates nothing", repo.AssetCount())
	}
	for _, held := range repo.Identifiers(established.Asset) {
		if held.Kind == identity.KindFQDN {
			t.Errorf("the advert's unverified fqdn %q was attached to an ESTABLISHED asset; "+
				"an alias nobody checked must not join an identity somebody did", held.Value)
		}
	}
	if got := repo.LastSeen(established.Asset); !got.Equal(later) {
		t.Errorf("last_seen = %s, want the advert's own observation time %s", got, later)
	}
	if got := repo.Hostname(established.Asset); got != nameBefore {
		t.Errorf("hostname moved from %q to %q on an unverified advert; a name somebody repeated must "+
			"not become the name of an asset a collector met", nameBefore, got)
	}
	if got := repo.Endpoints(established.Asset); len(got) != 0 {
		t.Errorf("the advert's endpoints were written to an established asset: %+v", got)
	}
	var sawFQDN bool
	for _, unattached := range res.Unattached {
		sawFQDN = sawFQDN || unattached.Kind == identity.KindFQDN
	}
	if !sawFQDN {
		t.Errorf("the unattached fqdn is not reported: %+v — an identifier that vanishes without a "+
			"trace is how an inventory quietly becomes wrong", res.Unattached)
	}
}

// TestProvisionalRepeatedAdvertIsIdempotent: the same advert delivered twice
// must not make two items out of one.
func TestProvisionalRepeatedAdvertIsIdempotent(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	obs := advert(advertAt, segmentB,
		scoped(identity.KindHostname, "printer.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.50", segmentB))

	first := mustResolve(t, e, obs)
	second := mustResolve(t, e, obs)

	if first.Outcome != identity.OutcomeProvisional {
		t.Fatalf("first outcome = %s, want provisional", first.Outcome)
	}
	if second.Outcome != identity.OutcomeSupporting {
		t.Fatalf("second outcome = %s, want supporting: a re-delivery is the same sighting, "+
			"not a second thing", second.Outcome)
	}
	if second.Asset.ID != first.Asset.ID || repo.AssetCount() != 1 {
		t.Fatalf("second landed on %s (count %d), want the one provisional asset %s",
			second.Asset.ID, repo.AssetCount(), first.Asset.ID)
	}
}

// ── D3: hearsay yields to direct evidence ──────────────────────────────────

// TestProvisionalAddressOnlyReuseMovesTheAddress is the rule that keeps a
// recycled DHCP lease from silently merging two devices.
//
// The advert claimed `printer.local` at .50. A collector then meets a device at
// .50 that calls itself something else and has a MAC. The ADDRESS is evidence
// about the device that was met; the NAME is evidence about whatever the advert
// was describing. They are two things, so the address moves and the name stays.
func TestProvisionalAddressOnlyReuseMovesTheAddress(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)

	p := mustResolve(t, e, advert(advertAt, segmentB,
		scoped(identity.KindHostname, "printer.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.50", segmentB)))
	if p.Outcome != identity.OutcomeProvisional {
		t.Fatalf("setup outcome = %s, want provisional", p.Outcome)
	}

	res := mustResolve(t, e, direct(advertAt.Add(time.Hour), segmentB,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:03"),
		scoped(identity.KindHostname, "scanner.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.50", segmentB)))

	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created: the direct evidence agrees with the provisional asset "+
			"about NOTHING but an address, and an address is a lease", res.Outcome)
	}
	if res.Asset.ID == p.Asset.ID {
		t.Fatal("the direct evidence was folded into the provisional asset; a shared address is not a shared identity")
	}

	owners, err := repo.FindByIdentifier(context.Background(), tenant, identity.KindIPAddress, "192.168.1.50", segmentB)
	if err != nil || len(owners) != 1 {
		t.Fatalf("FindByIdentifier(.50) = %+v (err %v), want one owner", owners, err)
	}
	if owners[0].ID != res.Asset.ID {
		t.Errorf(".50 still belongs to %s, want the directly observed asset %s", owners[0].ID, res.Asset.ID)
	}
	kept := repo.Identifiers(p.Asset)
	if len(kept) != 1 || kept[0].Kind != identity.KindHostname {
		t.Errorf("the provisional asset now holds %+v, want only the advertised name", kept)
	}
	if got := repo.StatusOf(p.Asset); got == identity.StatusArchived {
		t.Errorf("the provisional asset was archived although it still holds %+v", kept)
	}
	for _, ref := range []identity.AssetRef{p.Asset, res.Asset} {
		if len(repo.HistoryFor(ref)) == 0 {
			t.Fatalf("%s has no history at all", ref.ID)
		}
		found := false
		for _, entry := range repo.HistoryFor(ref) {
			found = found || entry.Action == identity.ActionIdentifierReassigned
		}
		if !found {
			t.Errorf("%s has no `identifier_reassigned` entry (%v); one side of a move with no record "+
				"is an identifier that silently appeared or silently vanished",
				ref.ID, historyActions(repo.HistoryFor(ref)))
		}
	}
	for _, unattached := range res.Unattached {
		if unattached.Kind == identity.KindIPAddress {
			t.Errorf("the resolution still reports .50 as unattached, although it was just moved onto %s", res.Asset.ID)
		}
	}
}

// TestProvisionalEmptiedByReassignmentIsArchived is the same rule when the
// advert had nothing but an address to give.
//
// The provisional asset is left holding no identifier, which is precisely the
// asset the floor refuses to create: nothing could ever match it again. It is
// archived with a reason, not merged — nothing was combined.
func TestProvisionalEmptiedByReassignmentIsArchived(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)

	// An address-only provisional asset cannot be produced by an advert (D2
	// needs a scoped identifier and AssessAdmission would establish a direct
	// scoped address), so it is built through the store, which is how a
	// migrated or backfilled row can look.
	p, err := repo.CreateAsset(context.Background(), tenant, identity.NewAsset{
		ClassKey:        "unknown_host",
		ClassSourceKind: identity.ClassSourceMeasured,
		DisplayName:     "192.168.1.51",
		Status:          identity.StatusPendingApproval,
		IdentityStatus:  string(identity.IdentityProvisional),
		NetworkSegment:  segmentB,
		Source:          identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:xps16-sensor-1"},
		Identifiers:     []identity.Identifier{scoped(identity.KindIPAddress, "192.168.1.51", segmentB)},
		FirstSeenAt:     advertAt,
		LastSeenAt:      advertAt,
	})
	if err != nil {
		t.Fatalf("seeding the provisional asset: %v", err)
	}

	res := mustResolve(t, e, direct(advertAt.Add(time.Hour), segmentB,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:04"),
		scoped(identity.KindHostname, "scanner.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.51", segmentB)))

	if res.Outcome != identity.OutcomeCreated || res.Asset.ID == p.ID {
		t.Fatalf("outcome = %s on %s, want a new asset", res.Outcome, res.Asset.ID)
	}
	if len(repo.Identifiers(p)) != 0 {
		t.Fatalf("the provisional asset still holds %+v", repo.Identifiers(p))
	}
	if got := repo.StatusOf(p); got != identity.StatusArchived {
		t.Errorf("status = %q, want archived: an asset with no identifier can never be matched again", got)
	}
	if !hasChange(repo.HistoryFor(p), identity.ActionArchived, "reason", identity.ReasonSupersededByDirectEvidence) {
		t.Errorf("no `archived` entry with reason %q: %+v",
			identity.ReasonSupersededByDirectEvidence, repo.HistoryFor(p))
	}
}

// TestProvisionalSharedNameSecondDeviceStaysAProposal: two devices answering to
// one advertised name is a question for a human, not a combine.
func TestProvisionalSharedNameSecondDeviceStaysAProposal(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)

	p := mustResolve(t, e, advert(advertAt, segmentB,
		scoped(identity.KindHostname, "printer.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.50", segmentB)))
	if p.Outcome != identity.OutcomeProvisional {
		t.Fatalf("setup outcome = %s, want provisional", p.Outcome)
	}
	one := mustResolve(t, e, direct(advertAt.Add(time.Hour), segmentB,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:05"),
		scoped(identity.KindHostname, "printer.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.50", segmentB)))
	if one.Outcome != identity.OutcomeMatched || one.Asset.ID != p.Asset.ID {
		t.Fatalf("corroboration = %s on %s, want matched on %s", one.Outcome, one.Asset.ID, p.Asset.ID)
	}

	two := mustResolve(t, e, direct(advertAt.Add(2*time.Hour), segmentB,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:06"),
		scoped(identity.KindHostname, "printer.local", segmentB)))

	if two.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict: a second interface answering to the same name is two "+
			"devices sharing a name until a human says otherwise", two.Outcome)
	}
	if two.Proposal.ID == "" {
		t.Error("no merge proposal was opened")
	}
	if len(repo.Proposals()) != 1 {
		t.Errorf("proposals = %d, want 1", len(repo.Proposals()))
	}
}

// TestProvisionalDynamicScopeAddressNeverCombines: an address inside a DHCP
// range decides nothing, whoever holds it.
//
// A provisional asset created in a dynamic segment keeps its address, and a
// later device that happens to hold the same lease becomes its own asset rather
// than being folded into the guess. Today's lease is tomorrow's other host.
func TestProvisionalDynamicScopeAddressNeverCombines(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)

	p := mustResolve(t, e, advert(advertAt, segmentD,
		scoped(identity.KindHostname, "printer.local", segmentD),
		scoped(identity.KindIPAddress, "10.0.0.50", segmentD)))
	if p.Outcome != identity.OutcomeProvisional {
		t.Fatalf("outcome = %s, want provisional", p.Outcome)
	}

	res := mustResolve(t, e, direct(advertAt.Add(time.Hour), segmentD,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:07"),
		scoped(identity.KindHostname, "scanner.local", segmentD),
		scoped(identity.KindIPAddress, "10.0.0.50", segmentD)))

	if res.Outcome != identity.OutcomeCreated || res.Asset.ID == p.Asset.ID {
		t.Fatalf("outcome = %s on %s, want a new asset: an ip_address inside a dynamic scope must "+
			"not decide anything", res.Outcome, res.Asset.ID)
	}
	owners, err := repo.FindByIdentifier(context.Background(), tenant, identity.KindIPAddress, "10.0.0.50", segmentD)
	if err != nil || len(owners) != 1 || owners[0].ID != p.Asset.ID {
		t.Errorf("FindByIdentifier(10.0.0.50) = %+v (err %v), want it still on the provisional asset %s — "+
			"an address that never voted cannot have been reassigned by a rule that only fires on a match",
			owners, err, p.Asset.ID)
	}
}

// ── D2: the cases that must NOT create anything ────────────────────────────

func TestProvisionalRefusesWhatItCannotPlace(t *testing.T) {
	tests := []struct {
		name       string
		observed   identity.Observation
		ineligible *memory.ProvisionalScopeAnswer
		wantReason string
	}{
		{
			name: "unresolved scope",
			observed: advert(advertAt, identity.ScopeTenantDefault,
				scoped(identity.KindHostname, "printer.local", identity.ScopeTenantDefault),
				scoped(identity.KindIPAddress, "192.168.1.50", identity.ScopeTenantDefault)),
			wantReason: identity.ReasonNetworkScopeUnresolved,
		},
		{
			name: "ambiguous scope",
			observed: advert(advertAt, segmentB,
				scoped(identity.KindHostname, "printer.local", segmentB),
				scoped(identity.KindIPAddress, "192.168.1.50", segmentB)),
			ineligible: &memory.ProvisionalScopeAnswer{Reason: identity.ReasonOverlappingNetworkScope},
			wantReason: identity.ReasonOverlappingNetworkScope,
		},
		{
			name:       "name only",
			observed:   advert(advertAt, segmentB, id(identity.KindName, "Front desk printer")),
			wantReason: identity.ReasonNoDeviceOrAddressBinding,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, repo := newProvisionalEngine(t, true)
			if tt.ineligible != nil {
				repo.SetProvisionalScope(tenant, segmentB, *tt.ineligible)
			}

			res := mustResolve(t, e, tt.observed)

			if res.Outcome != identity.OutcomeUnresolved {
				t.Fatalf("outcome = %s, want unresolved", res.Outcome)
			}
			if !res.Asset.Zero() {
				t.Errorf("an asset (%s) was created for evidence that cannot be placed", res.Asset.ID)
			}
			if repo.AssetCount() != 0 {
				t.Errorf("asset count = %d, want 0", repo.AssetCount())
			}
			if res.AdmissionReason != tt.wantReason {
				t.Errorf("AdmissionReason = %q, want %q — a refusal the tenant cannot read is a "+
					"discovery that looks like it never happened", res.AdmissionReason, tt.wantReason)
			}
		})
	}
}

// TestProvisionalNeedsARepositoryThatCanAnswer: a store with no
// ProvisionalScopeChecker has not told us the segment is unambiguous, so
// nothing is created. The default direction matters — the other one invents
// assets against segments nobody vouched for.
func TestProvisionalNeedsARepositoryThatCanAnswer(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	repo.SetProvisionalScope(tenant, segmentB, memory.ProvisionalScopeAnswer{})

	res := mustResolve(t, e, advert(advertAt, segmentB,
		scoped(identity.KindHostname, "printer.local", segmentB)))

	if res.Outcome != identity.OutcomeUnresolved || res.AdmissionReason != identity.ReasonNetworkScopeUnresolved {
		t.Fatalf("outcome = %s reason = %q, want unresolved / %s",
			res.Outcome, res.AdmissionReason, identity.ReasonNetworkScopeUnresolved)
	}
	if repo.AssetCount() != 0 {
		t.Errorf("asset count = %d, want 0", repo.AssetCount())
	}
}

// ── the flag ───────────────────────────────────────────────────────────────

// TestProvisionalInventoryOffIsTodaysBehaviour is what makes this PR
// behaviour-neutral, and it is the mutation target for the flag itself: make
// Config.ProvisionalInventory ignored (always on) and this test fails.
func TestProvisionalInventoryOffIsTodaysBehaviour(t *testing.T) {
	e, repo := newProvisionalEngine(t, false)

	res := mustResolve(t, e, advert(advertAt, segmentB,
		scoped(identity.KindHostname, "printer.local", segmentB),
		scoped(identity.KindIPAddress, "192.168.1.50", segmentB)))

	if res.Outcome != identity.OutcomeUnresolved {
		t.Fatalf("outcome = %s, want unresolved: with the flag off an advert is evidence and "+
			"nothing else, exactly as it was before #1898", res.Outcome)
	}
	if !res.Asset.Zero() || repo.AssetCount() != 0 {
		t.Errorf("asset %s / count %d: the flag off must create nothing", res.Asset.ID, repo.AssetCount())
	}
	if res.AdmissionReason != "" {
		t.Errorf("AdmissionReason = %q, want empty — the reason is part of the new behaviour", res.AdmissionReason)
	}
	if len(res.Unattached) != 2 {
		t.Errorf("unattached = %+v, want both identifiers reported as they were before", res.Unattached)
	}
}

// TestProvisionalInventoryOffStillLinksNothingForOwnedEvidence pins the other
// half of the flag: the supporting-evidence rule is new too, and with the flag
// off an advert whose identifiers an asset already owns is still `unresolved`.
func TestProvisionalInventoryOffStillLinksNothingForOwnedEvidence(t *testing.T) {
	e, repo := newProvisionalEngine(t, false)

	established := mustResolve(t, e, direct(advertAt, segmentB,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:08"),
		scoped(identity.KindHostname, "printer.local", segmentB)))
	if established.Outcome != identity.OutcomeCreated {
		t.Fatalf("setup outcome = %s, want created", established.Outcome)
	}
	before := repo.LastSeen(established.Asset)

	res := mustResolve(t, e, advert(advertAt.Add(3*time.Hour), segmentB,
		scoped(identity.KindHostname, "printer.local", segmentB)))

	if res.Outcome != identity.OutcomeUnresolved {
		t.Fatalf("outcome = %s, want unresolved", res.Outcome)
	}
	if got := repo.LastSeen(established.Asset); !got.Equal(before) {
		t.Errorf("last_seen moved to %s with the flag off; supporting evidence is #1898 D3", got)
	}
}

// ── supporting evidence only from a SIGHTING ───────────────────────────────

// TestProvisionalSupportingOnlyTouchesOnASighting is the guard against the one
// producer that would otherwise keep a dead device fresh for ever.
//
// inventory-service's scoped DNS lookup (`sensor:identity-dns:<id>`, active
// mode, no endpoints) resolves hostname-to-address evidence on EVERY rescan
// cycle, without anything having gone near the device. Under the supporting
// rule its identifiers are all owned by one asset, so it would touch that
// asset's last_seen every cycle — a device unplugged months ago would never go
// stale and would never appear in the stale lens. The customer documentation
// promises the opposite in as many words.
//
// Both polarities, because a guard that refused everything would be the same
// bug pointing the other way: a real passive advert and a real active probe
// that reached the device must still move the clock.
func TestProvisionalSupportingOnlyTouchesOnASighting(t *testing.T) {
	// dnsAnswer is the shape identity_enrichment.go builds: active, no
	// endpoints, name-to-address only.
	dnsAnswer := func(at time.Time, ids ...identity.Identifier) identity.Observation {
		o := identity.Observation{
			TenantID:    tenant,
			Identifiers: ids,
			Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:identity-dns:vlan-b-sensor", Mode: identity.ModeActive},
			ObservedAt:  at,
			Confidence:  0.5,
		}
		o.Network.SegmentID = segmentB
		return o
	}

	tests := []struct {
		name      string
		build     func(at time.Time, ids ...identity.Identifier) identity.Observation
		wantTouch bool
	}{
		{
			name:      "an active DNS answer with no endpoint is context, not a sighting",
			build:     dnsAnswer,
			wantTouch: false,
		},
		{
			name: "an active probe that produced an endpoint reached the device",
			build: func(at time.Time, ids ...identity.Identifier) identity.Observation {
				o := dnsAnswer(at, ids...)
				o.Endpoints = []identity.EndpointObservation{{Address: "192.168.1.50", Port: 443, Transport: "tcp"}}
				return o
			},
			wantTouch: true,
		},
		{
			name: "a passive relayed advert is traffic the thing emitted",
			build: func(at time.Time, ids ...identity.Identifier) identity.Observation {
				return advert(at, segmentB, ids...)
			},
			wantTouch: true,
		},
	}

	// Against BOTH asset statuses: the provisional path attaches and touches
	// through applyToAsset, the established one touches directly, and the
	// sighting test has to sit in front of both.
	for _, status := range []struct {
		name  string
		setup func(t *testing.T, e *identity.Engine, repo *admissionRepo) identity.AssetRef
	}{
		{
			name: "provisional asset",
			setup: func(t *testing.T, e *identity.Engine, repo *admissionRepo) identity.AssetRef {
				t.Helper()
				res := mustResolve(t, e, advert(advertAt, segmentB,
					scoped(identity.KindHostname, "printer.local", segmentB)))
				if res.Outcome != identity.OutcomeProvisional {
					t.Fatalf("setup outcome = %s, want provisional", res.Outcome)
				}
				return res.Asset
			},
		},
		{
			name: "established asset",
			setup: func(t *testing.T, e *identity.Engine, repo *admissionRepo) identity.AssetRef {
				t.Helper()
				res := mustResolve(t, e, direct(advertAt, segmentB,
					id(identity.KindMACAddress, "02:aa:bb:cc:dd:09"),
					scoped(identity.KindHostname, "printer.local", segmentB)))
				if res.Outcome != identity.OutcomeCreated {
					t.Fatalf("setup outcome = %s, want created", res.Outcome)
				}
				repo.SetIdentityStatus(res.Asset, identity.IdentityEstablished)
				return res.Asset
			},
		},
	} {
		for _, tt := range tests {
			t.Run(status.name+"/"+tt.name, func(t *testing.T) {
				e, repo := newProvisionalEngine(t, true)
				asset := status.setup(t, e, repo)
				before := repo.LastSeen(asset)
				identifiersBefore := len(repo.Identifiers(asset))

				later := advertAt.Add(6 * time.Hour)
				res := mustResolve(t, e, tt.build(later,
					scoped(identity.KindHostname, "printer.local", segmentB),
					scoped(identity.KindIPAddress, "192.168.1.50", segmentB)))

				if res.Outcome != identity.OutcomeSupporting {
					t.Fatalf("outcome = %s, want supporting — the evidence still belongs to this asset "+
						"whether or not it moves the clock", res.Outcome)
				}
				if res.Asset.ID != asset.ID {
					t.Fatalf("supporting evidence named %s, want %s", res.Asset.ID, asset.ID)
				}
				if repo.AssetCount() != 1 {
					t.Errorf("asset count = %d, want 1", repo.AssetCount())
				}

				got := repo.LastSeen(asset)
				switch {
				case tt.wantTouch && !got.Equal(later):
					t.Errorf("last_seen = %s, want the observation's own time %s", got, later)
				case !tt.wantTouch && !got.Equal(before):
					t.Errorf("last_seen moved from %s to %s on an active observation with no endpoint; "+
						"a DNS answer says what a name resolves to, not that the device is still there — "+
						"and a device kept permanently fresh never reaches the stale lens", before, got)
				}
				if !tt.wantTouch {
					if n := len(repo.Identifiers(asset)); n != identifiersBefore {
						t.Errorf("identifiers = %d, want %d unchanged: a non-sighting writes nothing, "+
							"whatever the asset's identity status", n, identifiersBefore)
					}
				}

				entries := repo.HistoryFor(asset)
				if !hasChange(entries, identity.ActionUpdated, "supporting", true) {
					t.Errorf("no supporting history entry: %+v", historyActions(entries))
				}
				if !hasChange(entries, identity.ActionUpdated, "sighting", tt.wantTouch) {
					t.Errorf("no `updated` entry with sighting=%v; the timeline has to say why an entry "+
						"that looks like every other supporting one left the clock alone", tt.wantTouch)
				}
			})
		}
	}
}
