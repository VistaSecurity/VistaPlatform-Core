package identity_test

// 1b — "the address follows the MAC" — and 1c — no IP-only provisional
// record on a dynamic segment.
//
// 1b is driven through Engine.Resolve over the in-memory store (which
// implements IdentifierReassigner and AssetArchiver). Every negative test is
// paired with the one condition it pins, and the mutation that makes it fail
// is named on the test. Addresses are RFC 5737 and every name is invented.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

const (
	leaseScope  = "seg-lease"  // dynamic: hands addresses out by DHCP
	staticScope = "seg-static" // not dynamic
)

var (
	leaseAt   = time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	leaseMACA = id(identity.KindMACAddress, "00:00:5e:00:53:0a")
	leaseMACB = id(identity.KindMACAddress, "00:00:5e:00:53:0b")
	leaseAddr = scoped(identity.KindIPAddress, "192.0.2.7", leaseScope)
	otherAddr = scoped(identity.KindIPAddress, "192.0.2.20", leaseScope)
)

// arpSighting is what an ARP (or DHCP) decoder hands the engine: a measured,
// direct, not-relayed observation of a MAC at an address.
func arpSighting(at time.Time, ids ...identity.Identifier) identity.Observation {
	o := identity.Observation{
		TenantID:    tenant,
		Identifiers: ids,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:lease-test", Mode: identity.ModePassive},
		ObservedAt:  at,
		Confidence:  0.9,
		Admission:   identity.AdmissionEvidence{Direct: true},
	}
	o.Network.SegmentID = leaseScope
	return o
}

func newLeaseEngine(t *testing.T, cfg identity.Config) (*identity.Engine, *memory.Repository) {
	t.Helper()
	if cfg.DynamicScopes == nil {
		cfg.DynamicScopes = map[string]bool{leaseScope: true}
	}
	return newEngine(t, cfg)
}

// leaseSetup is the world every 1b test starts from: device A met at the
// lease address, device B met at another address, B then seen at A's lease.
type leaseSetup struct {
	e    *identity.Engine
	repo *memory.Repository
	a, b identity.AssetRef
}

func newLeaseSetup(t *testing.T, cfg identity.Config) leaseSetup {
	t.Helper()
	e, repo := newLeaseEngine(t, cfg)
	a := mustResolve(t, e, arpSighting(leaseAt, leaseMACA, leaseAddr))
	b := mustResolve(t, e, arpSighting(leaseAt.Add(time.Minute), leaseMACB, otherAddr))
	if a.Outcome != identity.OutcomeCreated || b.Outcome != identity.OutcomeCreated {
		t.Fatalf("setup outcomes = %s, %s, want created twice", a.Outcome, b.Outcome)
	}
	return leaseSetup{e: e, repo: repo, a: a.Asset, b: b.Asset}
}

func (s leaseSetup) ownerOf(t *testing.T, ident identity.Identifier) string {
	t.Helper()
	n, err := ident.Normalized()
	if err != nil {
		t.Fatalf("Normalized: %v", err)
	}
	refs, err := s.repo.FindByIdentifier(context.Background(), tenant, n.Kind, n.Value, n.Scope)
	if err != nil {
		t.Fatalf("FindByIdentifier: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("%s has %d owners, want 1", n.Value, len(refs))
	}
	return refs[0].ID
}

func leaseMovedEntries(entries []identity.HistoryEntry) []identity.HistoryEntry {
	var out []identity.HistoryEntry
	for _, e := range entries {
		if e.Action == identity.ActionIdentifierReassigned && e.Changes["reason"] == identity.ReasonLeaseMoved {
			out = append(out, e)
		}
	}
	return out
}

// assertNotMoved is the shape every negative test checks: the address stays
// with A, nothing is recorded as a lease move, and the address is reported as
// an identifier the engine declined to write rather than silently dropped.
func (s leaseSetup) assertNotMoved(t *testing.T, res identity.Resolution, why string) {
	t.Helper()
	if got := s.ownerOf(t, leaseAddr); got != s.a.ID {
		t.Fatalf("the lease moved to %s; want it still on %s: %s", got, s.a.ID, why)
	}
	for _, ref := range []identity.AssetRef{s.a, s.b} {
		if n := len(leaseMovedEntries(s.repo.HistoryFor(ref))); n != 0 {
			t.Errorf("%s has %d lease_moved entries, want 0", ref.ID, n)
		}
	}
	found := false
	for _, u := range res.Unattached {
		if u.Kind == identity.KindIPAddress && u.Value == leaseAddr.Value {
			found = true
		}
	}
	if !found && !res.Asset.Zero() {
		t.Errorf("unattached = %+v, want the lease address reported", res.Unattached)
	}
}

// TestLease_AddressFollowsTheMAC is the positive case of 1b: device B,
// matched by its own MAC in a direct sighting, is seen at a DHCP address still
// owned by device A. The address moves to B, both timelines say so, and the
// address's last-seen is this observation.
func TestLease_AddressFollowsTheMAC(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	at := leaseAt.Add(time.Hour)

	res := mustResolve(t, s.e, arpSighting(at, leaseMACB, leaseAddr))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.b.ID || res.DecidedBy != identity.KindMACAddress {
		t.Fatalf("resolution = %s on %s by %s, want matched on B by mac_address", res.Outcome, res.Asset.ID, res.DecidedBy)
	}
	if got := s.ownerOf(t, leaseAddr); got != s.b.ID {
		t.Fatalf("the lease is on %s, want it moved to B (%s)", got, s.b.ID)
	}
	for _, u := range res.Unattached {
		if u.Key() == leaseAddr.Key() {
			t.Errorf("the moved address is still reported unattached: %+v", res.Unattached)
		}
	}
	for _, ref := range []identity.AssetRef{s.a, s.b} {
		moved := leaseMovedEntries(s.repo.HistoryFor(ref))
		if len(moved) != 1 {
			t.Fatalf("%s has %d lease_moved identifier_reassigned entries, want 1: %+v", ref.ID, len(moved), s.repo.HistoryFor(ref))
		}
		c := moved[0].Changes
		if c["from"] != s.a.ID || c["to"] != s.b.ID || c["decided_by"] != string(identity.KindMACAddress) {
			t.Errorf("%s's entry = %+v, want from A to B decided by mac_address", ref.ID, c)
		}
	}
	seen, ok, err := s.repo.IdentifierLastSeen(context.Background(), tenant, leaseAddr)
	if err != nil || !ok || !seen.Equal(at) {
		t.Errorf("the address's last-seen = %v, %v (err %v), want %v: the move is attached like any sighting", seen, ok, err, at)
	}
	// A kept its MAC and the other address it never had; it is not archived,
	// because it is not provisional.
	if got := s.repo.StatusOf(s.a); got == identity.StatusArchived {
		t.Errorf("A was archived; only a provisional previous holder is retired")
	}
}

// TestLease_AuthoritativeInventoryMovesTheAddress pins the "or Authoritative"
// half of condition 2: a controller's client table did not meet the device on
// the wire itself, but it is the system that handed out the lease.
func TestLease_AuthoritativeInventoryMovesTheAddress(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	ctrl := arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr)
	ctrl.Admission = identity.AdmissionEvidence{Authoritative: true}

	mustResolve(t, s.e, ctrl)

	if got := s.ownerOf(t, leaseAddr); got != s.b.ID {
		t.Fatalf("the lease is on %s, want B: an authoritative inventory is condition 2's other arm", got)
	}
}

// TestLease_NotMovedWhenNotMetDirectly pins condition 2.
//
// Mutation checks: drop `!obs.Admission.Relayed` → "relayed" fails; replace
// metDirectly with `true` → all three fail; drop the SourceMeasured check →
// "imported authoritative record" fails.
func TestLease_NotMovedWhenNotMetDirectly(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*identity.Observation)
	}{
		{"relayed", func(o *identity.Observation) {
			o.Admission = identity.AdmissionEvidence{Direct: true, Relayed: true}
		}},
		{"traffic, not the device", func(o *identity.Observation) {
			o.Admission = identity.AdmissionEvidence{}
		}},
		{"imported authoritative record", func(o *identity.Observation) {
			o.Source = identity.Source{Kind: identity.SourceImported, Ref: "cmdb:lease-test"}
			o.Admission = identity.AdmissionEvidence{Authoritative: true}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newLeaseSetup(t, identity.Config{})
			o := arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr)
			tt.mutate(&o)
			res := mustResolve(t, s.e, o)
			if res.Asset.ID != s.b.ID {
				t.Fatalf("setup: resolution on %q, want the MAC to have matched B", res.Asset.ID)
			}
			s.assertNotMoved(t, res, "who holds a lease is a fact about the wire; only a direct measurement "+
				"or the authority that issued it may say")
		})
	}
}

// TestLease_NotMovedInAStaticScope pins condition 3. The class's precedence
// here leaves ip_address out, so the address never votes and reaches the
// match's unattached list even though its scope is static — the only way a
// static address gets that far.
//
// Mutation check: drop the dynamic-scope test in leaseMoves → the address moves
// and this fails.
func TestLease_NotMovedInAStaticScope(t *testing.T) {
	macOnly := func(context.Context, string, string) ([]identity.Kind, bool) {
		return []identity.Kind{identity.KindMACAddress}, true
	}
	e, repo := newLeaseEngine(t, identity.Config{Precedence: macOnly})
	static := scoped(identity.KindIPAddress, "198.51.100.7", staticScope)
	a := mustResolve(t, e, arpSighting(leaseAt, leaseMACA, static))
	b := mustResolve(t, e, arpSighting(leaseAt.Add(time.Minute), leaseMACB, otherAddr))

	res := mustResolve(t, e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, static))

	if res.Asset.ID != b.Asset.ID {
		t.Fatalf("setup: resolution on %q, want B", res.Asset.ID)
	}
	refs, err := repo.FindByIdentifier(context.Background(), tenant, identity.KindIPAddress, static.Value, staticScope)
	if err != nil || len(refs) != 1 || refs[0].ID != a.Asset.ID {
		t.Fatalf("static address owners = %+v (err %v), want still A (%s): only a DHCP address is a lease", refs, err, a.Asset.ID)
	}
	if n := len(leaseMovedEntries(repo.History())); n != 0 {
		t.Errorf("%d lease_moved entries, want 0", n)
	}
}

// TestLease_NotMovedByAnOlderObservation pins condition 4: A was seen at the
// address AFTER the sighting of B was made; B's sighting arrives late.
//
// Mutation check: drop the ObservedAt comparison → the address moves to B and
// this fails.
func TestLease_NotMovedByAnOlderObservation(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	mustResolve(t, s.e, arpSighting(leaseAt.Add(2*time.Hour), leaseMACA, leaseAddr))

	res := mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))

	if res.Asset.ID != s.b.ID {
		t.Fatalf("setup: resolution on %q, want B", res.Asset.ID)
	}
	s.assertNotMoved(t, res, "A held the address more recently than this observation says B did")
}

// TestLease_NotMovedAtTheSameInstant pins that condition 4 is STRICTLY newer:
// two devices claiming one address at one instant is not evidence either of
// them holds it now.
//
// Mutation check: `!obs.ObservedAt.After(lastSeen)` → `obs.ObservedAt.Before(lastSeen)`
// → the address moves and this fails.
func TestLease_NotMovedAtTheSameInstant(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), leaseMACA, leaseAddr))

	res := mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))

	s.assertNotMoved(t, res, "a tie is not newer")
}

// TestLease_LateArrivalNeverMovesTheAddressBack is replay safety: B takes the
// lease at T+1h, and THEN a sighting of A at the address made at T+30m arrives
// (a batch delivered late, or a retried one). A's MAC matches A, the address
// is B's, and the late sighting must not move it back.
//
// Mutation check: drop the ObservedAt comparison → the late sighting moves the
// address back to A and this fails.
func TestLease_LateArrivalNeverMovesTheAddressBack(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))
	if got := s.ownerOf(t, leaseAddr); got != s.b.ID {
		t.Fatalf("setup: the lease did not move to B (owner %s)", got)
	}

	late := mustResolve(t, s.e, arpSighting(leaseAt.Add(30*time.Minute), leaseMACA, leaseAddr))

	if late.Asset.ID != s.a.ID {
		t.Fatalf("setup: the late sighting resolved to %q, want A by its MAC", late.Asset.ID)
	}
	if got := s.ownerOf(t, leaseAddr); got != s.b.ID {
		t.Fatalf("a late-arriving sighting moved the lease back to %s; B was seen with it more recently", got)
	}
	if n := len(leaseMovedEntries(s.repo.HistoryFor(s.a))); n != 1 {
		t.Errorf("A has %d lease_moved entries, want exactly the original 1", n)
	}

	// And a GENUINELY newer sighting of A does take it back: the rule is about
	// time, not about who had it first.
	mustResolve(t, s.e, arpSighting(leaseAt.Add(3*time.Hour), leaseMACA, leaseAddr))
	if got := s.ownerOf(t, leaseAddr); got != s.a.ID {
		t.Errorf("A met at the address after B was is not holding it (owner %s)", got)
	}
}

// TestLease_NotMovedByANameMatch pins condition 1's device-binding half: a
// match decided by a hostname in a dynamic scope must not move an address,
// although hostname ranks above ip_address in the default precedence.
//
// Mutation check: drop the deviceBindingKinds test in decidedAboveAddress →
// the hostname match moves the address and this fails.
func TestLease_NotMovedByANameMatch(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	kiosk := scoped(identity.KindHostname, "kiosk-b", leaseScope)
	if err := s.repo.AttachIdentifiers(context.Background(), s.b, []identity.Identifier{kiosk}); err != nil {
		t.Fatalf("AttachIdentifiers: %v", err)
	}

	res := mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), kiosk, leaseAddr))

	if res.Asset.ID != s.b.ID || res.DecidedBy != identity.KindHostname {
		t.Fatalf("setup: resolution on %q by %s, want B by hostname", res.Asset.ID, res.DecidedBy)
	}
	s.assertNotMoved(t, res, "a DHCP client's name is as much a choice as its lease; only a device binding moves one")
}

// TestLease_NotMovedWhenTheTenantRanksAddressesHigher pins condition 1's rank
// half: a precedence override that puts ip_address above mac_address says the
// address is the stronger evidence for this class, and a MAC match then does
// not outrank it.
//
// Mutation check: drop the rank comparison in decidedAboveAddress → the address
// moves and this fails.
func TestLease_NotMovedWhenTheTenantRanksAddressesHigher(t *testing.T) {
	addressFirst := func(context.Context, string, string) ([]identity.Kind, bool) {
		return []identity.Kind{identity.KindIPAddress, identity.KindMACAddress}, true
	}
	s := newLeaseSetup(t, identity.Config{Precedence: addressFirst})

	res := mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))

	if res.Asset.ID != s.b.ID || res.DecidedBy != identity.KindMACAddress {
		t.Fatalf("setup: resolution on %q by %s, want B by mac_address", res.Asset.ID, res.DecidedBy)
	}
	s.assertNotMoved(t, res, "the tenant ranked ip_address above the kind that decided")
}

// noReassign is a store without the IdentifierReassigner capability: the
// embedded interface exposes only the Repository methods.
type noReassign struct{ identity.Repository }

// TestLease_NotMovedWithoutAReassigner pins condition 5.
//
// Mutation check: drop the IdentifierReassigner check in leaseMoves → the
// write half refuses and Resolve fails.
func TestLease_NotMovedWithoutAReassigner(t *testing.T) {
	repo := memory.New()
	e, err := identity.New(identity.Config{Repo: noReassign{repo}, DynamicScopes: map[string]bool{leaseScope: true}})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	a := mustResolve(t, e, arpSighting(leaseAt, leaseMACA, leaseAddr))
	mustResolve(t, e, arpSighting(leaseAt.Add(time.Minute), leaseMACB, otherAddr))

	res := mustResolve(t, e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))

	s := leaseSetup{e: e, repo: repo, a: a.Asset, b: res.Asset}
	s.assertNotMoved(t, res, "a store that cannot move an identifier atomically must not have one detached and re-attached")
}

// TestLease_NotMovedFromADeclaredHolder: an address a person put on a record
// is not a sensor's to take (guard rail §A.5, owner decision D4). Three ways a
// record is declared, one sub-test each.
//
// Mutation checks, one per arm of holderDeclaredAddress: drop the
// operator_confirmed arm → "operator-confirmed identity" fails; drop the
// declaration_id arm → "declared record" fails; drop the declared-identifier
// arm → "declared address" fails.
func TestLease_NotMovedFromADeclaredHolder(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, repo *memory.Repository) identity.AssetRef
	}{
		{"declared address", func(t *testing.T, repo *memory.Repository) identity.AssetRef {
			addr := leaseAddr
			addr.Source = identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}
			addr.SeenAt = leaseAt
			return createHolder(t, repo, "", addr)
		}},
		{"declared record", func(t *testing.T, repo *memory.Repository) identity.AssetRef {
			// A serial of its own, so the holder is a device and ONLY the
			// declaration_id arm stands between it and the move.
			return createHolder(t, repo, "",
				scoped(identity.KindDeclarationID, "decl-lease-1", tenant),
				measuredAt(id(identity.KindSerialNumber, "SN-DECLARED-1"), leaseAt),
				measuredAt(leaseAddr, leaseAt))
		}},
		{"operator-confirmed identity", func(t *testing.T, repo *memory.Repository) identity.AssetRef {
			return createHolder(t, repo, string(identity.IdentityOperatorConfirmed), measuredAt(leaseAddr, leaseAt))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, repo := newLeaseEngine(t, identity.Config{})
			a := tt.setup(t, repo)
			b := mustResolve(t, e, arpSighting(leaseAt.Add(time.Minute), leaseMACB, otherAddr))

			res := mustResolve(t, e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))

			s := leaseSetup{e: e, repo: repo, a: a, b: b.Asset}
			s.assertNotMoved(t, res, "the previous holder is a record a person made about this address")
		})
	}
}

// TestLease_VIPHolderKeepsItsAddressAcrossFailover is the floating-VIP case on
// a DHCP segment. A service record holds the VIP by NAME and address — no
// device binding of its own. Node A then announces the VIP by ARP ("VIP is-at
// A's MAC"); in a dynamic scope the address cannot vote, so the frame is a
// match on node A by MAC. The frame alone cannot tell a lease reassignment
// from a VIP, so the holder decides: a record with a name and no device
// binding is not a device that lost a lease, and keeps its address. At
// failover node B announces it, and it still does not move.
//
// Mutation check: make holderLostALease return true → the VIP moves to node A
// and this fails.
func TestLease_VIPHolderKeepsItsAddressAcrossFailover(t *testing.T) {
	e, repo := newLeaseEngine(t, identity.Config{})
	vipAddr := scoped(identity.KindIPAddress, "192.0.2.230", leaseScope)
	vip := createHolder(t, repo, "",
		measuredAt(scoped(identity.KindHostname, "ingress-vip", leaseScope), leaseAt),
		measuredAt(vipAddr, leaseAt))
	nodeA := mustResolve(t, e, arpSighting(leaseAt, leaseMACA, scoped(identity.KindIPAddress, "192.0.2.21", leaseScope)))
	nodeB := mustResolve(t, e, arpSighting(leaseAt, leaseMACB, scoped(identity.KindIPAddress, "192.0.2.22", leaseScope)))
	historyBefore := len(repo.HistoryFor(vip))

	for i, node := range []struct {
		name string
		mac  identity.Identifier
		ref  identity.AssetRef
	}{{"node A", leaseMACA, nodeA.Asset}, {"node B (failover)", leaseMACB, nodeB.Asset}} {
		res := mustResolve(t, e, arpSighting(leaseAt.Add(time.Duration(i+1)*time.Hour), node.mac, vipAddr))
		if res.Asset.ID != node.ref.ID {
			t.Fatalf("%s: setup: resolution on %q, want the node by its MAC", node.name, res.Asset.ID)
		}
		s := leaseSetup{repo: repo}
		if got := s.ownerOf(t, vipAddr); got != vip.ID {
			t.Fatalf("%s: the VIP moved to %s; a record with a name and no device binding of its own is a "+
				"service, and its address is not a lease", node.name, got)
		}
	}
	if n := len(repo.HistoryFor(vip)); n != historyBefore {
		t.Errorf("the VIP record gained %d history entries; announcements of its address must write nothing on it here",
			n-historyBefore)
	}
	if n := len(leaseMovedEntries(repo.History())); n != 0 {
		t.Errorf("%d lease_moved entries, want 0", n)
	}
}

// TestLease_NotMovedFromAnAnnouncedHolder: a holder the floating-address rule
// has already recorded this address as announced for is a VIP, whatever it
// carries — here nothing but the address, which would otherwise move. This
// is the segment that was static when the VIP was first seen (the floating
// rule ran and recorded a hosted_on edge) and was later marked DHCP.
//
// Mutation check: drop the AddressAnnounced check in leaseMoves → the address
// moves and this fails.
func TestLease_NotMovedFromAnAnnouncedHolder(t *testing.T) {
	e, repo := newLeaseEngine(t, identity.Config{})
	vipAddr := scoped(identity.KindIPAddress, "192.0.2.231", leaseScope)
	vip := createHolder(t, repo, "", measuredAt(vipAddr, leaseAt))
	node := mustResolve(t, e, arpSighting(leaseAt, leaseMACA, scoped(identity.KindIPAddress, "192.0.2.21", leaseScope)))
	n, err := vipAddr.Normalized()
	if err != nil {
		t.Fatalf("Normalized: %v", err)
	}
	if err := repo.RecordAnnouncement(context.Background(), node.Asset, vip, identity.Announcement{
		MACs: []string{leaseMACA.Value}, Addresses: []string{n.Value},
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:lease-test"}, At: leaseAt,
	}); err != nil {
		t.Fatalf("RecordAnnouncement: %v", err)
	}

	res := mustResolve(t, e, arpSighting(leaseAt.Add(time.Hour), leaseMACA, vipAddr))

	if res.Asset.ID != node.Asset.ID {
		t.Fatalf("setup: resolution on %q, want the node", res.Asset.ID)
	}
	s := leaseSetup{repo: repo}
	if got := s.ownerOf(t, vipAddr); got != vip.ID {
		t.Fatalf("the announced VIP moved to %s; an address with floating-address history is not a lease", got)
	}
	if n := len(leaseMovedEntries(repo.History())); n != 0 {
		t.Errorf("%d lease_moved entries, want 0", n)
	}
}

// TestLease_NotMovedFromTwoHolders: a store that says two assets hold the
// address has lost its invariant; moving "it" would pick one of them.
//
// Mutation check: `len(refs) != 1` → `len(refs) == 0` → the engine asks the
// store to move a value from an owner it cannot confirm, and this fails.
func TestLease_NotMovedFromTwoHolders(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	extra := createHolder(t, s.repo, "", measuredAt(scoped(identity.KindSerialNumber, "SN-EXTRA", ""), leaseAt))
	n, err := leaseAddr.Normalized()
	if err != nil {
		t.Fatalf("Normalized: %v", err)
	}
	s.repo.Corrupt(tenant, n, extra)

	res, err := s.e.Resolve(context.Background(), arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Asset.ID != s.b.ID {
		t.Fatalf("setup: resolution on %q, want B", res.Asset.ID)
	}
	refs, err := s.repo.FindByIdentifier(context.Background(), tenant, n.Kind, n.Value, n.Scope)
	if err != nil {
		t.Fatalf("FindByIdentifier: %v", err)
	}
	for _, r := range refs {
		if r.ID == s.b.ID {
			t.Fatalf("an address two assets claim was moved to B")
		}
	}
	if n := len(leaseMovedEntries(s.repo.History())); n != 0 {
		t.Errorf("%d lease_moved entries, want 0", n)
	}
}

// TestLease_EmptiedProvisionalHolderIsArchived: a provisional record whose
// only identifier was the lease is retired when the lease moves — it can never
// be recognised again. An ESTABLISHED record emptied the same way is left for
// a person: retiring something a collector met is not this rule's decision.
//
// Mutation check: drop the provisional test in retireEmptiedLeaseHolders →
// "established" fails; drop the archive call → "provisional" fails.
func TestLease_EmptiedProvisionalHolderIsArchived(t *testing.T) {
	for _, tt := range []struct {
		status       identity.IdentityStatus
		wantArchived bool
	}{
		{identity.IdentityProvisional, true},
		{identity.IdentityEstablished, false},
	} {
		t.Run(string(tt.status), func(t *testing.T) {
			e, repo := newLeaseEngine(t, identity.Config{})
			a := createHolder(t, repo, string(tt.status), measuredAt(leaseAddr, leaseAt))
			mustResolve(t, e, arpSighting(leaseAt.Add(time.Minute), leaseMACB, otherAddr))

			res := mustResolve(t, e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))

			s := leaseSetup{repo: repo}
			if got := s.ownerOf(t, leaseAddr); got != res.Asset.ID {
				t.Fatalf("the lease is on %s, want it moved to %s", got, res.Asset.ID)
			}
			archived := repo.StatusOf(a) == identity.StatusArchived
			if archived != tt.wantArchived {
				t.Fatalf("%s holder archived = %v, want %v", tt.status, archived, tt.wantArchived)
			}
			if tt.wantArchived && !hasChange(repo.HistoryFor(a), identity.ActionArchived, "reason", identity.ReasonSupersededByDirectEvidence) {
				t.Errorf("no archived entry on the emptied provisional record: %+v", repo.HistoryFor(a))
			}
		})
	}
}

func measuredAt(ident identity.Identifier, at time.Time) identity.Identifier {
	ident.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:lease-test"}
	ident.SeenAt = at
	return ident
}

// createHolder writes a previous holder straight into the store, for the
// shapes the engine would not create itself (a declared record, an IP-only
// provisional record on a dynamic segment after 1c).
func createHolder(t *testing.T, repo *memory.Repository, identityStatus string, ids ...identity.Identifier) identity.AssetRef {
	t.Helper()
	normalized := make([]identity.Identifier, 0, len(ids))
	for _, raw := range ids {
		n, err := raw.Normalized()
		if err != nil {
			t.Fatalf("Normalized(%s): %v", raw.Value, err)
		}
		n.Source, n.SeenAt = raw.Source, raw.SeenAt
		normalized = append(normalized, n)
	}
	ref, err := repo.CreateAsset(context.Background(), tenant, identity.NewAsset{
		ClassKey:        "unknown_host",
		ClassSourceKind: identity.ClassSourceMeasured,
		DisplayName:     "previous holder",
		Status:          identity.StatusPendingApproval,
		IdentityStatus:  identityStatus,
		NetworkSegment:  leaseScope,
		Source:          identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:lease-test"},
		Identifiers:     normalized,
		FirstSeenAt:     leaseAt,
		LastSeenAt:      leaseAt,
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	return ref
}

// ── 1c: no IP-only provisional record on a dynamic segment ─────────────────

// TestProvisional_DynamicSegmentRefusesAnAddressAlone is 1c. On a DHCP
// segment, an unverified sighting carrying only an address creates nothing:
// the reason is dynamic_address_without_device_binding. The same evidence with
// a name, or with a device-binding identifier, is still a provisional record;
// and an address alone on a STATIC segment still is too.
//
// A sighting whose only name was synthetic (a UUID-form service instance, an
// IP-encoded label) reaches the engine as exactly the "address only" row:
// since D1 intake drops such a name as an identifier
// (hostnamequality.IsIdentityName) and records it as the `synthetic_names`
// attribute, which the engine never reads as identity.
//
// Mutation checks: drop the 1c guard → the two refusals create provisional
// records; drop `!carriesName(ids)` → "with a name" is refused; drop
// `!carriesDeviceBinding(ids)` → "with a MAC" is refused; make the guard ignore
// the segment's posture → "static segment" is refused.
func TestProvisional_DynamicSegmentRefusesAnAddressAlone(t *testing.T) {
	const staticSeg = segmentB
	syntheticOnly := func(at time.Time, segment string, ids ...identity.Identifier) identity.Observation {
		o := advert(at, segment, ids...)
		o.Attributes = map[string]any{"synthetic_names": []string{"0d6f8a3e-1c2b-4f5a-9e7d-2b3c4d5e6f70.local"}}
		return o
	}
	tests := []struct {
		name        string
		observed    identity.Observation
		wantOutcome identity.Outcome
		wantReason  string
	}{
		{
			name:        "relayed advert, address only",
			observed:    advert(advertAt, segmentD, scoped(identity.KindIPAddress, "10.0.0.61", segmentD)),
			wantOutcome: identity.OutcomeUnresolved, wantReason: identity.ReasonDynamicAddressWithoutDeviceBinding,
		},
		{
			name:        "traffic sighting, address only",
			observed:    flow(advertAt, segmentD, scoped(identity.KindIPAddress, "10.0.0.62", segmentD)),
			wantOutcome: identity.OutcomeUnresolved, wantReason: identity.ReasonDynamicAddressWithoutDeviceBinding,
		},
		{
			name:        "only name was synthetic",
			observed:    syntheticOnly(advertAt, segmentD, scoped(identity.KindIPAddress, "10.0.0.63", segmentD)),
			wantOutcome: identity.OutcomeUnresolved, wantReason: identity.ReasonDynamicAddressWithoutDeviceBinding,
		},
		{
			name: "with a name",
			observed: advert(advertAt, segmentD,
				scoped(identity.KindHostname, "hall-speaker.local", segmentD),
				scoped(identity.KindIPAddress, "10.0.0.64", segmentD)),
			wantOutcome: identity.OutcomeProvisional,
		},
		{
			name: "with a MAC",
			observed: advert(advertAt, segmentD,
				id(identity.KindMACAddress, "00:00:5e:00:53:65"),
				scoped(identity.KindIPAddress, "10.0.0.65", segmentD)),
			wantOutcome: identity.OutcomeProvisional,
		},
		{
			name:        "static segment, address only",
			observed:    advert(advertAt, staticSeg, scoped(identity.KindIPAddress, "198.51.100.66", staticSeg)),
			wantOutcome: identity.OutcomeProvisional,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, repo := newProvisionalEngine(t, true)

			res := mustResolve(t, e, tt.observed)

			if res.Outcome != tt.wantOutcome {
				t.Fatalf("outcome = %s (reason %q), want %s", res.Outcome, res.AdmissionReason, tt.wantOutcome)
			}
			if tt.wantOutcome == identity.OutcomeProvisional {
				if res.Asset.Zero() || repo.IdentityStatusOf(res.Asset) != string(identity.IdentityProvisional) {
					t.Errorf("asset %q is not a provisional record", res.Asset.ID)
				}
				return
			}
			if res.AdmissionReason != tt.wantReason {
				t.Errorf("reason = %q, want %q", res.AdmissionReason, tt.wantReason)
			}
			if !res.Asset.Zero() || repo.AssetCount() != 0 {
				t.Errorf("asset %q, %d assets in the store; want none created", res.Asset.ID, repo.AssetCount())
			}
			if len(res.Unattached) != len(tt.observed.Identifiers) {
				t.Errorf("unattached = %+v, want the evidence reported, not dropped", res.Unattached)
			}
		})
	}
}
