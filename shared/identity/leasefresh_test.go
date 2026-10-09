package identity_test

// The lease-fresh address (leasefresh.go, ADR-0002 D3 erratum): a probe of an
// address the platform recently confirmed a device at, by that device's MAC,
// attaches to the device instead of waiting in Observations as "Matches an
// asset".
//
// Driven through Engine.Resolve over the in-memory store, from the lease
// tests' world (lease_test.go): device A met by ARP at the lease address, which
// is what confirms it there. Every negative test pins one condition and names
// the mutation that makes it fail. Addresses are RFC 5737; names are invented.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// probe is an active L3 probe of an address — an SSH, TLS or QUIC scan — as a
// sensor reports it: measured, direct, not relayed, carrying the address, the
// socket that answered and whatever the service said about itself, never a
// MAC. The endpoint is what makes an active probe a sighting (isSighting).
func probe(at time.Time, ids ...identity.Identifier) identity.Observation {
	o := identity.Observation{
		TenantID:    tenant,
		Identifiers: ids,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:probe", Mode: identity.ModeActive},
		ObservedAt:  at,
		Confidence:  0.9,
		Admission:   identity.AdmissionEvidence{Direct: true},
	}
	for _, i := range ids {
		if i.Kind == identity.KindIPAddress {
			o.Endpoints = []identity.EndpointObservation{{Address: i.Value, Port: 22, Transport: "tcp", Protocol: "SSH"}}
			break
		}
	}
	o.Network.SegmentID = leaseScope
	return o
}

func deviceConfirmedAt(t *testing.T, s leaseSetup, ref identity.AssetRef, addr identity.Identifier) time.Time {
	t.Helper()
	n, err := addr.Normalized()
	if err != nil {
		t.Fatalf("Normalized: %v", err)
	}
	for _, held := range s.repo.Identifiers(ref) {
		if held.Key() == n.Key() {
			return held.DeviceConfirmedAt
		}
	}
	t.Fatalf("%s does not hold %s", ref.ID, n.Value)
	return time.Time{}
}

func hasLeaseFreshEntry(entries []identity.HistoryEntry) bool {
	for _, e := range entries {
		if v, ok := e.Changes["lease_fresh"].(bool); ok && v {
			return true
		}
	}
	return false
}

// TestLeaseFresh_CreationByMACConfirmsTheDevice: the first sighting — a MAC at
// an address — is as good a confirmation as any later one.
// Mutation: drop the stampDeviceConfirmation call in resolveCreate → zero.
func TestLeaseFresh_CreationByMACConfirmsTheDevice(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	if got := deviceConfirmedAt(t, s, s.a, leaseAddr); !got.Equal(leaseAt) {
		t.Fatalf("A's address was device-confirmed at %v, want the creating ARP sighting at %v", got, leaseAt)
	}
}

// TestLeaseFresh_ProbeOfAConfirmedDeviceMatches is the positive control and
// the bug this fixes: an hour after the sensor saw A's MAC at the address, a
// probe of the address alone is A — matched, decided by the address, with the
// timeline saying why that was allowed inside a DHCP scope.
// Mutation: make addressDecides return !dynamicAddress alone → unresolved.
func TestLeaseFresh_ProbeOfAConfirmedDeviceMatches(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	at := leaseAt.Add(time.Hour)

	res := mustResolve(t, s.e, probe(at, leaseAddr))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.a.ID || res.DecidedBy != identity.KindIPAddress {
		t.Fatalf("resolution = %s on %q by %s, want matched on A by ip_address", res.Outcome, res.Asset.ID, res.DecidedBy)
	}
	if !hasLeaseFreshEntry(s.repo.HistoryFor(s.a)) {
		t.Error("A's timeline has no entry saying the match was decided by a lease-fresh address")
	}
	sums, err := s.repo.LoadSummaries(context.Background(), tenant, []string{s.a.ID})
	if err != nil || len(sums) != 1 {
		t.Fatalf("LoadSummaries: %v (%d)", err, len(sums))
	}
	if !sums[0].LastSeenAt.Equal(at) {
		t.Errorf("A's last-seen = %v, want the probe's time %v: a lease-fresh match is a real sighting", sums[0].LastSeenAt, at)
	}
	// A probe decided by the address confirms nothing about the device: the
	// confirmation clock stays where the MAC sighting put it.
	if got := deviceConfirmedAt(t, s, s.a, leaseAddr); !got.Equal(leaseAt) {
		t.Errorf("the address-decided probe moved the device confirmation to %v; want it left at %v", got, leaseAt)
	}
}

// TestLeaseFresh_StaleConfirmationStillDoesNotDecide pins condition 2: past the
// window the address is a lease again, and the probe is held exactly as before
// — single owner, address-only link, no asset.
// Mutation: drop the window comparison in ownerLeaseFreshAt → matched.
func TestLeaseFresh_StaleConfirmationStillDoesNotDecide(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})

	res := mustResolve(t, s.e, probe(leaseAt.Add(identity.DefaultLeaseWindow+time.Second), leaseAddr))
	if res.Outcome != identity.OutcomeUnresolved || res.Asset.ID != "" {
		t.Fatalf("a probe a second past the window resolved %s on %q, want unresolved with no asset", res.Outcome, res.Asset.ID)
	}

	res = mustResolve(t, s.e, probe(leaseAt.Add(identity.DefaultLeaseWindow), leaseAddr))
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.a.ID {
		t.Fatalf("a probe exactly at the window resolved %s on %q, want matched on A", res.Outcome, res.Asset.ID)
	}
}

// TestLeaseFresh_WindowIsConfigurableAndNegativeTurnsItOff: Config.LeaseWindow
// is the window; a negative one is the kill-switch.
func TestLeaseFresh_WindowIsConfigurableAndNegativeTurnsItOff(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{LeaseWindow: time.Hour})
	if res := mustResolve(t, s.e, probe(leaseAt.Add(2*time.Hour), leaseAddr)); res.Outcome == identity.OutcomeMatched {
		t.Fatalf("a one-hour window matched a probe two hours on: %+v", res)
	}
	if res := mustResolve(t, s.e, probe(leaseAt.Add(30*time.Minute), leaseAddr)); res.Outcome != identity.OutcomeMatched {
		t.Fatalf("a one-hour window did not match a probe thirty minutes on: %s", res.Outcome)
	}

	off := newLeaseSetup(t, identity.Config{LeaseWindow: -1})
	if res := mustResolve(t, off.e, probe(leaseAt.Add(time.Minute), leaseAddr)); res.Outcome == identity.OutcomeMatched {
		t.Fatalf("with the rule off a probe a minute on still matched: %+v", res)
	}
}

// TestLeaseFresh_ConfirmationCannotDecideThePast pins the lower bound of
// condition 2: a later confirmation cannot decide an earlier sighting. That
// would join historical DHCP evidence with knowledge unavailable at the time.
func TestLeaseFresh_ConfirmationCannotDecideThePast(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	if res := mustResolve(t, s.e, probe(leaseAt.Add(-time.Hour), leaseAddr)); res.Outcome == identity.OutcomeMatched {
		t.Fatalf("a probe made an hour before the confirmation matched despite future-only evidence: %+v", res)
	}
}

// TestLeaseFresh_ANameMatchDoesNotConfirmTheDevice pins condition 1: only a
// match an observed device binding decided advances the confirmation. A direct
// sighting of A's hostname at the address matches A by name — and leaves the
// clock where the MAC put it, so a probe past the window of THAT is held.
// Mutation: drop deviceBindingKinds[decidedBy] from deviceDecided → the name
// sighting refreshes the clock and the late probe matches.
func TestLeaseFresh_ANameMatchDoesNotConfirmTheDevice(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	name := scoped(identity.KindHostname, "kiosk-a", leaseScope)
	if _, err := s.repo.AttachIdentifiers(context.Background(), s.a, []identity.Identifier{name}); err != nil {
		t.Fatalf("AttachIdentifiers: %v", err)
	}

	byName := mustResolve(t, s.e, probe(leaseAt.Add(20*time.Hour), name, leaseAddr))
	if byName.Outcome != identity.OutcomeMatched || byName.Asset.ID != s.a.ID || byName.DecidedBy != identity.KindHostname {
		t.Fatalf("setup: %s on %q by %s, want A by hostname", byName.Outcome, byName.Asset.ID, byName.DecidedBy)
	}
	if got := deviceConfirmedAt(t, s, s.a, leaseAddr); !got.Equal(leaseAt) {
		t.Fatalf("a name-decided match moved the device confirmation to %v; want it left at %v", got, leaseAt)
	}
	if res := mustResolve(t, s.e, probe(leaseAt.Add(identity.DefaultLeaseWindow+time.Hour), leaseAddr)); res.Outcome == identity.OutcomeMatched {
		t.Fatalf("a probe past the window of the MAC confirmation matched on the strength of a name sighting: %+v", res)
	}
}

// TestLeaseFresh_ReconfirmationAdvancesTheClock: the sensor seeing A's MAC at
// the address again moves the confirmation forward, which is what keeps a live
// device's address deciding indefinitely.
// Mutation: drop stampDeviceConfirmation from the matched branch → the late
// probe is held.
func TestLeaseFresh_ReconfirmationAdvancesTheClock(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	again := leaseAt.Add(20 * time.Hour)
	if res := mustResolve(t, s.e, arpSighting(again, leaseMACA, leaseAddr)); res.Outcome != identity.OutcomeMatched || res.DecidedBy != identity.KindMACAddress {
		t.Fatalf("setup: %s by %s, want matched by mac_address", res.Outcome, res.DecidedBy)
	}
	if got := deviceConfirmedAt(t, s, s.a, leaseAddr); !got.Equal(again) {
		t.Fatalf("device confirmation = %v, want advanced to %v", got, again)
	}
	if res := mustResolve(t, s.e, probe(leaseAt.Add(30*time.Hour), leaseAddr)); res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.a.ID {
		t.Fatalf("a probe ten hours after the re-confirmation resolved %s on %q, want matched on A", res.Outcome, res.Asset.ID)
	}
}

// TestLeaseFresh_OwnerWithoutADeviceBindingNeverQualifies pins condition 4: a
// record that holds nothing but an address — a service or VIP record — is not
// something a device was confirmed at, whatever its row says.
// Mutation: drop the `bound` check in ownerLeaseFreshAt → matched.
func TestLeaseFresh_OwnerWithoutADeviceBindingNeverQualifies(t *testing.T) {
	e, repo := newLeaseEngine(t, identity.Config{})
	held := scoped(identity.KindIPAddress, "192.0.2.30", leaseScope)
	held.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:lease-test"}
	held.SeenAt, held.DeviceConfirmedAt = leaseAt, leaseAt
	vip, err := repo.CreateAsset(context.Background(), tenant, identity.NewAsset{
		ClassKey: "server", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: "vip",
		Status: identity.StatusMonitoring, Source: held.Source,
		Identifiers: []identity.Identifier{held}, FirstSeenAt: leaseAt, LastSeenAt: leaseAt,
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	res := mustResolve(t, e, probe(leaseAt.Add(time.Hour), held))
	if res.Outcome == identity.OutcomeMatched && res.Asset.ID == vip.ID {
		t.Fatalf("an address-only record was treated as a confirmed device: %+v", res)
	}
}

// TestLeaseFresh_HearsayDoesNotUseTheLease pins condition 5: an advertisement
// or a relayed report of the address is not a direct meeting, and the lease
// stays a lease to it.
// Mutation: drop directMeasurement from leaseFreshAddresses → matched.
func TestLeaseFresh_HearsayDoesNotUseTheLease(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	for name, adm := range map[string]identity.AdmissionEvidence{
		"advertisement": {},
		"relayed":       {Direct: true, Relayed: true},
	} {
		o := probe(leaseAt.Add(time.Hour), leaseAddr)
		o.Admission = adm
		if res := mustResolve(t, s.e, o); res.Outcome == identity.OutcomeMatched {
			t.Errorf("%s: a %s of the address matched A on the lease: %+v", name, name, res)
		}
	}
}

// TestLeaseFresh_IsNotAPin_TheAddressStillFollowsTheMAC: device B's MAC seen at
// A's freshly confirmed address is B, and the lease MOVES (lease.go) — the one
// case a pinned address would have turned into a conflict.
// Mutation: fold leaseFresh into dynamicAddress → the move is refused and the
// address stays on A.
func TestLeaseFresh_IsNotAPin_TheAddressStillFollowsTheMAC(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})

	res := mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), leaseMACB, leaseAddr))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.b.ID || res.DecidedBy != identity.KindMACAddress {
		t.Fatalf("resolution = %s on %q by %s, want matched on B by its MAC", res.Outcome, res.Asset.ID, res.DecidedBy)
	}
	if got := s.ownerOf(t, leaseAddr); got != s.b.ID {
		t.Fatalf("the lease is on %s, want moved to B %s: a lease-fresh address is still a lease", got, s.b.ID)
	}
	if n := len(leaseMovedEntries(s.repo.HistoryFor(s.b))); n != 1 {
		t.Errorf("B's timeline has %d lease-move entries, want 1", n)
	}
	// And the move confirmed B there: the next probe of the address is B.
	if res := mustResolve(t, s.e, probe(leaseAt.Add(2*time.Hour), leaseAddr)); res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.b.ID {
		t.Fatalf("after the move a probe resolved %s on %q, want matched on B", res.Outcome, res.Asset.ID)
	}
}

// TestLeaseFresh_FallsBackBehindAStrongerKind: B's hostname seen directly at
// A's fresh address is B by name, with A's address left where it is for the
// lease rule to judge (which keeps it: a name moves no lease) — not a
// cross-kind conflict.
// Mutation: drop the fallback `continue` in the precedence walk → conflict.
func TestLeaseFresh_FallsBackBehindAStrongerKind(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	kiosk := scoped(identity.KindHostname, "kiosk-b", leaseScope)
	if _, err := s.repo.AttachIdentifiers(context.Background(), s.b, []identity.Identifier{kiosk}); err != nil {
		t.Fatalf("AttachIdentifiers: %v", err)
	}
	res := mustResolve(t, s.e, probe(leaseAt.Add(time.Hour), kiosk, leaseAddr))
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != s.b.ID || res.DecidedBy != identity.KindHostname {
		t.Fatalf("resolution = %s on %q by %s, want matched on B by hostname", res.Outcome, res.Asset.ID, res.DecidedBy)
	}
	if got := s.ownerOf(t, leaseAddr); got != s.a.ID {
		t.Fatalf("the address moved to %s on a name match; want it still on A", got)
	}
}

// TestLeaseFresh_AForeignNICIsANewDevice: a MAC nobody holds at A's fresh
// address is not A, and is never written onto A. Two rules defend this and
// either alone holds it: condition 6 (the address does not decide) and the
// drift classifier on the matched path (a different NIC answering is
// `replaced`). So dropping the observedMACs check in ownerLeaseFreshAt does
// NOT fail this test; it fails TestLease_NotMovedWhenTheTenantRanksAddressesHigher,
// where an address ranked above the MAC would otherwise decide first and turn
// B's own MAC into a cross-kind conflict. That is the test that pins
// condition 6 on its own.
func TestLeaseFresh_AForeignNICIsANewDevice(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	macC := id(identity.KindMACAddress, "00:00:5e:00:53:0c")

	res := mustResolve(t, s.e, arpSighting(leaseAt.Add(time.Hour), macC, leaseAddr))

	if res.Outcome == identity.OutcomeMatched && res.Asset.ID == s.a.ID {
		t.Fatalf("a NIC A does not have was matched onto A by the lease: %+v", res)
	}
	for _, held := range s.repo.Identifiers(s.a) {
		if held.Kind == identity.KindMACAddress && held.Value == macC.Value {
			t.Fatalf("the foreign MAC was written onto A")
		}
	}
}

// TestLeaseFresh_AProbeWithAHostKeyAttachesIt is the SSH half of the dev-cluster
// finding: the probe carries a host key the asset has never held. The address
// decides, the key is attached, and the next probe — now fully owned — is A
// without the address having to decide anything.
func TestLeaseFresh_AProbeWithAHostKeyAttachesIt(t *testing.T) {
	s := newLeaseSetup(t, identity.Config{})
	key := id(identity.KindSSHHostKeyFingerprint, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	key.KeyAlgorithm = "ed25519"

	first := mustResolve(t, s.e, probe(leaseAt.Add(time.Hour), leaseAddr, key))
	if first.Outcome != identity.OutcomeMatched || first.Asset.ID != s.a.ID {
		t.Fatalf("first probe resolved %s on %q, want matched on A", first.Outcome, first.Asset.ID)
	}
	if got := s.ownerOf(t, key); got != s.a.ID {
		t.Fatalf("the host key is on %s, want attached to A", got)
	}

	second := mustResolve(t, s.e, probe(leaseAt.Add(2*time.Hour), leaseAddr, key))
	if second.Asset.ID != s.a.ID || (second.Outcome != identity.OutcomeMatched && second.Outcome != identity.OutcomeSupporting) {
		t.Fatalf("second probe resolved %s on %q, want A", second.Outcome, second.Asset.ID)
	}
}
