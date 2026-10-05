package identity_test

// C1 — an address-only link never carries a device — and its
// interaction with A1, which routes more sightings into supporting evidence.
//
// Driven through the real admission path (newProvisionalEngine in
// provisional_test.go) against the in-memory store. Addresses are RFC 5737 and
// every name is invented.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// flow is a measured passive observation the platform sensor made of TRAFFIC
// to an address — a TLS flow, say — rather than of the device itself: not
// direct, not relayed. AssessAdmission answers insufficient_identity_evidence,
// so nothing it carries may vote; its source MAC is whatever frame the sensor
// saw, which on a DHCP network is whoever holds the lease right now.
func flow(at time.Time, segment string, ids ...identity.Identifier) identity.Observation {
	o := identity.Observation{
		TenantID:    tenant,
		Identifiers: ids,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:platform-flow", Mode: identity.ModePassive},
		ObservedAt:  at,
		Confidence:  0.7,
	}
	o.Network.SegmentID = segment
	return o
}

func ownersOf(t *testing.T, repo *admissionRepo, ident identity.Identifier) []identity.AssetRef {
	t.Helper()
	n, err := ident.Normalized()
	if err != nil {
		t.Fatalf("Normalized(%s): %v", ident.Value, err)
	}
	refs, err := repo.FindByIdentifier(context.Background(), tenant, n.Kind, n.Value, n.Scope)
	if err != nil {
		t.Fatalf("FindByIdentifier(%s): %v", n.Value, err)
	}
	return refs
}

// TestProvisionalAddressOnlyLinkAttachesNoDeviceBinding is C1 end to end:
// the wrong-merge journey, in invented names and RFC 5737 addresses.
//
//  1. A relayed advert names a laptop at .39 — a provisional asset.
//  2. The sensor sees traffic to .39 from an access point's MAC (the lease
//     changed hands). It is linked to the laptop by the ADDRESS ALONE, so
//     nothing is attached — not the MAC, not the name it came with — the
//     laptop's last-seen does not move, and the resolution names no asset,
//     so the intake path cannot write the access point's facts or class
//     evidence onto the laptop either.
//  3. The controller then reports the access point directly (MAC, serial,
//     .39). The MAC is nobody's, so it cannot corroborate the laptop: the
//     access point becomes its own asset and the address follows it. Before
//     C1, step 2 put the MAC on the laptop, and step 3 matched it by MAC,
//     promoted it and renamed the laptop after the access point.
//
// Mutation check: remove the leaseOnlyLink branch in resolveSupporting → step 2
// attaches the MAC and the name to the laptop, and this fails.
func TestProvisionalAddressOnlyLinkAttachesNoDeviceBinding(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	laptopName := scoped(identity.KindHostname, "desk-laptop.local", segmentB)
	lease := scoped(identity.KindIPAddress, "198.51.100.39", segmentB)
	apMAC := id(identity.KindMACAddress, "02:aa:bb:cc:dd:39")
	apName := scoped(identity.KindHostname, "lobby-ap.local", segmentB)

	laptop := mustResolve(t, e, advert(advertAt, segmentB, laptopName, lease))
	if laptop.Outcome != identity.OutcomeProvisional {
		t.Fatalf("setup outcome = %s, want provisional", laptop.Outcome)
	}
	heldBefore := len(repo.Identifiers(laptop.Asset))

	sawAt := advertAt.Add(4 * time.Hour)
	res := mustResolve(t, e, flow(sawAt, segmentB, lease, apMAC, apName))

	if res.Outcome != identity.OutcomeUnresolved || !res.Asset.Zero() {
		t.Fatalf("outcome = %s on %q, want unresolved with NO asset: every intake path writes facts, "+
			"placement and class evidence onto the resolution's asset, and this evidence is about the "+
			"device holding the lease now, not the laptop", res.Outcome, res.Asset.ID)
	}
	if refs := ownersOf(t, repo, apMAC); len(refs) != 0 {
		t.Fatalf("the MAC seen at the leased address now belongs to %s; an address is a lease, and "+
			"the device holding it now is not the one the advert described", refs[0].ID)
	}
	if refs := ownersOf(t, repo, apName); len(refs) != 0 {
		t.Errorf("the name that came with that MAC was attached to %s; names from the same device "+
			"are not attached either", refs[0].ID)
	}
	if n := len(repo.Identifiers(laptop.Asset)); n != heldBefore {
		t.Errorf("the laptop holds %d identifiers, want %d unchanged", n, heldBefore)
	}
	if got := repo.LastSeen(laptop.Asset); !got.Equal(advertAt) {
		t.Errorf("last_seen = %s, want %s: this sighting is about whatever holds the lease now", got, advertAt)
	}
	entries := repo.HistoryFor(laptop.Asset)
	if !hasChange(entries, identity.ActionUpdated, "address_only_link", true) ||
		!hasChange(entries, identity.ActionUpdated, "supporting", true) {
		t.Errorf("no `updated` entry with supporting + address_only_link: %+v", entries)
	}
	unattached := map[identity.Kind]int{}
	for _, u := range res.Unattached {
		unattached[u.Kind]++
	}
	if unattached[identity.KindMACAddress] != 1 || unattached[identity.KindHostname] != 1 {
		t.Errorf("unattached = %+v, want the MAC and the name reported, not silently dropped", res.Unattached)
	}

	// Step 3: the controller meets the access point.
	ctrl := direct(sawAt.Add(time.Second), segmentB, apMAC, id(identity.KindSerialNumber, "SN-AP-39"), lease)
	ctrl.Admission.Authoritative = true
	ap := mustResolve(t, e, ctrl)
	if ap.Asset.ID == laptop.Asset.ID {
		t.Fatalf("the controller's access point resolved to the laptop's provisional asset (%s): the "+
			"wrong merge #2081 C1 exists to prevent", ap.Asset.ID)
	}
	if refs := ownersOf(t, repo, apMAC); len(refs) != 1 || refs[0].ID != ap.Asset.ID {
		t.Errorf("MAC owners = %+v, want only the access point %s", refs, ap.Asset.ID)
	}
	if got := repo.IdentityStatusOf(laptop.Asset); got != string(identity.IdentityProvisional) {
		t.Errorf("the laptop's identity_status = %q, want still provisional: nothing about it was corroborated", got)
	}
	if refs := ownersOf(t, repo, laptopName); len(refs) != 1 || refs[0].ID != laptop.Asset.ID {
		t.Errorf("the laptop's name moved: owners %+v", refs)
	}
}

// TestProvisionalNameLinkStillAttachesTheDevice is C1's other polarity: when
// the observation ALSO carries the provisional asset's name, the link is a name
// and an address — corroboration — and the device identifier is attached as it
// always was. A guard that refused this too would be the same bug pointed the
// other way.
func TestProvisionalNameLinkStillAttachesTheDevice(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	laptopName := scoped(identity.KindHostname, "desk-laptop.local", segmentB)
	lease := scoped(identity.KindIPAddress, "198.51.100.40", segmentB)
	laptopMAC := id(identity.KindMACAddress, "02:aa:bb:cc:dd:40")

	laptop := mustResolve(t, e, advert(advertAt, segmentB, laptopName, lease))
	if laptop.Outcome != identity.OutcomeProvisional {
		t.Fatalf("setup outcome = %s, want provisional", laptop.Outcome)
	}

	sawAt := advertAt.Add(time.Hour)
	res := mustResolve(t, e, flow(sawAt, segmentB, laptopName, lease, laptopMAC))

	if res.Outcome != identity.OutcomeSupporting || res.Asset.ID != laptop.Asset.ID {
		t.Fatalf("outcome = %s on %q, want supporting on %s", res.Outcome, res.Asset.ID, laptop.Asset.ID)
	}
	if refs := ownersOf(t, repo, laptopMAC); len(refs) != 1 || refs[0].ID != laptop.Asset.ID {
		t.Errorf("MAC owners = %+v, want the provisional laptop %s: a name link is corroboration, and a "+
			"sketch may be filled in", refs, laptop.Asset.ID)
	}
	if got := repo.LastSeen(laptop.Asset); !got.Equal(sawAt) {
		t.Errorf("last_seen = %s, want %s", got, sawAt)
	}
	if hasChange(repo.HistoryFor(laptop.Asset), identity.ActionUpdated, "address_only_link", true) {
		t.Error("a name-and-address link was recorded as address_only_link")
	}
}

// TestSupportingAddressOnlyLinkNeverTouchesAnotherDevice is the A1 × C1
// cross-check: A1 routes more sightings into supporting evidence, including
// against ESTABLISHED assets and through the floor. Whichever way a sighting
// linked to an asset by an address alone arrives, a device identifier it
// carries must not end up on that asset, and the asset must not be kept fresh
// by another device's traffic.
//
// Mutation check: remove the leaseOnlyLink branch → the "provisional inventory
// on" case touches the established asset (last_seen moves).
func TestSupportingAddressOnlyLinkNeverTouchesAnotherDevice(t *testing.T) {
	ownMAC := id(identity.KindMACAddress, "02:aa:bb:cc:dd:41")
	otherMAC := id(identity.KindMACAddress, "02:aa:bb:cc:dd:42")

	tests := []struct {
		name        string
		provisional bool
		segment     string
		sighting    func(at time.Time, segment string, ids ...identity.Identifier) identity.Observation
		wantOutcome identity.Outcome
		// wantNewOwner: the other MAC legitimately becomes a NEW asset (the
		// floor's create path, reached by an established sighting).
		wantNewOwner bool
	}{
		{
			name: "not established, provisional inventory on", provisional: true, segment: segmentB,
			sighting: flow, wantOutcome: identity.OutcomeUnresolved,
		},
		{
			name: "not established, provisional inventory off", provisional: false, segment: segmentB,
			sighting: flow, wantOutcome: identity.OutcomeUnresolved,
		},
		{
			// Established (a direct MAC), the address inside a DHCP range so it
			// cannot vote: the floor. The unowned MAC is something to attach,
			// so it creates — and the lease holder gains nothing.
			name: "established through the floor, dynamic scope", provisional: true, segment: segmentD,
			sighting: direct, wantOutcome: identity.OutcomeCreated, wantNewOwner: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, repo := newProvisionalEngine(t, tt.provisional)
			lease := scoped(identity.KindIPAddress, "203.0.113.41", tt.segment)
			established := mustResolve(t, e, direct(advertAt, tt.segment, ownMAC, lease))
			if established.Outcome != identity.OutcomeCreated {
				t.Fatalf("setup outcome = %s, want created", established.Outcome)
			}
			repo.SetIdentityStatus(established.Asset, identity.IdentityEstablished)
			heldBefore := len(repo.Identifiers(established.Asset))
			seenBefore := repo.LastSeen(established.Asset)

			res := mustResolve(t, e, tt.sighting(advertAt.Add(5*time.Hour), tt.segment, lease, otherMAC))

			if res.Outcome != tt.wantOutcome {
				t.Fatalf("outcome = %s, want %s", res.Outcome, tt.wantOutcome)
			}
			if res.Asset.ID == established.Asset.ID {
				t.Fatalf("the resolution names %s, which the sighting is linked to only by an address; the "+
					"intake path would write the other device's facts onto it", res.Asset.ID)
			}
			refs := ownersOf(t, repo, otherMAC)
			for _, r := range refs {
				if r.ID == established.Asset.ID {
					t.Fatalf("the other device's MAC was attached to %s, which it is linked to only by an address", r.ID)
				}
			}
			if tt.wantNewOwner && len(refs) != 1 {
				t.Errorf("the other MAC has owners %+v, want exactly one new asset", refs)
			}
			if !tt.wantNewOwner && len(refs) != 0 {
				t.Errorf("the other MAC has owners %+v, want none", refs)
			}
			if n := len(repo.Identifiers(established.Asset)); n != heldBefore {
				t.Errorf("the established asset holds %d identifiers, want %d unchanged", n, heldBefore)
			}
			if got := repo.LastSeen(established.Asset); !got.Equal(seenBefore) {
				t.Errorf("last_seen moved from %s to %s: another device's traffic on the lease kept this "+
					"asset fresh", seenBefore, got)
			}
			if n := len(repo.Proposals()); n != 0 {
				t.Errorf("%d proposals, want 0", n)
			}
		})
	}
}

// TestProvisionalYieldRerunWritesNothingOfItsOwn pins the interaction between
// A1 and hearsay-yields.
//
// The yield re-runs the decision with the provisional asset's addresses muted.
// When everything left is owned by that same asset and may not vote, the re-run
// reaches the floor with ONE owner — which before A1 opened a one-candidate
// proposal, and after A1 would write supporting evidence — and THEN the yield
// falls back to an ordinary match and writes again. The re-run must write
// nothing: the outer resolution owns the observation.
//
// Mutation check: remove the `len(e.muted) > 0` return in resolveSupporting →
// a second, supporting history entry lands on the asset for one observation.
func TestProvisionalYieldRerunWritesNothingOfItsOwn(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	lease := scoped(identity.KindIPAddress, "198.51.100.43", segmentB)
	// A `name` never votes outside the classes that list it, so it is owned
	// and mute: exactly what the re-run is left holding.
	label, err := scoped(identity.KindName, "Front desk", identity.ScopeTenantDefault).Normalized()
	if err != nil {
		t.Fatalf("Normalized: %v", err)
	}
	p, err := repo.CreateAsset(context.Background(), tenant, identity.NewAsset{
		ClassKey:        "unknown_host",
		ClassSourceKind: identity.ClassSourceMeasured,
		DisplayName:     "front desk",
		Status:          identity.StatusPendingApproval,
		IdentityStatus:  string(identity.IdentityProvisional),
		NetworkSegment:  segmentB,
		Source:          identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:relay"},
		Identifiers:     []identity.Identifier{lease, label},
		FirstSeenAt:     advertAt,
		LastSeenAt:      advertAt,
	})
	if err != nil {
		t.Fatalf("seeding the provisional asset: %v", err)
	}
	before := len(repo.HistoryFor(p))

	// The observation carries a socket the asset does not have yet. A match
	// that changed nothing writes no timeline row (asset-history rule), so
	// without something new the one entry this test counts would not exist and
	// a stray supporting entry from the re-run would be the ONLY thing it saw.
	// The endpoint is written by whichever path reaches the asset first, which
	// is what makes the mutation below visible.
	obs := direct(advertAt.Add(time.Hour), segmentB, lease, label)
	obs.Endpoints = []identity.EndpointObservation{{Address: "198.51.100.43", Port: 443, Transport: "tcp"}}
	res := mustResolve(t, e, obs)

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != p.ID {
		t.Fatalf("outcome = %s on %q, want the fallback ordinary match on %s", res.Outcome, res.Asset.ID, p.ID)
	}
	added := repo.HistoryFor(p)[before:]
	if len(added) != 1 {
		t.Errorf("one observation wrote %d history entries on the asset (%v), want 1", len(added), historyActions(added))
	}
	if hasChange(added, identity.ActionUpdated, "supporting", true) {
		t.Error("the muted re-run wrote supporting evidence of its own")
	}
	if n := len(repo.Proposals()); n != 0 {
		t.Errorf("%d proposals, want 0: the re-run's single owner is not a question", n)
	}
}
