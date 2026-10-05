package identitytest

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// RunClaimedAddressContract holds an implementation to the claimed-address
// rule (shared/identity/claimed.go): a device's own address on a
// network it serves, reported over a first-hand session, attaches to it
// pinned; re-homes from a provisional or address-only holder; and, held by
// anything stronger, stays where it is and becomes a merge proposal — in a
// DHCP segment as much as in a static one.
//
// It drives a real [identity.Intake] and engine over the repository, the way
// inventory-service's sightings route does, so the rule is held through the
// path that carries it: the Claimed provenance on the sighting, Intake's
// marking, the engine's decision and the store's reassignment.
//
// newRepo must return a FRESH, empty repository on every call. The repository
// must implement [SegmentWriter] and [HistoryReader]; the subtests skip
// without the first and fail without the second.
func RunClaimedAddressContract(t *testing.T, newRepo func() identity.Repository) {
	t.Helper()
	const tenant = "tenant-claims"
	ctx := context.Background()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	src := identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:contract", Mode: identity.ModeActive}

	setup := func(t *testing.T, dynamic bool) (identity.Repository, string) {
		t.Helper()
		r := newRepo()
		seg, ok := r.(SegmentWriter)
		if !ok {
			t.Skipf("%T cannot register segments", r)
		}
		if err := seg.AddSegment(tenant, "192.0.2.0/24", "seg-lan", dynamic); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}
		snap, err := r.SegmentSnapshot(ctx, tenant)
		if err != nil {
			t.Fatalf("SegmentSnapshot: %v", err)
		}
		scope, _ := snap.ScopeForAddress(netip.MustParseAddr("192.0.2.1"), "")
		if scope == identity.ScopeTenantDefault {
			t.Fatal("the segment did not register")
		}
		return r, scope
	}
	create := func(t *testing.T, r identity.Repository, name, identityStatus string, ids ...identity.Identifier) identity.AssetRef {
		t.Helper()
		for i := range ids {
			if ids[i].Confidence == 0 {
				ids[i].Confidence = 1
			}
			if ids[i].Source.Kind == "" {
				ids[i].Source = identity.Source{Kind: identity.SourceMeasured, Ref: "contract"}
			}
			ids[i].SeenAt = now
		}
		ref, err := r.CreateAsset(ctx, tenant, identity.NewAsset{
			ClassKey: "server", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: name,
			Status: identity.StatusMonitoring, IdentityStatus: identityStatus,
			Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			Identifiers: ids, FirstSeenAt: now, LastSeenAt: now,
		})
		if err != nil {
			t.Fatalf("CreateAsset(%s): %v", name, err)
		}
		return ref
	}
	// The gateway, known by its serial; the claim sighting carries that serial
	// as the platform's own (inferred) binding, as an interrogation does.
	gateway := func(t *testing.T, r identity.Repository) identity.AssetRef {
		return create(t, r, "gateway", "", identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-GW-1"})
	}
	claim := func(address string, ref identity.AssetRef) identity.Sighting {
		return identity.Sighting{
			TenantID: tenant, Source: src, Channel: identity.ChannelAuthenticatedSession,
			ObservedAt: now.Add(time.Hour), Confidence: 1, Ownership: identity.OwnershipInternal,
			Identifiers: []identity.SightedIdentifier{
				{Kind: identity.KindIPAddress, Value: address,
					Provenance: identity.IdentifierProvenance{SelfReported: true, Claimed: true}},
				{Kind: identity.KindSerialNumber, Value: "SN-GW-1",
					Provenance: identity.IdentifierProvenance{Kind: identity.SourceInferred, Ref: "asset:" + ref.ID}},
			},
		}
	}
	resolve := func(t *testing.T, r identity.Repository, s identity.Sighting) identity.Resolution {
		t.Helper()
		in, err := identity.NewIntake(r, identity.WithIntakeGenericNames(nil))
		if err != nil {
			t.Fatalf("NewIntake: %v", err)
		}
		obs, err := in.Build(ctx, s)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		eng, err := identity.New(identity.Config{Repo: r, ProvisionalInventory: true})
		if err != nil {
			t.Fatalf("identity.New: %v", err)
		}
		res, err := eng.Resolve(ctx, obs)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		return res
	}
	held := func(t *testing.T, r identity.Repository, ref identity.AssetRef, address string) (identity.Identifier, bool) {
		t.Helper()
		sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		if len(sums) != 1 {
			return identity.Identifier{}, false
		}
		for _, id := range sums[0].Identifiers {
			if id.Kind == identity.KindIPAddress && id.Value == address {
				return id, true
			}
		}
		return identity.Identifier{}, false
	}
	status := func(t *testing.T, r identity.Repository, ref identity.AssetRef) string {
		t.Helper()
		sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil || len(sums) != 1 {
			t.Fatalf("LoadSummaries(%s): %v (%d)", ref.ID, err, len(sums))
		}
		return sums[0].Status
	}
	reassignedFor := func(t *testing.T, r identity.Repository, ref identity.AssetRef) bool {
		t.Helper()
		hr, ok := r.(HistoryReader)
		if !ok {
			t.Fatalf("%T does not implement HistoryReader", r)
		}
		for _, h := range hr.HistoryFor(ref) {
			if h.Action == identity.ActionIdentifierReassigned && h.Changes["reason"] == identity.ReasonClaimedByDevice {
				return true
			}
		}
		return false
	}

	for _, dynamic := range []bool{true, false} {
		name := "static segment"
		if dynamic {
			name = "dhcp segment"
		}
		t.Run(name, func(t *testing.T) {
			t.Run("an address nobody holds attaches to the device, pinned and scoped", func(t *testing.T) {
				r, scope := setup(t, dynamic)
				gw := gateway(t, r)
				res := resolve(t, r, claim("192.0.2.1", gw))
				if res.Outcome != identity.OutcomeMatched || res.Asset.ID != gw.ID {
					t.Fatalf("resolution = %s on %q, want matched on the gateway", res.Outcome, res.Asset.ID)
				}
				id, ok := held(t, r, gw, "192.0.2.1")
				if !ok {
					t.Fatal("the claimed address is not on the gateway")
				}
				if id.Scope != scope || id.StoredAssignment() != identity.AssignmentStatic || id.Inferred() {
					t.Errorf("claimed address stored as scope %q assignment %q source %q; want scope %q, static, measured",
						id.Scope, id.StoredAssignment(), id.Source.Kind, scope)
				}
			})

			t.Run("an address the device already holds unpinned becomes pinned", func(t *testing.T) {
				r, scope := setup(t, dynamic)
				gw := create(t, r, "gateway", "",
					identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-GW-1"},
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: scope})
				res := resolve(t, r, claim("192.0.2.1", gw))
				if res.Outcome != identity.OutcomeMatched || res.Asset.ID != gw.ID {
					t.Fatalf("resolution = %s on %q, want matched on the gateway", res.Outcome, res.Asset.ID)
				}
				if id, _ := held(t, r, gw, "192.0.2.1"); id.StoredAssignment() != identity.AssignmentStatic {
					t.Errorf("assignment = %q after the device claimed it, want static", id.StoredAssignment())
				}
				if reassignedFor(t, r, gw) {
					t.Error("an address the device already held was recorded as reassigned to it")
				}
			})

			// A device the platform knows by that one address and nothing
			// else: the claim has nowhere to move it TO, so it must not be
			// muted out of the device that holds it.
			t.Run("a device known only by the claimed address keeps it", func(t *testing.T) {
				r, scope := setup(t, dynamic)
				only := create(t, r, "address-only device", "",
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: scope})
				s := claim("192.0.2.1", only)
				s.Identifiers = s.Identifiers[:1]
				res := resolve(t, r, s)
				id, ok := held(t, r, only, "192.0.2.1")
				if !ok {
					t.Error("the device lost the only address it is known by")
				}
				// Outside a DHCP segment the address still decides, so the
				// device is matched and its address pinned. (Inside one, an
				// unpinned address decides nothing: supporting evidence, as
				// for any other sighting of it.)
				if !dynamic && (res.Outcome != identity.OutcomeMatched || res.Asset.ID != only.ID || id.StoredAssignment() != identity.AssignmentStatic) {
					t.Errorf("resolution = %s on %q, assignment %q; want matched on the device and the address pinned",
						res.Outcome, res.Asset.ID, id.StoredAssignment())
				}
				if got := status(t, r, only); got == identity.StatusArchived {
					t.Error("the device was archived")
				}
				if reassignedFor(t, r, only) {
					t.Error("an address was recorded as reassigned with no claimant")
				}
			})

			t.Run("a provisional holder yields the address; one left empty is archived", func(t *testing.T) {
				r, scope := setup(t, dynamic)
				gw := gateway(t, r)
				named := create(t, r, "printer guess", string(identity.IdentityProvisional),
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: scope},
					identity.Identifier{Kind: identity.KindHostname, Value: "printer.local", Scope: scope})
				bare := create(t, r, "address guess", string(identity.IdentityProvisional),
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.2", Scope: scope})

				for _, a := range []string{"192.0.2.1", "192.0.2.2"} {
					res := resolve(t, r, claim(a, gw))
					if res.Outcome != identity.OutcomeMatched || res.Asset.ID != gw.ID {
						t.Fatalf("%s: resolution = %s on %q, want matched on the gateway", a, res.Outcome, res.Asset.ID)
					}
					if _, ok := held(t, r, gw, a); !ok {
						t.Errorf("%s did not move to the gateway", a)
					}
				}
				if _, ok := held(t, r, named, "192.0.2.1"); ok {
					t.Error("the provisional holder still has the claimed address")
				}
				for _, ref := range []identity.AssetRef{gw, named, bare} {
					if !reassignedFor(t, r, ref) {
						t.Errorf("asset %s has no identifier_reassigned entry naming the claim", ref.ID)
					}
				}
				if got := status(t, r, named); got == identity.StatusArchived {
					t.Error("a provisional holder that kept its name was archived")
				}
				if got := status(t, r, bare); got != identity.StatusArchived {
					t.Errorf("the emptied provisional holder is %q, want archived", got)
				}
			})

			t.Run("an established holder of nothing but addresses yields the address and is kept", func(t *testing.T) {
				r, scope := setup(t, dynamic)
				gw := gateway(t, r)
				ipOnly := create(t, r, "192.0.2.1", "",
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: scope})
				res := resolve(t, r, claim("192.0.2.1", gw))
				if res.Outcome != identity.OutcomeMatched || res.Asset.ID != gw.ID {
					t.Fatalf("resolution = %s on %q, want matched on the gateway", res.Outcome, res.Asset.ID)
				}
				if _, ok := held(t, r, gw, "192.0.2.1"); !ok {
					t.Error("the address did not move to the gateway")
				}
				if got := status(t, r, ipOnly); got == identity.StatusArchived {
					t.Error("an established record was archived; retiring it is not this rule's decision")
				}
			})

			// The other polarity: a stronger holder keeps the address and the
			// two become a merge proposal — the claimant does not take it.
			t.Run("a holder with a device identifier keeps the address and a merge proposal opens", func(t *testing.T) {
				r, scope := setup(t, dynamic)
				gw := gateway(t, r)
				other := create(t, r, "other device", "",
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: scope},
					identity.Identifier{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:01"})
				res := resolve(t, r, claim("192.0.2.1", gw))
				if res.Outcome != identity.OutcomeConflict || res.Proposal.ID == "" {
					t.Fatalf("resolution = %s (proposal %q), want a conflict with a merge proposal", res.Outcome, res.Proposal.ID)
				}
				if _, ok := held(t, r, other, "192.0.2.1"); !ok {
					t.Error("the stronger holder lost the address")
				}
				if _, ok := held(t, r, gw, "192.0.2.1"); ok {
					t.Error("the gateway took an address a stronger holder keeps")
				}
			})

			// A holder the observation names by something else as well is not
			// a third party to strip: the two may be one device, and that is a
			// reviewer's question.
			t.Run("a holder linked to the observation by other evidence is weighed, not stripped", func(t *testing.T) {
				r, scope := setup(t, dynamic)
				gw := gateway(t, r)
				twin := create(t, r, "twin", "",
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: scope},
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.5", Scope: scope})
				s := claim("192.0.2.1", gw)
				s.Identifiers = append(s.Identifiers, identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: "192.0.2.5"})
				res := resolve(t, r, s)
				if _, ok := held(t, r, twin, "192.0.2.1"); !ok {
					t.Errorf("the address moved off a holder the observation also names (resolution %s on %q)", res.Outcome, res.Asset.ID)
				}
				if res.Outcome != identity.OutcomeConflict {
					t.Errorf("resolution = %s, want a conflict for a reviewer", res.Outcome)
				}
			})

			t.Run("an address an operator declared on another asset is not taken", func(t *testing.T) {
				r, scope := setup(t, dynamic)
				gw := gateway(t, r)
				declared := create(t, r, "declared", "",
					identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: scope,
						Source: identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}})
				res := resolve(t, r, claim("192.0.2.1", gw))
				if res.Outcome == identity.OutcomeMatched && res.Asset.ID == gw.ID {
					if _, ok := held(t, r, gw, "192.0.2.1"); ok {
						t.Fatal("the gateway took an address an operator declared on another asset")
					}
				}
				if _, ok := held(t, r, declared, "192.0.2.1"); !ok {
					t.Error("the declared holder lost the address")
				}
			})
		})
	}

	t.Run("a claim on anything but a first-hand measured sighting is refused", func(t *testing.T) {
		r, _ := setup(t, true)
		gw := gateway(t, r)
		in, err := identity.NewIntake(r, identity.WithIntakeGenericNames(nil))
		if err != nil {
			t.Fatalf("NewIntake: %v", err)
		}
		for _, mutate := range []func(*identity.Sighting){
			func(s *identity.Sighting) { s.Channel = identity.ChannelL2Frame },
			func(s *identity.Sighting) { s.Channel = identity.ChannelControllerInventory },
			func(s *identity.Sighting) { s.Source.Kind = identity.SourceDeclared },
			func(s *identity.Sighting) { s.Identifiers[0].Assignment = identity.AssignmentDynamic },
			func(s *identity.Sighting) {
				s.Identifiers[0].Kind, s.Identifiers[0].Value = identity.KindHostname, "gateway"
			},
		} {
			s := claim("192.0.2.1", gw)
			mutate(&s)
			if _, err := in.Build(ctx, s); !errors.Is(err, identity.ErrInvalidSighting) {
				t.Errorf("a claim on %s/%s (%s) was accepted: err = %v",
					s.Channel, s.Source.Kind, s.Identifiers[0].Kind, err)
			}
		}
	})
}
