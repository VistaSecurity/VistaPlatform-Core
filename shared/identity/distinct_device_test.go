package identity_test

// Two devices of one model share a DHCP default hostname. A network controller
// reports both clients, each with its own MAC and address. The name is a weak
// identifier; a MAC the controller reports for that client binds one device.
// So the second client is a second asset — not a merge proposal asking a
// reviewer a question the evidence already answers.
//
// A bare direct sighting (L2/L3, not authoritative) of the same shape stays a
// proposal: TestProvisionalSharedNameSecondDeviceStaysAProposal pins it.
//
// Mutation record: with the `DriftDistinct` branch removed from Engine.resolve,
// TestDistinctHardwareUnderASharedNameCreates fails with outcome `matched` (the
// second MAC silently attached to the first plug) and ...UnderAdmission fails
// with outcome `conflict` and a merge proposal.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const plugSegment = "seg-plugs"

var (
	plugAt   = time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	plugMACA = id(identity.KindMACAddress, "00:00:5e:00:53:a1")
	plugMACB = id(identity.KindMACAddress, "00:00:5e:00:53:b2")
	plugIPA  = scoped(identity.KindIPAddress, "192.0.2.101", plugSegment)
	plugIPB  = scoped(identity.KindIPAddress, "192.0.2.146", plugSegment)
	plugName = scoped(identity.KindHostname, "plug-model-x", plugSegment)
)

// controllerClient is one client row from a network controller: an
// authoritative, direct, active interrogation of a named device.
func controllerClient(at time.Time, ids ...identity.Identifier) identity.Observation {
	o := identity.Observation{
		TenantID:    tenant,
		Identifiers: ids,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "controller:test", Mode: identity.ModeActive},
		ObservedAt:  at,
		Confidence:  0.9,
		Admission:   identity.AdmissionEvidence{Authoritative: true},
	}
	o.Network.SegmentID = plugSegment
	return o
}

// directClient is the same report as an authenticated session delivers it:
// authoritative AND direct, which is what durable admission needs to establish.
func directClient(at time.Time, ids ...identity.Identifier) identity.Observation {
	o := controllerClient(at, ids...)
	o.Admission.Direct = true
	return o
}

func relayedClient(at time.Time, ids ...identity.Identifier) identity.Observation {
	o := controllerClient(at, ids...)
	o.Source.Mode = identity.ModePassive
	o.Admission = identity.AdmissionEvidence{Relayed: true}
	return o
}

func ownerOfID(t *testing.T, r interface {
	FindByIdentifier(context.Context, string, identity.Kind, string, string) ([]identity.AssetRef, error)
}, i identity.Identifier) []identity.AssetRef {
	t.Helper()
	n, err := i.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	refs, err := r.FindByIdentifier(context.Background(), tenant, n.Kind, n.Value, n.Scope)
	if err != nil {
		t.Fatal(err)
	}
	return refs
}

func assertSecondPlug(t *testing.T, first identity.AssetRef, second identity.Resolution, repo interface {
	FindByIdentifier(context.Context, string, identity.Kind, string, string) ([]identity.AssetRef, error)
}, proposals int, before []identity.Identifier, after func() []identity.Identifier) {
	t.Helper()
	if second.Outcome != identity.OutcomeCreated {
		t.Fatalf("second plug outcome = %s, want created", second.Outcome)
	}
	if second.Asset.ID == first.ID {
		t.Fatal("the second plug landed on the first plug's asset")
	}
	if proposals != 0 {
		t.Fatalf("%d merge proposals opened, want none", proposals)
	}
	for _, i := range []identity.Identifier{plugMACB, plugIPB} {
		if got := ownerOfID(t, repo, i); len(got) != 1 || got[0].ID != second.Asset.ID {
			t.Fatalf("%s owned by %v, want the new asset", i.Value, got)
		}
	}
	for _, i := range []identity.Identifier{plugMACA, plugIPA, plugName} {
		if got := ownerOfID(t, repo, i); len(got) != 1 || got[0].ID != first.ID {
			t.Fatalf("%s owned by %v, want the original asset", i.Value, got)
		}
	}
	if now := after(); len(now) != len(before) {
		t.Fatalf("original asset identifiers changed: %d -> %d", len(before), len(now))
	}
}

func TestDistinctHardwareUnderASharedNameCreates(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	first := mustResolve(t, e, controllerClient(plugAt, plugName, plugIPA, plugMACA))
	if first.Outcome != identity.OutcomeCreated {
		t.Fatalf("setup: %s", first.Outcome)
	}
	before := repo.Identifiers(first.Asset)
	second := mustResolve(t, e, controllerClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB))
	assertSecondPlug(t, first.Asset, second, repo, len(repo.Proposals()), before, func() []identity.Identifier { return repo.Identifiers(first.Asset) })
	if repo.StatusOf(second.Asset) != identity.StatusPendingApproval {
		t.Fatalf("new asset status = %q, want pending_approval", repo.StatusOf(second.Asset))
	}
}

func TestDistinctHardwareUnderASharedNameCreatesUnderAdmission(t *testing.T) {
	repo := newAdmissionRepo()
	e, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	first := mustResolve(t, e, directClient(plugAt, plugName, plugIPA, plugMACA))
	if first.Outcome != identity.OutcomeCreated {
		t.Fatalf("setup: %s", first.Outcome)
	}
	before := repo.Identifiers(first.Asset)
	second := mustResolve(t, e, directClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB))
	assertSecondPlug(t, first.Asset, second, repo, len(repo.Proposals()), before, func() []identity.Identifier { return repo.Identifiers(first.Asset) })
}

// A relayed advert is not a direct measurement: it never creates. Pinned as it
// behaved before the row existed — the sighting is attached to the named asset
// (no admission) / proposed (admission), and in neither case is a second asset
// created.
func TestDistinctHardwareFromARelayedAdvertDoesNotCreate(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	first := mustResolve(t, e, directClient(plugAt, plugName, plugIPA, plugMACA))
	second := mustResolve(t, e, relayedClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB))
	if second.Outcome != identity.OutcomeMatched || second.Asset.ID != first.Asset.ID {
		t.Fatalf("relayed advert outcome = %s on %s, want matched on the original", second.Outcome, second.Asset.ID)
	}
	if repo.AssetCount() != 1 {
		t.Fatalf("%d assets, want 1", repo.AssetCount())
	}
}

func TestDistinctHardwareFromARelayedAdvertDoesNotCreateUnderAdmission(t *testing.T) {
	repo := newAdmissionRepo()
	e, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	first := mustResolve(t, e, directClient(plugAt, plugName, plugIPA, plugMACA))
	second := mustResolve(t, e, relayedClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB))
	if second.Outcome == identity.OutcomeCreated {
		t.Fatal("a relayed advert created an asset")
	}
	if repo.AssetCount() != 1 {
		t.Fatalf("%d assets, want 1 (first %s)", repo.AssetCount(), first.Asset.ID)
	}
}

// Address-only drift: same name, same MAC, new address is the lease moving
// with the device, never a second device.
func TestSameNameSameMACNewAddressIsNotCreated(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	first := mustResolve(t, e, controllerClient(plugAt, plugName, plugIPA, plugMACA))
	second := mustResolve(t, e, controllerClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACA))
	if second.Outcome != identity.OutcomeMatched || second.Asset.ID != first.Asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", second.Outcome, second.Asset.ID, first.Asset.ID)
	}
	if repo.AssetCount() != 1 || len(repo.Proposals()) != 0 {
		t.Fatalf("assets=%d proposals=%d, want 1 and 0", repo.AssetCount(), len(repo.Proposals()))
	}
}

// interrogationClient is shaped exactly like the observation that motivated the
// fix: a controller/API interrogation job's answer, measured, ACTIVE, direct,
// and carrying no `authoritative` flag.
func interrogationClient(at time.Time, ids ...identity.Identifier) identity.Observation {
	o := controllerClient(at, ids...)
	o.Source = identity.Source{Kind: identity.SourceMeasured, Mode: identity.ModeActive, Ref: "interrogation:job-1"}
	o.Admission = identity.AdmissionEvidence{Direct: true}
	return o
}

func TestDistinctHardwareFromAnInterrogationJobCreates(t *testing.T) {
	for _, admission := range []bool{false, true} {
		name := "plain"
		if admission {
			name = "admission"
		}
		t.Run(name, func(t *testing.T) {
			type store interface {
				FindByIdentifier(context.Context, string, identity.Kind, string, string) ([]identity.AssetRef, error)
				Identifiers(identity.AssetRef) []identity.Identifier
				Proposals() []identity.MergeProposal
			}
			var (
				e    *identity.Engine
				repo store
			)
			if admission {
				r := newAdmissionRepo()
				eng, err := identity.New(identity.Config{Repo: r, AdmissionEnabled: true})
				if err != nil {
					t.Fatal(err)
				}
				e, repo = eng, r
			} else {
				eng, r := newEngine(t, identity.Config{})
				e, repo = eng, r
			}
			first := mustResolve(t, e, interrogationClient(plugAt, plugName, plugIPA, plugMACA))
			if first.Outcome != identity.OutcomeCreated {
				t.Fatalf("setup: %s", first.Outcome)
			}
			before := repo.Identifiers(first.Asset)
			second := mustResolve(t, e, interrogationClient(plugAt.Add(time.Minute), plugName, plugIPB, plugMACB))
			assertSecondPlug(t, first.Asset, second, repo, len(repo.Proposals()), before, func() []identity.Identifier { return repo.Identifiers(first.Asset) })
		})
	}
}
