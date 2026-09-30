package identity_test

// The identity FLOOR: the engine must never create an asset that carries no
// identifier.
//
// An asset with none can never be matched again, so every re-observation of the
// same thing makes another one — measured before the rule existed: one host
// ingested three times became three assets, each after the first with no
// identifiers at all.
//
// `ErrNoUsableIdentifier` appeared in ZERO tests. The rule was written down in
// three places in engine.go and asserted in none, which means it could have been
// deleted in any of them and every suite would still have been green.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// TestFloor_AnObservationWithNoIdentifierIsRefused: the first of the three
// floors — nothing at all to identify the thing by.
func TestFloor_AnObservationWithNoIdentifierIsRefused(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})

	_, err := e.Resolve(context.Background(), obs(assetclass.KeyServer))
	if !errors.Is(err, identity.ErrNoUsableIdentifier) {
		t.Fatalf("err = %v, want ErrNoUsableIdentifier", err)
	}
	if n := repo.AssetCount(); n != 0 {
		t.Errorf("%d assets created for an observation with no identifier, want 0 — such an asset "+
			"can never be matched again, so every re-observation makes another one", n)
	}
}

// TestFloor_AnObservationWhoseIdentifiersCannotVoteIsRefused: the second floor.
// The identifiers exist, nobody else owns them, and the CLASS does not identify
// by any of them — a `business_service` identified by `name` alone, handed a
// serial number.
//
// This is the shape that would otherwise create an asset holding identifiers its
// own class is not allowed to match on: recognisable to nothing, re-created on
// every sighting.
func TestFloor_AnObservationWhoseIdentifiersCannotVoteIsRefused(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})

	// `business_service` identifies by `name` and nothing else (ADR-0002 D3
	// erratum), so a serial number is recorded-but-mute.
	o := obs(assetclass.KeyBusinessService, id(identity.KindSerialNumber, "SN-MUTE-1"))
	res, err := e.Resolve(context.Background(), o)

	// Either answer is acceptable as a FLOOR — refuse outright, or create with
	// the identifier attached — but creating an asset the class can never match
	// again is not. Assert the property, not the spelling.
	if err != nil {
		if !errors.Is(err, identity.ErrNoUsableIdentifier) {
			t.Fatalf("err = %v, want ErrNoUsableIdentifier", err)
		}
		if n := repo.AssetCount(); n != 0 {
			t.Errorf("refused, yet %d assets exist", n)
		}
		return
	}
	if res.Asset.Zero() {
		t.Fatal("neither an error nor an asset; the caller has nothing to act on")
	}
	// It was created — then a SECOND sighting of the same thing must find it,
	// not make another one. That is what the floor is protecting.
	if _, err := e.Resolve(context.Background(), o); err != nil {
		t.Fatalf("second sighting: %v", err)
	}
	if n := repo.AssetCount(); n != 1 {
		t.Errorf("%d assets after two sightings of one thing, want 1 — an asset whose class cannot "+
			"match its identifiers is re-created on every poll", n)
	}
}

// TestFloor_AllIdentifiersOwnedOpensAProposalAndCreatesNothing: the third floor,
// and the one with a work item. Every identifier belongs to somebody else and
// none may decide, so the honest answer is a merge proposal and no asset — the
// one the engine would create carries nothing at all.
func TestFloor_AllIdentifiersOwnedOpensAProposalAndCreatesNothing(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	ctx := context.Background()

	// Two assets, each owning one identifier the third observation carries:
	// the cross-kind conflict where nothing is left to attach.
	if _, err := e.Resolve(ctx, obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-OWNED"))); err != nil {
		t.Fatalf("seed the serial's owner: %v", err)
	}
	if _, err := e.Resolve(ctx, obs(assetclass.KeyServer,
		id(identity.KindMACAddress, "aa:bb:cc:00:00:01"))); err != nil {
		t.Fatalf("seed the MAC's owner: %v", err)
	}
	before := repo.AssetCount()

	res, err := e.Resolve(ctx, obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-OWNED"),
		id(identity.KindMACAddress, "aa:bb:cc:00:00:01")))
	if err != nil {
		t.Fatalf("a contested observation must not be an error: %v", err)
	}
	if !res.Asset.Zero() {
		t.Errorf("an asset was created (%s) for an observation with nothing left to attach; it would "+
			"carry no identifier at all", res.Asset.ID)
	}
	if n := repo.AssetCount(); n != before {
		t.Errorf("%d assets, want %d — the floor must create nothing", n, before)
	}
	if res.Proposal.ID == "" {
		t.Error("no merge proposal; a contested observation with no proposal is evidence thrown away")
	}
	if len(res.Candidates) != 2 {
		t.Errorf("%d candidates, want 2 — a reviewer needs both assets the identifiers pointed at",
			len(res.Candidates))
	}
}

// TestResolve_FloorSingleOwnerIsSupportingNotProposal is A1.
//
// Every identifier the observation carries is already owned — and all by the
// SAME asset — but none of them may decide. The floor used to open a merge
// proposal naming that one asset: a "question" whose only possible answer is
// "keep separate" from nothing, because the Approvals UI needs two live records
// to offer a merge. It is another sighting of a known thing: supporting
// evidence, no proposal, nothing created.
//
// Both ways into the floor are covered, and the admission-enabled one runs with
// Config.ProvisionalInventory OFF: the shortcut is about ownership, not about
// provisional inventory.
//
// Mutation check: delete the single-owner branch in the floor AND the
// one-candidate refusal in resolveContested → a one-candidate proposal opens and
// this fails. Deleting either one alone leaves it green, by design: the other is
// the belt and braces, and TestResolveContested_NeverProposesOneCandidate pins
// the refusal on its own.
func TestResolve_FloorSingleOwnerIsSupportingNotProposal(t *testing.T) {
	ctx := context.Background()
	cloudMAC := id(identity.KindMACAddress, "aa:bb:cc:00:20:81")
	cloudARN := id(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-2081")

	tests := []struct {
		name  string
		setup func(t *testing.T) (identity.Repository, *identity.Engine, identity.AssetRef, identity.Observation)
	}{
		{
			// No admission at all: a cloud class drops mac_address from its
			// precedence, so the MAC is recorded and mute.
			name: "unassessed observation, a kind the class does not vote on",
			setup: func(t *testing.T) (identity.Repository, *identity.Engine, identity.AssetRef, identity.Observation) {
				e, repo := newEngine(t, identity.Config{})
				owner := mustResolve(t, e, obs(assetclass.KeyCloudResource, cloudARN, cloudMAC))
				return repo, e, owner.Asset, obs(assetclass.KeyCloudResource, cloudMAC)
			},
		},
		{
			// Admission on, provisional inventory OFF, and the observation IS
			// established (a direct, scoped interface) — the floor is reached
			// because its only identifier may not vote for the class.
			name: "established observation, provisional inventory off",
			setup: func(t *testing.T) (identity.Repository, *identity.Engine, identity.AssetRef, identity.Observation) {
				e, repo := newProvisionalEngine(t, false)
				owner, err := repo.CreateAsset(ctx, tenant, identity.NewAsset{
					ClassKey:        assetclass.KeyCloudResource,
					ClassSourceKind: identity.ClassSourceMeasured,
					DisplayName:     "i-2081",
					Status:          identity.StatusPendingApproval,
					Source:          identity.Source{Kind: identity.SourceMeasured, Ref: "collector"},
					Identifiers:     []identity.Identifier{cloudARN, cloudMAC},
					FirstSeenAt:     observedAt,
					LastSeenAt:      observedAt,
				})
				if err != nil {
					t.Fatalf("seed the owner: %v", err)
				}
				o := direct(observedAt.Add(time.Hour), segmentB, cloudMAC)
				o.ClassHint = assetclass.KeyCloudResource
				return repo.Repository, e, owner, o
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, e, owner, o := tt.setup(t)
			repo := r.(interface {
				AssetCount() int
				Proposals() []identity.MergeProposal
				HistoryFor(identity.AssetRef) []identity.HistoryEntry
			})
			before := repo.AssetCount()

			res := mustResolve(t, e, o)

			if res.Outcome != identity.OutcomeSupporting {
				t.Fatalf("outcome = %s, want supporting: every identifier belongs to ONE asset, so this is "+
					"another sighting of it, not a question", res.Outcome)
			}
			if res.Asset.ID != owner.ID {
				t.Errorf("supporting evidence named %q, want the owner %s", res.Asset.ID, owner.ID)
			}
			if n := len(repo.Proposals()); n != 0 || res.Proposal.ID != "" {
				t.Errorf("%d proposals (resolution names %q), want 0 — a one-candidate proposal can only be "+
					"kept separate from nothing", n, res.Proposal.ID)
			}
			if n := repo.AssetCount(); n != before {
				t.Errorf("%d assets, want %d: the floor never creates", n, before)
			}
			entries := repo.HistoryFor(owner)
			if !hasChange(entries, identity.ActionUpdated, "supporting", true) {
				t.Errorf("no supporting history entry on the owner: %v", historyActions(entries))
			}
			for _, h := range entries {
				if h.Action == identity.ActionMergeProposed {
					t.Errorf("a merge_proposed pointer entry was written: %+v", h.Changes)
				}
			}
		})
	}
}

// TestResolveContested_NeverProposesOneCandidate is A1's belt and braces,
// driven directly: whatever routes a single owner into the contested path, it
// answers supporting instead of opening a proposal nobody can answer.
//
// Mutation check: delete the `len(candidateSeq) == 1` refusal in
// resolveContested → a one-candidate proposal opens and this fails.
func TestResolveContested_NeverProposesOneCandidate(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	owner := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-BELT")))

	serial, err := id(identity.KindSerialNumber, "SN-BELT").Normalized()
	if err != nil {
		t.Fatalf("Normalized: %v", err)
	}
	o := obs(assetclass.KeyServer, serial)
	o.ObservedAt = observedAt.Add(time.Hour)
	res, err := e.ResolveContestedForTest(context.Background(), o,
		[]identity.Identifier{serial}, map[string][]identity.AssetRef{serial.Key(): {owner.Asset}})
	if err != nil {
		t.Fatalf("resolveContested: %v", err)
	}
	if res.Outcome != identity.OutcomeSupporting || res.Asset.ID != owner.Asset.ID {
		t.Fatalf("outcome = %s on %q, want supporting on %s", res.Outcome, res.Asset.ID, owner.Asset.ID)
	}
	if n := proposalCount(repo); n != 0 {
		t.Errorf("%d proposals, want 0: one candidate is not a question", n)
	}
}

// TestFloor_TheOtherPolarity: an observation that CAN be identified must still
// be created. A floor that refuses everything is the same bug pointed the other
// way, and would be invisible to the three tests above.
func TestFloor_TheOtherPolarity(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})

	res, err := e.Resolve(context.Background(),
		obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-FINE")))
	if err != nil {
		t.Fatalf("a perfectly identifiable observation was refused: %v", err)
	}
	if res.Outcome != identity.OutcomeCreated || res.Asset.Zero() {
		t.Fatalf("outcome = %q, asset = %q; want a created asset", res.Outcome, res.Asset.ID)
	}
	if n := repo.AssetCount(); n != 1 {
		t.Errorf("%d assets, want 1", n)
	}
}
