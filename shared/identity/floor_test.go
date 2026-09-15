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
