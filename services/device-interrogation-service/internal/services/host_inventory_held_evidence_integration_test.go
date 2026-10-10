package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// heldPoster answers every sighting the way the engine answers evidence it
// links to an established asset but writes nothing from: `supporting`, with
// EvidenceHeld (platform ADR-0003 D2). It does not resolve anything, which is
// the point — the engine wrote no endpoint for this run.
type heldPoster struct{ assetID string }

func (p heldPoster) PostItems(_ context.Context, _ string, items []sightingclient.Item) ([]sightingclient.Result, error) {
	out := make([]sightingclient.Result, len(items))
	for i := range items {
		out[i] = sightingclient.Result{Outcome: identity.OutcomeSupporting, AssetID: p.assetID, EvidenceHeld: true}
	}
	return out, nil
}

// TestIntegration_HostInventory_Materialises_HeldEvidenceClosesNothing: a
// host inventory the engine HELD wrote none of its sockets onto the asset, so
// it is not this run's statement about which sockets are open. Sweeping on it
// marks every socket the agent reported last time as closed — every one is
// "absent" from a run that recorded nothing.
//
// The flag crosses the sightings route (inventory-service → sightingclient →
// identity.Resolution); losing it anywhere on that path reaches the sweep as
// an ordinary match. Mutation check: drop EvidenceHeld from
// sightingclient.Result.Resolution, or the EvidenceHeld gate in materialise,
// and this fails with three live sockets closed.
func TestIntegration_HostInventory_Materialises_HeldEvidenceClosesNothing(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	ingest := NewHostInventoryIngest(appDB, owner)

	first := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	firstCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, first))
	if err != nil {
		t.Fatalf("first collection: %v", err)
	}
	before := endpointRows(t, owner, tenantID, firstCounts.AssetID)
	if len(before) == 0 {
		t.Fatal("the first collection wrote no endpoints; nothing for the sweep to close")
	}

	posterMu.RLock()
	previous := posterFactory
	posterMu.RUnlock()
	SetSightingPosterFactory(func(d *sql.DB) sightingclient.Poster {
		if d == appDB {
			return heldPoster{assetID: firstCounts.AssetID}
		}
		return previous(d)
	})
	t.Cleanup(func() { SetSightingPosterFactory(previous) })

	// A complete listeners section with only sshd: were it materialised, every
	// other socket would be retired.
	second := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y3", defaultPackages())
	second.Listeners = []hostinventory.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd", PID: 812}}
	secondCounts, err := ingest.MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, second))
	if err != nil {
		t.Fatalf("held collection: %v", err)
	}
	if secondCounts.EndpointsClosed != 0 {
		t.Errorf("endpoints_closed = %d for a run whose evidence the engine held", secondCounts.EndpointsClosed)
	}
	if secondCounts.Endpoints != 0 {
		t.Errorf("endpoints = %d for a run that wrote none", secondCounts.Endpoints)
	}
	for port, status := range endpointRows(t, owner, tenantID, firstCounts.AssetID) {
		if status != before[port] {
			t.Errorf("port %d went %q -> %q on a held run", port, before[port], status)
		}
	}
}
