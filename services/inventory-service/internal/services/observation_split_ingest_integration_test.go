package services

// Identical evidence that resolves to a different asset after a segment's DHCP
// posture changes, through the REAL intake: IngestFindingsReport →
// ingestHostObservation → the production engine (admission enforced) → the
// Postgres identity repository's StoreObservation / FinishObservation.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const (
	splitSegmentCIDR = "203.0.113.0/24" // RFC 5737 TEST-NET-3
	splitVIPAddr     = "203.0.113.230"
	splitNodeAddr    = "203.0.113.11"
	splitHolderMAC   = "00:00:5e:00:53:e7" // RFC 7042 documentation MACs,
	splitNodeMAC     = "00:00:5e:00:53:e8" // universally administered
)

// ingestARPFrame runs one decoded ARP frame through the whole intake. It fails
// the test on an ingest ERROR, which is the defect this file pins.
func (f *provisionalFixture) ingestARPFrame(mac, addr string, at time.Time) identity.IngestResult {
	f.t.Helper()
	ho := &hostobs.HostObservation{ObservedAt: at, Source: hostobs.SourceARP, MAC: mac, Addresses: addrsFor(f.t, addr)}
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{observationFinding(f.t, ho)}, "monitoring")
	if err != nil {
		f.t.Fatalf("ingesting %s is-at %s at %s: %v", addr, mac, at.Format(time.RFC3339), err)
	}
	if len(report.Results) != 1 {
		f.t.Fatalf("results = %+v, want one", report.Results)
	}
	return report.Results[0]
}

func (f *provisionalFixture) observationLink(id string) (asset string, receipts int) {
	f.t.Helper()
	if err := f.raw.QueryRow(`SELECT coalesce(asset_id::text,''),
	   (SELECT count(*) FROM identity_observation_receipts r WHERE r.tenant_id=o.tenant_id AND r.observation_id=o.id)
	   FROM identity_observations o WHERE tenant_id=$1 AND id=$2`, f.tenant, id).Scan(&asset, &receipts); err != nil {
		f.t.Fatalf("observation %s: %v", id, err)
	}
	return asset, receipts
}

// TestIntegration_HostObservationIngest_SameFrameAfterPostureFlipSplitsTheObservation
// is the sequence that used to fail ingest with "observation missing or linked
// to another asset":
//
//  1. On a STATIC segment, a host holds the VIP address and a node is met at
//     its own address.
//  2. The node announces the VIP ("VIP is-at node's MAC"). The address votes,
//     so the floating-address rule lands the sighting on the HOLDER: the
//     evidence row is linked to the holder.
//  3. The segment is marked DHCP (Phase 1a does this from a controller, an
//     operator or observed DHCP traffic).
//  4. The node announces the VIP again — byte-identical evidence, a new
//     receipt on the same row. The address no longer votes, so it is a match on
//     the NODE by MAC.
//
// Step 4 must not error, must resolve to the node, and must leave step 2's
// evidence with the holder: the sighting is split onto its own row linked to
// the node, reported as the resolution's observation, with observation_split
// history on both assets.
//
// Mutation checks: skip settleObservationRow in FinishObservation → step 4
// fails the ingest; relink the row in place instead of splitting → the
// holder's row is re-linked to the node; have FinishObservation return the
// stored id → the ingest result names the holder's row.
func TestIntegration_HostObservationIngest_SameFrameAfterPostureFlipSplitsTheObservation(t *testing.T) {
	f := newProvisionalFixture(t)
	seg := uuid.New()
	f.exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment,metadata)
	 VALUES($1,$2,'Lab','cidr',$3,true,'production','{}'::jsonb)`, seg, f.tenant, splitSegmentCIDR)

	t0 := f.now.Add(-4 * time.Hour)
	holder := f.ingestARPFrame(splitHolderMAC, splitVIPAddr, t0)
	node := f.ingestARPFrame(splitNodeMAC, splitNodeAddr, t0.Add(time.Minute))
	if holder.AssetID == "" || node.AssetID == "" || holder.AssetID == node.AssetID {
		t.Fatalf("setup: assets %q and %q, want two", holder.AssetID, node.AssetID)
	}

	floating := f.ingestARPFrame(splitNodeMAC, splitVIPAddr, t0.Add(time.Hour))
	if floating.AssetID != holder.AssetID || floating.ObservationID == "" {
		t.Fatalf("setup: on a static segment the announcement resolved to %q (observation %q); want the floating-address "+
			"rule to land it on the holder %s", floating.AssetID, floating.ObservationID, holder.AssetID)
	}

	f.exec(`UPDATE network_segments SET metadata='{"dynamic":true}'::jsonb WHERE tenant_id=$1 AND id=$2`, f.tenant, seg)

	again := f.ingestARPFrame(splitNodeMAC, splitVIPAddr, t0.Add(2*time.Hour))

	if again.AssetID != node.AssetID {
		t.Fatalf("after the flip the same frame resolved to %q, want a match on the node %s by its MAC", again.AssetID, node.AssetID)
	}
	if again.ObservationID == "" || again.ObservationID == floating.ObservationID {
		t.Fatalf("the ingest reports observation %q; want the sighting on a row of its own, not the holder's row %s — "+
			"callers write the sighting's retained context against this id", again.ObservationID, floating.ObservationID)
	}
	if asset, receipts := f.observationLink(floating.ObservationID); asset != holder.AssetID || receipts != 1 {
		t.Errorf("the holder's evidence row is on %q with %d receipts; want it still on the holder %s with the "+
			"sighting the floating-address rule resolved", asset, receipts, holder.AssetID)
	}
	if asset, receipts := f.observationLink(again.ObservationID); asset != node.AssetID || receipts != 1 {
		t.Errorf("the split row is on %q with %d receipts; want it on the node %s with the new sighting", asset, receipts, node.AssetID)
	}
	for _, side := range []struct{ name, id string }{{"holder", holder.AssetID}, {"node", node.AssetID}} {
		if !containsAll(f.historyActions(side.id), `"kind": "observation_split"`, `"observation_id": "`+again.ObservationID+`"`) {
			t.Errorf("the %s's timeline does not record the split: %v", side.name, f.historyActions(side.id))
		}
	}

	// And the next identical frame lands on the split row: no further split.
	next := f.ingestARPFrame(splitNodeMAC, splitVIPAddr, t0.Add(3*time.Hour))
	if next.ObservationID != again.ObservationID || next.AssetID != node.AssetID {
		t.Errorf("the next identical frame landed on observation %q / asset %q; want %s / %s",
			next.ObservationID, next.AssetID, again.ObservationID, node.AssetID)
	}
}
