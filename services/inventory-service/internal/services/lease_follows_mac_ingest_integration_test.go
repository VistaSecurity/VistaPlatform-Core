package services

// 1b and 1c through the REAL inventory intake: IngestFindingsReport →
// ingestHostObservation → the production engine (svc.identityEngine(), admission
// enforced, provisional inventory on) → the Postgres identity repository.
//
// The segment is DHCP by its `network_segments.metadata.dynamic` flag, the one
// key ScopeForAddress reads, so the dynamic posture reaches the engine the way
// production delivers it: as the observation's own DynamicScopes, not an engine
// setting.
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
	leaseSegmentCIDR = "203.0.113.0/24" // RFC 5737 TEST-NET-3
	leaseTestAddr    = "203.0.113.7"
	leaseOtherAddr   = "203.0.113.20"
	leaseMACOne      = "00:00:5e:00:53:71" // RFC 7042 documentation MACs,
	leaseMACTwo      = "00:00:5e:00:53:72" // universally administered
)

// addDHCPSegment configures a DHCP segment on the fixture's tenant.
func (f *provisionalFixture) addDHCPSegment() uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment,metadata)
	 VALUES($1,$2,'Guest Wi-Fi','cidr',$3,true,'production','{"dynamic":true}'::jsonb)`, id, f.tenant, leaseSegmentCIDR)
	return id
}

// ingestARP runs one decoded ARP frame — MAC at address, observed at `at` —
// through the whole intake and returns its result.
func (f *provisionalFixture) ingestARP(mac, addr string, at time.Time) identity.IngestResult {
	f.t.Helper()
	ho := &hostobs.HostObservation{
		ObservedAt: at,
		Source:     hostobs.SourceARP,
		MAC:        mac,
		Addresses:  addrsFor(f.t, addr),
	}
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{observationFinding(f.t, ho)}, "monitoring")
	if err != nil {
		f.t.Fatal(err)
	}
	if len(report.Results) != 1 {
		f.t.Fatalf("results = %+v, want one", report.Results)
	}
	return report.Results[0]
}

func (f *provisionalFixture) identifierOwner(kind, value string) (owner string, lastSeen time.Time) {
	f.t.Helper()
	if err := f.raw.QueryRow(`SELECT asset_id::text, last_seen_at FROM asset_identifiers WHERE tenant_id=$1 AND kind=$2 AND value=$3`,
		f.tenant, kind, value).Scan(&owner, &lastSeen); err != nil {
		f.t.Fatalf("owner of %s=%s: %v", kind, value, err)
	}
	return owner, lastSeen
}

func (f *provisionalFixture) countLeaseMoves(assetID string) int {
	f.t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2
	   AND action='identifier_reassigned' AND changes_json->>'reason'=$3`, f.tenant, assetID, identity.ReasonLeaseMoved).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// TestIntegration_HostObservationIngest_LeaseFollowsTheMAC is 1b end to end.
//
//  1. Device one is met by ARP at .7 on a DHCP segment; device two at .20.
//  2. An hour later ARP says device two holds .7. The address moves to device
//     two, and BOTH assets' timelines carry `identifier_reassigned` with
//     reason `lease_moved`, naming where it came from and went to.
//  3. A sighting of device one at .7 made BEFORE step 2 then arrives late.
//     It matches device one by its MAC and must NOT move the address back:
//     device two was seen with it more recently.
//
// Mutation checks: remove the lease-move call in Engine.resolve → step 2
// fails (the address stays on device one); drop the ObservedAt comparison in
// leaseMoves → step 3 fails (the late sighting moves it back); drop the
// obs.DynamicScopes half of the dynamic-scope test → step 2 fails, because
// production carries the posture on the observation, not on the engine.
func TestIntegration_HostObservationIngest_LeaseFollowsTheMAC(t *testing.T) {
	f := newProvisionalFixture(t)
	f.addDHCPSegment()

	t0 := f.now.Add(-3 * time.Hour)
	one := f.ingestARP(leaseMACOne, leaseTestAddr, t0)
	two := f.ingestARP(leaseMACTwo, leaseOtherAddr, t0.Add(time.Minute))
	if one.AssetID == "" || two.AssetID == "" || one.AssetID == two.AssetID {
		t.Fatalf("setup: two ARP sightings produced assets %q and %q, want two distinct assets (outcomes %s, %s)",
			one.AssetID, two.AssetID, one.Outcome, two.Outcome)
	}
	if owner, _ := f.identifierOwner("ip_address", leaseTestAddr); owner != one.AssetID {
		t.Fatalf("setup: %s is owned by %s, want device one %s", leaseTestAddr, owner, one.AssetID)
	}

	// Step 2 — device two now holds the lease.
	movedAt := f.now.Add(-time.Hour)
	moved := f.ingestARP(leaseMACTwo, leaseTestAddr, movedAt)
	if moved.AssetID != two.AssetID || moved.Outcome != string(identity.OutcomeMatched) {
		t.Fatalf("device two's sighting at %s resolved to %q (%s), want a match on device two %s",
			leaseTestAddr, moved.AssetID, moved.Outcome, two.AssetID)
	}
	owner, lastSeen := f.identifierOwner("ip_address", leaseTestAddr)
	if owner != two.AssetID {
		t.Fatalf("%s is still owned by %s after device two was met there directly; want it on device two %s — "+
			"on a DHCP segment the address follows the MAC", leaseTestAddr, owner, two.AssetID)
	}
	if !lastSeen.Equal(movedAt) {
		t.Errorf("the address's last_seen_at = %s, want %s (the sighting that moved it)", lastSeen, movedAt)
	}
	for _, side := range []struct{ name, id string }{{"device one", one.AssetID}, {"device two", two.AssetID}} {
		if n := f.countLeaseMoves(side.id); n != 1 {
			t.Errorf("%s has %d identifier_reassigned/lease_moved history entries, want 1: %v",
				side.name, n, f.historyActions(side.id))
		}
	}
	if !containsAll(f.historyActions(one.AssetID), `"from": "`+one.AssetID+`"`, `"to": "`+two.AssetID+`"`, `"decided_by": "mac_address"`) {
		t.Errorf("device one's lease_moved entry does not name the move: %v", f.historyActions(one.AssetID))
	}

	// Step 3 — a late sighting of device one, made before step 2.
	late := f.ingestARP(leaseMACOne, leaseTestAddr, f.now.Add(-2*time.Hour))
	if late.AssetID != one.AssetID {
		t.Fatalf("setup: the late sighting resolved to %q, want device one %s by its MAC", late.AssetID, one.AssetID)
	}
	if owner, _ := f.identifierOwner("ip_address", leaseTestAddr); owner != two.AssetID {
		t.Fatalf("a late-arriving sighting moved %s back to %s; device two was seen with it more recently", leaseTestAddr, owner)
	}
	if n := f.countLeaseMoves(one.AssetID); n != 1 {
		t.Errorf("device one has %d lease_moved entries after the late sighting, want still 1", n)
	}
	if n := f.assetCount(); n != 2 {
		t.Errorf("%d assets, want 2: a lease moving is not a new device", n)
	}
}

// TestIntegration_HostObservationIngest_AnnouncedVIPDoesNotFollowTheNode is the
// floating VIP on a network that becomes DHCP — the order it happens in when
// a controller's posture reaches a segment that already had a VIP on it.
//
//  1. On a STATIC segment: a host is met by ARP at the VIP address (it holds
//     the address, with a MAC of its own), and two nodes at their own
//     addresses.
//  2. The node announces the VIP ("VIP is-at node's MAC"). The address votes,
//     so the floating-address rule runs: the observation lands on the holder
//     and a hosted_on edge + `floating_address` history are recorded.
//  3. The segment is then marked dynamic.
//  4. At failover the SECOND node announces the VIP. The address can no longer
//     vote, so the frame is a match on that node by MAC, and the holder — a
//     device, with a MAC of its own — would pass every other lease condition.
//     It must keep the VIP: the floating-address history says this address is
//     announced, not leased, whichever node announces it.
//
// Mutation check: drop the AddressAnnounced check in leaseMoves → step 4 moves
// the VIP onto the node and this fails. Make the Postgres AddressAnnounced
// always answer false → same.
func TestIntegration_HostObservationIngest_AnnouncedVIPDoesNotFollowTheNode(t *testing.T) {
	f := newProvisionalFixture(t)
	seg := uuid.New()
	f.exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment,metadata)
	 VALUES($1,$2,'Lab','cidr',$3,true,'production','{}'::jsonb)`, seg, f.tenant, leaseSegmentCIDR)

	const (
		vipAddr   = "203.0.113.230"
		nodeAddr  = "203.0.113.11"
		holderMAC = "00:00:5e:00:53:e6"
	)
	t0 := f.now.Add(-4 * time.Hour)
	holder := f.ingestARP(holderMAC, vipAddr, t0)
	node := f.ingestARP(leaseMACOne, nodeAddr, t0.Add(time.Minute))
	standby := f.ingestARP(leaseMACTwo, "203.0.113.12", t0.Add(2*time.Minute))
	if holder.AssetID == "" || node.AssetID == "" || standby.AssetID == "" ||
		holder.AssetID == node.AssetID || node.AssetID == standby.AssetID {
		t.Fatalf("setup: assets %q, %q, %q, want three", holder.AssetID, node.AssetID, standby.AssetID)
	}

	floating := f.ingestARP(leaseMACOne, vipAddr, t0.Add(time.Hour))
	if floating.AssetID != holder.AssetID {
		t.Fatalf("setup: on a static segment the announcement resolved to %q, want the floating-address rule to land it on "+
			"the holder %s", floating.AssetID, holder.AssetID)
	}
	var edges int
	if err := f.raw.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND from_asset_id=$2 AND to_asset_id=$3 AND type='hosted_on'`,
		f.tenant, holder.AssetID, node.AssetID).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if edges != 1 {
		t.Fatalf("setup: %d hosted_on edges from the holder to the node, want the floating-address rule's 1", edges)
	}

	f.exec(`UPDATE network_segments SET metadata='{"dynamic":true}'::jsonb WHERE tenant_id=$1 AND id=$2`, f.tenant, seg)

	failover := f.ingestARP(leaseMACTwo, vipAddr, t0.Add(2*time.Hour))
	if failover.AssetID != standby.AssetID {
		t.Fatalf("setup: on the now-DHCP segment the announcement resolved to %q, want a match on the standby node %s by its MAC",
			failover.AssetID, standby.AssetID)
	}
	if owner, _ := f.identifierOwner("ip_address", vipAddr); owner != holder.AssetID {
		t.Fatalf("the announced VIP moved to %s; an address with floating-address history is not a lease", owner)
	}
	for _, id := range []string{holder.AssetID, node.AssetID, standby.AssetID} {
		if n := f.countLeaseMoves(id); n != 0 {
			t.Errorf("%s has %d lease_moved entries, want 0", id, n)
		}
	}
}

// TestIntegration_HostObservationIngest_DynamicAddressAloneCreatesNothing is 1c
// through the intake, in the shape D1 makes common: a relayed mDNS
// advertisement whose only name is a rotating UUID-form instance name. Intake
// drops that name as an identifier (it becomes `synthetic_names`), so the
// engine is handed an address and nothing else — on a DHCP segment, where a
// record built from it would absorb the next device given the lease.
//
// Mutation check: remove the 1c guard in provisionalScopeFor → a provisional
// record is created for the bare address and this fails.
func TestIntegration_HostObservationIngest_DynamicAddressAloneCreatesNothing(t *testing.T) {
	f := newProvisionalFixture(t)
	f.addDHCPSegment()

	ho := &hostobs.HostObservation{
		ObservedAt: f.now.Add(-time.Minute),
		Source:     hostobs.SourceMDNS,
		Addresses:  addrsFor(t, "203.0.113.61"),
		FQDNs:      []string{"4f2c9a1e-7b3d-4e8a-9c1f-2d6b8e0a7c35.local"},
		Services:   []string{"_googlecast._tcp"},
		Attributes: map[string]any{"mdns_relayed": true},
	}
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{observationFinding(t, ho)}, "monitoring")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results = %+v, want one", report.Results)
	}
	got := report.Results[0]
	if got.AssetID != "" || got.Outcome != string(identity.OutcomeUnresolved) {
		t.Fatalf("a relayed sighting carrying only a DHCP address resolved to %q (%s); want unresolved with no asset",
			got.AssetID, got.Outcome)
	}
	if n := f.assetCount(); n != 0 {
		t.Fatalf("%d assets, want 0: an address alone on a DHCP segment names no device", n)
	}
	var reasoned int
	if err := f.raw.QueryRow(`SELECT count(*) FROM identity_observations WHERE tenant_id=$1 AND $2 = ANY(admission_reasons)`,
		f.tenant, identity.ReasonDynamicAddressWithoutDeviceBinding).Scan(&reasoned); err != nil {
		t.Fatal(err)
	}
	if reasoned != 1 {
		t.Errorf("%d retained observations carry %q, want 1: the evidence is kept and says why it created nothing",
			reasoned, identity.ReasonDynamicAddressWithoutDeviceBinding)
	}
}
