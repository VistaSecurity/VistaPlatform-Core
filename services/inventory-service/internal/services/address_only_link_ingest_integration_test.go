package services

// C1 through the REAL inventory intake: IngestFindingsReport →
// ingestHostObservation → the production engine (svc.identityEngine(), with
// provisional inventory on) → applyHostObservationContext.
//
// The engine refusing to attach a device identifier is half of the rule. The
// other half is everything the intake writes AFTER Resolve onto the
// resolution's asset: the asset context (metadata, ownership, names), the
// host-observation facts (OUI vendor, mDNS services), the segment placement and
// the class proposal. For a sighting linked to an asset by an address alone,
// all of that describes whichever device holds the lease NOW. This test pins
// that none of it lands on the provisional asset the address happens to point
// at.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// assetSnapshot is every column and child-row count the host-observation
// intake can write for an asset.
type assetSnapshot struct {
	displayName, hostname, attributes, metadata, classKey string
	identityStatus, assetStatus, segment, location, owner string
	lastSeen                                              sql.NullTime
	identifiers, facts, relationships, classProposals     int
}

func (f *provisionalFixture) snapshotAsset(assetID string) assetSnapshot {
	f.t.Helper()
	var s assetSnapshot
	if err := f.raw.QueryRow(`
		SELECT COALESCE(display_name,''), COALESCE(hostname,''), COALESCE(attributes::text,''), COALESCE(metadata::text,''),
		       COALESCE(class_key,''), COALESCE(identity_status,''), COALESCE(asset_status::text,''),
		       COALESCE(network_segment_id::text,''), COALESCE(location_id::text,''), COALESCE(asset_ownership::text,''), last_seen_at
		  FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, assetID).
		Scan(&s.displayName, &s.hostname, &s.attributes, &s.metadata, &s.classKey, &s.identityStatus, &s.assetStatus,
			&s.segment, &s.location, &s.owner, &s.lastSeen); err != nil {
		f.t.Fatal(err)
	}
	for _, c := range []struct {
		dst   *int
		query string
	}{
		{&s.identifiers, `SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2`},
		{&s.facts, `SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2`},
		{&s.relationships, `SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND (from_asset_id=$2 OR to_asset_id=$2)`},
		{&s.classProposals, `SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND action LIKE 'class%'`},
	} {
		if err := f.raw.QueryRow(c.query, f.tenant, assetID).Scan(c.dst); err != nil {
			f.t.Fatal(err)
		}
	}
	return s
}

// TestIntegration_HostObservationIngest_AddressOnlyLinkLeavesTheAssetUntouched
// is the C1 shape through the intake: a relayed advert makes a provisional
// laptop at .39; a sensor then decodes an mDNS announcement (not relayed, not a
// device-binding protocol, so it cannot establish anything) from a DIFFERENT
// device that now holds .39 — with its own MAC, name and services.
//
// Mutation check: return the lease holder's asset from the engine's
// leaseOnlyLink branch (`Asset: ref`) and this fails on the facts / context
// written by applyHostObservationContext; remove the branch entirely and it
// fails on the MAC and name attached to the laptop.
func TestIntegration_HostObservationIngest_AddressOnlyLinkLeavesTheAssetUntouched(t *testing.T) {
	f := newProvisionalFixture(t)
	const (
		leaseAddr = "198.51.100.39"
		otherMAC  = "00:00:5e:00:53:39" // RFC 7042 documentation MAC, universally administered
		otherName = "lobby-display"
	)

	advertAt := f.now.Add(-2 * time.Hour)
	laptop, err := f.svc.resolveObservationWith(t.Context(),
		f.relayedAdvertOn(f.segB, "desk-laptop", leaseAddr, f.sensorA, "advert-c1", advertAt), nil)
	if err != nil {
		t.Fatal(err)
	}
	if laptop.Outcome != identity.OutcomeProvisional || laptop.Asset.Zero() {
		t.Fatalf("setup: the relayed advert did not become a provisional asset: %+v", laptop)
	}
	before := f.snapshotAsset(laptop.Asset.ID)

	ho := &hostobs.HostObservation{
		ObservedAt: f.now.Add(-time.Minute),
		Source:     hostobs.SourceMDNS,
		MAC:        otherMAC,
		Addresses:  addrsFor(t, leaseAddr),
		Hostnames:  []string{otherName},
		Services:   []string{"_airplay._tcp", "_raop._tcp"},
		Model:      "DisplayBox 4",
	}
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{observationFinding(t, ho)}, "monitoring")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results = %+v, want one", report.Results)
	}
	got := report.Results[0]
	if got.AssetID != "" {
		t.Errorf("the intake reported asset %s for a sighting linked only by a lease; everything it writes after "+
			"Resolve lands there (outcome %s)", got.AssetID, got.Outcome)
	}
	if got.Outcome != string(identity.OutcomeUnresolved) {
		t.Errorf("outcome = %s, want unresolved", got.Outcome)
	}

	// Checked whatever the report said, so a regression shows WHAT it wrote.
	after := f.snapshotAsset(laptop.Asset.ID)
	if after != before {
		t.Errorf("the provisional laptop changed on another device's sighting:\n before %+v\n after  %+v", before, after)
	}
	if strings.Contains(after.displayName+after.hostname, otherName) {
		t.Errorf("the other device's name reached the laptop: display_name=%q hostname=%q", after.displayName, after.hostname)
	}

	var macOwners int
	if err := f.raw.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND kind='mac_address' AND value=$2`,
		f.tenant, otherMAC).Scan(&macOwners); err != nil {
		t.Fatal(err)
	}
	if macOwners != 0 {
		t.Errorf("the other device's MAC is attached to %d asset(s); it was seen only at a leased address", macOwners)
	}
	if !containsAll(f.historyActions(laptop.Asset.ID), `"address_only_link": true`) {
		t.Errorf("the laptop's timeline does not record the address-only link: %v", f.historyActions(laptop.Asset.ID))
	}
	if n := f.assetCount(); n != 1 {
		t.Errorf("%d assets, want 1: an unresolved sighting creates nothing", n)
	}
}
