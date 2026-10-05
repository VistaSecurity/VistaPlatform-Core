package services

// Re-interrogating a firewall must not clobber a person's claim on a range it
// reported ( D8, R4). ensureVLANSegments refreshes the rows it learned
// with `metadata || <its own keys>`, which leaves every other key alone — the
// claim among them. This pins that against the real sink, under RLS, and
// against the real ownership reader, so a refresh rewritten as a whole-blob
// replace (or one that started writing the claim key) fails here.
//
// It also pins what happens when the firewall stops reporting the range:
// nothing. The learned row is never deleted by interrogation, so the claim
// stands until a person revokes it or deletes the segment.

import (
	"database/sql"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ClaimedLearnedSegment_SurvivesReinterrogation(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)
	tenant := testdb.NewTenant(t, db)
	firewall := seedInterrogatedDevice(t, db, tenant, "fortinet", "00:09:0f:00:00:21", "fw-dmz")
	sink := NewObservationSink(testdb.ConnectAsAppRole(t, db))
	dmz := map[string]any{"id": 210, "name": "dmz", "subnet": "93.184.219.0/28", "gateway": "93.184.219.1"}

	persistVLANs(t, sink, tenant, firewall, []map[string]any{dmz})
	if got, ok := segmentByCIDR(t, db, tenant, "93.184.219.0/28"); !ok || got.NetworkType != "public" || got.Metadata["source"] != "interrogation" {
		t.Fatalf("learned segment = %+v (found %v), want a learned public segment", got, ok)
	}

	// The claim, as inventory-service's claim action writes it.
	if _, err := db.Exec(`UPDATE network_segments SET metadata = metadata || jsonb_build_object($3::text,
		'{"by":"00000000-0000-0000-0000-000000000001","by_name":"Ada Admin","at":"2026-10-01T12:00:00Z"}'::jsonb)
		WHERE tenant_id = $1 AND value = $2`, tenant, "93.184.219.0/28", dispatchguard.SegmentClaimKey); err != nil {
		t.Fatal(err)
	}

	inScope := func() bool {
		var allowed bool
		testdb.AsTenant(t, db, tenant, func(tx *sql.Tx) {
			scope, err := dispatchguard.LoadTargetScope(tx, tenant.String())
			if err != nil {
				t.Fatal(err)
			}
			allowed = scope.Authorize("93.184.219.5") == nil
		})
		return allowed
	}
	if !inScope() {
		t.Fatal("the claimed range is not in scope before re-interrogation; the test's premise is wrong")
	}

	// Re-interrogation — this time the device also answers DHCP, which takes
	// the posture path that rewrites metadata through its own SQL.
	relearned := map[string]any{"id": 210, "name": "dmz-renamed-on-device", "subnet": "93.184.219.0/28", "gateway": "93.184.219.1", "dhcp_enabled": false}
	persistVLANs(t, sink, tenant, firewall, []map[string]any{relearned})
	got, _ := segmentByCIDR(t, db, tenant, "93.184.219.0/28")
	claim, _ := got.Metadata[dispatchguard.SegmentClaimKey].(map[string]any)
	if claim["by"] != "00000000-0000-0000-0000-000000000001" || got.Metadata["source"] != "interrogation" || got.Metadata["dhcp"] != "disabled" {
		t.Fatalf("after re-interrogation metadata = %v, want the claim kept beside the refreshed learned keys", got.Metadata)
	}
	if !inScope() {
		t.Fatal("re-interrogation withdrew the claim's ownership")
	}

	// The firewall stops reporting the range: the row, and the claim, stay.
	persistVLANs(t, sink, tenant, firewall, []map[string]any{{"id": 100, "name": "lan", "subnet": "10.44.0.0/24"}})
	if got, ok := segmentByCIDR(t, db, tenant, "93.184.219.0/28"); !ok || got.Metadata[dispatchguard.SegmentClaimKey] == nil {
		t.Fatalf("after the device stopped reporting the range: %+v (found %v), want the claimed row unchanged", got, ok)
	}
	if !inScope() {
		t.Fatal("a range the device no longer reports lost its claim")
	}
}
