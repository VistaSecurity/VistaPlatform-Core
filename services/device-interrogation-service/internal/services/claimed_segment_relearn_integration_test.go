package services

// Re-interrogating a firewall must not clobber a person's claim on a range it
// reported ( D8, R4; DCIM row 1.6: the claim is the prefix's source set to
// declared). ensureVLANPrefixes inserts a learned prefix only where none
// exists and writes a DHCP posture only where nobody has said, so the claim
// stays. Pinned against the real sink, under RLS, and against the real
// ownership reader.
//
// It also pins what happens when the firewall stops reporting the range:
// nothing. The learned row is never deleted by interrogation, so the claim
// stands until a person changes it or deletes the prefix.

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
	if got, ok := segmentByCIDR(t, db, tenant, "93.184.219.0/28"); !ok || got.NetworkType != "public" || got.SourceKind != "measured" {
		t.Fatalf("learned prefix = %+v (found %v), want a learned public prefix", got, ok)
	}

	// The claim, as Inventory → Networks writes it: the prefix's source set to
	// declared (recorded in its change log).
	if _, err := db.Exec(`UPDATE prefixes SET source_kind = 'declared' WHERE tenant_id = $1 AND prefix = $2::cidr`, tenant, "93.184.219.0/28"); err != nil {
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
	if got.SourceKind != "declared" || got.DHCP == nil || *got.DHCP {
		t.Fatalf("after re-interrogation = %+v, want the claim kept and the measured posture recorded", got)
	}
	if !inScope() {
		t.Fatal("re-interrogation withdrew the claim's ownership")
	}

	// The firewall stops reporting the range: the row, and the claim, stay.
	persistVLANs(t, sink, tenant, firewall, []map[string]any{{"id": 100, "name": "lan", "subnet": "10.44.0.0/24"}})
	if got, ok := segmentByCIDR(t, db, tenant, "93.184.219.0/28"); !ok || got.SourceKind != "declared" {
		t.Fatalf("after the device stopped reporting the range: %+v (found %v), want the claimed row unchanged", got, ok)
	}
	if !inScope() {
		t.Fatal("a range the device no longer reports lost its claim")
	}
}
