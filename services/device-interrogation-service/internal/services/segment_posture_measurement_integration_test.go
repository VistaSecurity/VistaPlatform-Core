package services

// What a controller's DHCP answer does to the segment it names ( Phase 1a,
// case C2), through the real ensureVLANSegments over a real Postgres.
//
// Read back two ways: the row's metadata, and what identity's ScopeForAddress
// reports — the second is the one that decides whether a leased address may
// vote, so a test that only read the row could pass while identity still saw a
// static network.

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Measurement_ReachesAnOperatorDeclaredSegmentButNeverOverwritesTheOperator(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	sink := NewObservationSink(db)
	controller := uuid.New()

	// Declared by hand: not created by interrogation, so ensureVLANSegments
	// does not own its row — only the posture it measured.
	var segment string
	if err := db.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata)
		VALUES($1,'Home LAN','cidr','192.0.2.0/24','private','production',true,'{"source":"manual_import"}') RETURNING id::text`, tenant).Scan(&segment); err != nil {
		t.Fatal(err)
	}
	vlans := func(dhcp any) []map[string]any {
		e := map[string]any{"subnet": "192.0.2.1/24", "name": "Controller LAN"}
		if dhcp != nil {
			e["dhcp_enabled"] = dhcp
		}
		return []map[string]any{e}
	}
	read := func() (dyn any, src any, name string) {
		t.Helper()
		var raw []byte
		if err := db.QueryRow(`SELECT name, metadata FROM network_segments WHERE id = $1`, segment).Scan(&name, &raw); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m["dynamic"], m["dynamic_source"], name
	}
	identityDynamic := func() bool {
		t.Helper()
		_, d, err := pgidentity.New(db).ScopeForAddress(ctx, tenant.String(), netip.MustParseAddr("192.0.2.9"), "")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if identityDynamic() {
		t.Fatal("precondition: a silent segment must read as static")
	}

	// 1. The controller says DHCP is on: the operator-declared segment learns it.
	if err := sink.ensureVLANSegments(ctx, tenant, controller, vlans(true)); err != nil {
		t.Fatal(err)
	}
	if dyn, src, name := read(); dyn != true || src != "measured" || name != "Home LAN" {
		t.Fatalf("declared segment after a DHCP-on measurement: dynamic=%v source=%v name=%q", dyn, src, name)
	}
	if !identityDynamic() {
		t.Fatal("the measurement is on the row but identity still sees a static network")
	}

	// 2. The operator says it is static. A later measurement must not undo that.
	if _, err := pgidentity.RecordSegmentPosture(ctx, db, tenant.String(), segment, pgidentity.PostureOperator, false, pgidentity.PostureEvidence{}); err != nil {
		t.Fatal(err)
	}
	if err := sink.ensureVLANSegments(ctx, tenant, controller, vlans(true)); err != nil {
		t.Fatal(err)
	}
	if dyn, src, _ := read(); dyn != false || src != "operator" {
		t.Fatalf("a measurement overwrote the operator's answer: dynamic=%v source=%v", dyn, src)
	}
	if identityDynamic() {
		t.Fatal("identity followed the measurement over the operator")
	}

	// 3. An unknown posture states nothing, whoever is in force.
	if err := sink.ensureVLANSegments(ctx, tenant, controller, vlans(nil)); err != nil {
		t.Fatal(err)
	}
	if dyn, src, _ := read(); dyn != false || src != "operator" {
		t.Fatalf("an unknown posture disturbed the operator's answer: dynamic=%v source=%v", dyn, src)
	}

	// 4. The operator hands it back to automatic: the measurement that arrived
	// while their answer was in force is what takes over.
	if _, err := pgidentity.ClearSegmentPosture(ctx, db, tenant.String(), segment, pgidentity.PostureOperator); err != nil {
		t.Fatal(err)
	}
	if dyn, src, _ := read(); dyn != true || src != "measured" {
		t.Fatalf("clearing the operator did not fall back to the measurement: dynamic=%v source=%v", dyn, src)
	}
	if !identityDynamic() {
		t.Fatal("after falling back, identity still sees a static network")
	}

	// 5. Same rank: the newest measurement wins.
	if err := sink.ensureVLANSegments(ctx, tenant, controller, vlans(false)); err != nil {
		t.Fatal(err)
	}
	if dyn, src, _ := read(); dyn != false || src != "measured" {
		t.Fatalf("the newest measurement did not win: dynamic=%v source=%v", dyn, src)
	}
}

// A segment interrogation created is refreshed as before — the posture just no
// longer arrives by a side door around the rule.
func TestIntegration_Measurement_LearnedSegmentStillCarriesItsMeasurement(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	sink := NewObservationSink(db)
	controller := seedInterrogatedDevice(t, db, tenant, "unifi", "00:1a:2b:3c:4d:5f", "controller")

	if err := sink.ensureVLANSegments(context.Background(), tenant, controller,
		[]map[string]any{{"subnet": "198.51.100.0/24", "name": "IoT", "dhcp_enabled": false}}); err != nil {
		t.Fatal(err)
	}
	seg, ok := segmentByCIDR(t, db, tenant, "198.51.100.0/24")
	if !ok {
		t.Fatal("segment not created")
	}
	if seg.Metadata["dynamic"] != false || seg.Metadata["dynamic_source"] != "measured" || seg.Metadata["dhcp"] != "disabled" {
		t.Fatalf("learned segment metadata = %v", seg.Metadata)
	}
	if ev, _ := seg.Metadata["dynamic_evidence"].(map[string]any); ev["source_asset_id"] != controller.String() {
		t.Fatalf("evidence does not name the controller: %v", seg.Metadata["dynamic_evidence"])
	}
}
