package services

// DB-integration tests for the rack power budget and PDU intake (DCIM
// BUILD_PLAN row 6.2). Skipped unless TEST_DATABASE_URL is set; run with make
// test-integration-db. Services run on the NON-OWNER app role, so RLS is in
// force as in production.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// A rack served by a single-phase and a three-phase feed. Feed A powers PDU 1
// (inlet declares nothing: its draw is its outlets' devices', NetBox
// get_power_draw); feed B powers PDU 2 on three phases, legs A and B. The
// budget sums per feed, per leg (a third of the feed each), per rack; a device
// with power ports but no declared draw is not 0 W; the rack list carries the
// same figure; a rack whose PDU declares more than its feed can supply is
// over budget on the facilities roll-up.
//
// Mutations: drop the aggregated branch (use dp.allocated_draw only) → feed A
// draws 0, red; count only active feeds → (all feeds are active here, so) the
// failed feed C below changes the rack total, red; drop the rpw join from the
// capacity CTE → racks_over_power_budget 0, red.
func TestIntegration_RackPower_Budget(t *testing.T) {
	f := newPowerFix(t)
	rack := f.simpleRack(t, "R1")
	panel := powerID(f.create(t, PowerRoutePanels, map[string]any{"site_id": f.site, "name": "Panel 1"}))
	feedA := powerID(f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": panel, "rack_id": rack, "name": "Feed A"}))
	feedB := powerID(f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": panel, "rack_id": rack, "name": "Feed B",
		"phase": "three-phase", "voltage": 208, "amperage": 30}))

	pdu1, pdu2 := f.asset(t, "pdu-1", uuid.Nil), f.asset(t, "pdu-2", uuid.Nil)
	srv1, srv2, srv3 := f.asset(t, "srv-1", uuid.Nil), f.asset(t, "srv-2", uuid.Nil), f.asset(t, "srv-3", uuid.Nil)
	in1 := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": pdu1, "name": "Inlet"})
	in2 := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": pdu2, "name": "Inlet"})
	o11 := f.comp(t, ComponentPowerOutlet, map[string]any{"asset_id": pdu1, "name": "Outlet 1", "power_port_id": in1})
	o12 := f.comp(t, ComponentPowerOutlet, map[string]any{"asset_id": pdu1, "name": "Outlet 2", "power_port_id": in1})
	o21 := f.comp(t, ComponentPowerOutlet, map[string]any{"asset_id": pdu2, "name": "Outlet 1", "power_port_id": in2, "feed_leg": "A"})
	o22 := f.comp(t, ComponentPowerOutlet, map[string]any{"asset_id": pdu2, "name": "Outlet 2", "power_port_id": in2, "feed_leg": "B"})
	s1 := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": srv1, "name": "PSU1", "maximum_draw": 450, "allocated_draw": 300})
	s2 := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": srv2, "name": "PSU1", "allocated_draw": 500})
	_ = f.comp(t, ComponentPowerPort, map[string]any{"asset_id": srv2, "name": "PSU2"})
	s3a := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": srv3, "name": "PSU1", "allocated_draw": 600})
	s3b := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": srv3, "name": "PSU2", "allocated_draw": 400})
	for _, c := range [][2]uuid.UUID{{s1, o11}, {s2, o12}, {s3a, o21}, {s3b, o22}} {
		f.cable(t, term(dcim.ObjectKindPowerPort, c[0]), term(dcim.ObjectKindPowerOutlet, c[1]))
	}
	f.cable(t, term(dcim.ObjectKindPowerPort, in1), term(dcim.ObjectKindPowerFeed, feedA))
	f.cable(t, term(dcim.ObjectKindPowerPort, in2), term(dcim.ObjectKindPowerFeed, feedB))
	for i, a := range []uuid.UUID{srv1, srv2, pdu1} {
		if _, err := f.place.Place(f.ctx, f.tenant, a, PlaceInput{RackID: rack, Position: float64(10 + 2*i), Face: "front"}); err != nil {
			t.Fatal(err)
		}
	}
	// A PDU collector measured PDU 1's inlet.
	if _, err := f.owner.Exec(`UPDATE power_ports SET measured_draw = 760, measured_at = now() WHERE id = $1`, in1); err != nil {
		t.Fatal(err)
	}

	b, err := f.power.RackPower(f.ctx, f.tenant, rack)
	if err != nil {
		t.Fatal(err)
	}
	if b.FeedCount != 2 || b.AvailablePower != 1920+8646 || b.AllocatedDraw != 1800 || b.Utilization == nil || *b.Utilization != 17.0 {
		t.Fatalf("rack budget %+v", b)
	}
	if b.MeasuredDraw == nil || *b.MeasuredDraw != 760 {
		t.Errorf("rack measured %v, want 760 (beside the budget, never in it)", b.MeasuredDraw)
	}
	byName := map[string]RackPowerFeed{}
	for _, fd := range b.Feeds {
		byName[fd.Name] = fd
	}
	fa, fb := byName["Feed A"], byName["Feed B"]
	if !fa.Aggregated || fa.AllocatedDraw != 800 || fa.MaximumDraw != 450 || fa.RecordedCount != 2 || fa.OutletCount != 2 ||
		fa.Utilization == nil || *fa.Utilization != 41.7 || fa.PowerPort == nil || fa.PowerPort.ID != in1 {
		t.Errorf("feed A %+v", fa)
	}
	if fa.MeasuredDraw == nil || *fa.MeasuredDraw != 760 || len(fa.Legs) != 0 {
		t.Errorf("feed A measured %v legs %v", fa.MeasuredDraw, fa.Legs)
	}
	if fb.AllocatedDraw != 1000 || len(fb.Legs) != 3 {
		t.Fatalf("feed B %+v", fb)
	}
	if l := fb.Legs[0]; l.Leg != "A" || l.AllocatedDraw != 600 || l.AvailablePower != 2882 || l.OutletCount != 1 || l.Utilization == nil || *l.Utilization != 20.8 {
		t.Errorf("leg A %+v", l)
	}
	if l := fb.Legs[2]; l.Leg != "C" || l.AllocatedDraw != 0 || l.OutletCount != 0 {
		t.Errorf("leg C %+v", l)
	}
	devs := map[uuid.UUID]RackPowerDevice{}
	for _, d := range b.Devices {
		devs[d.AssetID] = d
	}
	if len(b.Devices) != 3 {
		t.Fatalf("devices %+v", b.Devices)
	}
	if d := devs[srv1]; d.AllocatedDraw == nil || *d.AllocatedDraw != 300 || d.Share == nil || *d.Share != 2.8 || d.MaximumDraw == nil || *d.MaximumDraw != 450 {
		t.Errorf("srv-1 %+v", d)
	}
	if d := devs[pdu1]; d.PowerPorts != 1 || d.AllocatedDraw != nil || d.Share != nil || d.MeasuredDraw == nil || *d.MeasuredDraw != 760 {
		t.Errorf("pdu-1 declares no draw (not 0 W) and is measured: %+v", d)
	}

	// The rack list carries the same figure; a rack with no feed has none.
	empty := f.simpleRack(t, "R-empty")
	rows, _, err := f.racks.List(f.ctx, f.tenant, "racks", IPAMListParams{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, raw := range rows {
		var r map[string]any
		_ = json.Unmarshal(raw, &r)
		switch fmt.Sprint(r["id"]) {
		case rack.String():
			pu, _ := r["power_utilization"].(map[string]any)
			if fmt.Sprint(pu["utilization"]) != "17" && fmt.Sprint(pu["utilization"]) != "17.0" || fmt.Sprint(pu["allocated_draw"]) != "1800" || fmt.Sprint(pu["feed_count"]) != "2" {
				t.Errorf("rack list power_utilization %v", r["power_utilization"])
			}
			seen++
		case empty.String():
			if r["power_utilization"] != nil {
				t.Errorf("a rack no feed serves has a budget: %v", r["power_utilization"])
			}
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("rack rows seen %d", seen)
	}

	// A failed feed still counts (NetBox counts every feed of the rack).
	_ = powerID(f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": panel, "rack_id": rack, "name": "Feed C", "operational_status": "failed"}))
	if b, err = f.power.RackPower(f.ctx, f.tenant, rack); err != nil || b.AvailablePower != 1920*2+8646 {
		t.Fatalf("with a failed feed: %+v (%v)", b, err)
	}

	// R2: one 1920 VA feed, a PDU whose inlet declares 2500 W — over budget.
	r2 := f.simpleRack(t, "R2")
	feedD := powerID(f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": panel, "rack_id": r2, "name": "Feed D"}))
	pdu3 := f.asset(t, "pdu-3", uuid.Nil)
	in3 := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": pdu3, "name": "Inlet", "allocated_draw": 2500})
	f.cable(t, term(dcim.ObjectKindPowerPort, in3), term(dcim.ObjectKindPowerFeed, feedD))
	if b, err = f.power.RackPower(f.ctx, f.tenant, r2); err != nil || b.Feeds[0].Aggregated || b.Utilization == nil || *b.Utilization != 130.2 {
		t.Fatalf("R2: %+v (%v)", b, err)
	}
	rep, err := NewCapacityService(f.app).Report(f.ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if rep.RackTotals.RacksWithPower != 2 || rep.RackTotals.RacksOverPowerBudget != 1 {
		t.Errorf("capacity totals %+v", rep.RackTotals)
	}
	if len(rep.Sites) != 1 || rep.Sites[0].RacksOverPowerBudget != 1 || rep.Sites[0].RacksWithPower != 2 {
		t.Errorf("capacity sites %+v", rep.Sites)
	}

	// Tenant isolation and the unknown rack.
	tb := testdb.NewTenant(t, f.owner)
	if _, err := f.power.RackPower(f.ctx, tb, rack); err == nil {
		t.Error("tenant B read tenant A's rack budget")
	}
	if _, err := f.power.RackPower(f.ctx, f.tenant, uuid.New()); err == nil {
		t.Error("an unknown rack answered a budget")
	}
}

// pduSighting is a rack PDU's interrogation: an inlet with three legs and
// eight outlets, as the APC collector reports them (snmp_power.go).
func pduSighting(serial string, draw int) identity.Sighting {
	w := func(n int) *int { return &n }
	a := func(f float64) *float64 { return &f }
	var outlets []identity.ObservedPowerOutlet
	for n := 1; n <= 8; n++ {
		name := fmt.Sprintf("Outlet %d", n)
		if n == 8 {
			name = "web-01 PSU A"
		}
		st := "on"
		if n == 3 {
			st = "off"
		}
		outlets = append(outlets, identity.ObservedPowerOutlet{Name: name, Number: n, PowerPort: "Input", State: st, MeasuredDraw: w(40 * n), MeasuredCurrent: a(0.2 * float64(n))})
	}
	return identity.Sighting{
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: interrogationSourcePrefix + "pdu", Mode: identity.ModeActive},
		Channel:     identity.ChannelAuthenticatedSession,
		ObservedAt:  time.Now().UTC(),
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: serial}},
		PowerPorts: []identity.ObservedPowerPort{{Name: "Input", Number: 1, MeasuredDraw: w(draw),
			Legs: []identity.ObservedPowerLeg{{Leg: "A", MeasuredDraw: w(450), MeasuredCurrent: a(2.1)}, {Leg: "B", MeasuredDraw: w(390)}}}},
		PowerOutlets: outlets,
	}
}

// A PDU sighting through the REAL internal sightings intake.
//
//   - First sight of a PDU nobody declared: its inlet and outlets are created
//     measured and pending (the asset waits for approval), each outlet drawing
//     from the inlet, with the readings.
//   - A PDU whose device type was applied ("Power Port 1", "Power Outlet 1..8",
//     declared, the inlet's allocated_draw a person typed): the sighting
//     matches every socket by number, creates nothing, writes only the
//     measured columns (allocated_draw and source_kind stand) and records no
//     object change for a reading; the next run counts the observation.
//   - Once the first PDU is approved, its pending sockets become active.
//
// Mutations: drop the UpsertObservedPower call from IngestSightings → no
// socket, red; drop the by-number match in matchSocket → the declared PDU
// gets nine new sockets, red; write measured_draw into allocated_draw → the
// typed 1000 W is overwritten, red; record the reading through updateTx → an
// object change per run, red.
func TestIntegration_PowerIntake_PDUSighting(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)
	ctx := context.Background()

	serial := "PDU" + uuid.NewString()[:8]
	res, err := svc.IngestSightings(ctx, tenant, []SightingItem{{Sighting: pduSighting(serial, 1230)}})
	if err != nil || res[0].AssetID == "" {
		t.Fatalf("IngestSightings: %+v (%v)", res, err)
	}
	pdu := uuid.MustParse(res[0].AssetID)
	var inlet uuid.UUID
	var inSK, inStatus string
	var inDraw int
	var legs []byte
	if err := raw.QueryRow(`SELECT id, source_kind, status, measured_draw, measured_legs FROM power_ports WHERE tenant_id = $1 AND asset_id = $2`, tenant, pdu).
		Scan(&inlet, &inSK, &inStatus, &inDraw, &legs); err != nil {
		t.Fatalf("the inlet: %v", err)
	}
	if inSK != "measured" || inStatus != "pending" || inDraw != 1230 || len(legs) == 0 {
		t.Errorf("inlet %s %s %d legs %s", inSK, inStatus, inDraw, legs)
	}
	var n, wired, off int
	_ = raw.QueryRow(`SELECT count(*), count(*) FILTER (WHERE power_port_id = $3), count(*) FILTER (WHERE measured_state = 'off')
		FROM power_outlets WHERE tenant_id = $1 AND asset_id = $2 AND source_kind = 'measured' AND status = 'pending'`, tenant, pdu, inlet).Scan(&n, &wired, &off)
	if n != 8 || wired != 8 || off != 1 {
		t.Errorf("outlets %d, drawing from the inlet %d, off %d; want 8, 8, 1", n, wired, off)
	}
	var draw8 int
	var amps8 float64
	_ = raw.QueryRow(`SELECT measured_draw, measured_current FROM power_outlets WHERE asset_id = $1 AND name = 'web-01 PSU A'`, pdu).Scan(&draw8, &amps8)
	if draw8 != 320 || amps8 != 1.6 {
		t.Errorf("outlet 8 reading %d W %v A", draw8, amps8)
	}

	// Approved: the next sighting makes its sockets active.
	if _, err := raw.Exec(`UPDATE assets SET asset_status = 'monitoring' WHERE id = $1`, pdu); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestSightings(ctx, tenant, []SightingItem{{Sighting: pduSighting(serial, 1250)}}); err != nil {
		t.Fatal(err)
	}
	var pending int
	_ = raw.QueryRow(`SELECT (SELECT count(*) FROM power_ports WHERE asset_id = $1 AND status <> 'active') + (SELECT count(*) FROM power_outlets WHERE asset_id = $1 AND status <> 'active')`, pdu).Scan(&pending)
	if pending != 0 {
		t.Errorf("%d sockets still not active after the PDU was approved", pending)
	}

	// The declared PDU: its device type's sockets, the inlet's draw typed.
	serial2 := "PDU" + uuid.NewString()[:8]
	res, err = svc.IngestSightings(ctx, tenant, []SightingItem{{Sighting: identity.Sighting{
		Source:  identity.Source{Kind: identity.SourceMeasured, Ref: interrogationSourcePrefix + "pdu2", Mode: identity.ModeActive},
		Channel: identity.ChannelAuthenticatedSession, ObservedAt: time.Now().UTC(),
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: serial2}},
	}}})
	if err != nil || res[0].AssetID == "" {
		t.Fatalf("IngestSightings: %+v (%v)", res, err)
	}
	pdu2 := uuid.MustParse(res[0].AssetID)
	if _, err := raw.Exec(`UPDATE assets SET asset_status = 'monitoring' WHERE id = $1`, pdu2); err != nil {
		t.Fatal(err)
	}
	var port1 uuid.UUID
	if err := raw.QueryRow(`INSERT INTO power_ports (tenant_id, asset_id, name, type, allocated_draw) VALUES ($1, $2, 'Power Port 1', 'nema-l6-30p', 1000) RETURNING id`,
		tenant, pdu2).Scan(&port1); err != nil {
		t.Fatal(err)
	}
	for k := 1; k <= 8; k++ {
		if _, err := raw.Exec(`INSERT INTO power_outlets (tenant_id, asset_id, name, type, power_port_id, feed_leg) VALUES ($1, $2, $3, 'iec-60320-c13', $4, 'A')`,
			tenant, pdu2, fmt.Sprintf("Power Outlet %d", k), port1); err != nil {
			t.Fatal(err)
		}
	}
	changesFor := func() int {
		var c int
		_ = raw.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND (object_id = $2 OR object_id IN (SELECT id FROM power_outlets WHERE asset_id = $3))`,
			tenant, port1, pdu2).Scan(&c)
		return c
	}
	before := changesFor()
	for run := 1; run <= 2; run++ {
		if _, err := svc.IngestSightings(ctx, tenant, []SightingItem{{Sighting: pduSighting(serial2, 1100+run)}}); err != nil {
			t.Fatal(err)
		}
	}
	var ports, outlets int
	_ = raw.QueryRow(`SELECT (SELECT count(*) FROM power_ports WHERE asset_id = $1), (SELECT count(*) FROM power_outlets WHERE asset_id = $1)`, pdu2).Scan(&ports, &outlets)
	if ports != 1 || outlets != 8 {
		t.Fatalf("the declared PDU has %d ports and %d outlets after two sightings; want 1 and 8 (matched by number)", ports, outlets)
	}
	var alloc, measured, obs int
	var sk string
	_ = raw.QueryRow(`SELECT allocated_draw, measured_draw, source_kind, observation_count FROM power_ports WHERE id = $1`, port1).Scan(&alloc, &measured, &sk, &obs)
	if alloc != 1000 || measured != 1102 || sk != "declared" || obs != 2 {
		t.Errorf("Power Port 1: allocated %d measured %d source %s observations %d; want 1000, 1102, declared, 2", alloc, measured, sk, obs)
	}
	var st8 string
	var d8 int
	_ = raw.QueryRow(`SELECT measured_state, measured_draw FROM power_outlets WHERE asset_id = $1 AND name = 'Power Outlet 8'`, pdu2).Scan(&st8, &d8)
	if st8 != "on" || d8 != 320 {
		t.Errorf("Power Outlet 8 (the PDU's 'web-01 PSU A') %s %d", st8, d8)
	}
	if after := changesFor(); after != before {
		t.Errorf("readings recorded %d object changes; want none", after-before)
	}
}
