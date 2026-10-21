package services

// DB-integration tests for power panels, power feeds and power cabling (DCIM
// BUILD_PLAN row 6.1). Skipped unless TEST_DATABASE_URL is set; run with make
// test-integration-db. Services run on the NON-OWNER app role, so RLS is in
// force as in production.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type powerFix struct {
	*rackFix
	power  *PowerService
	cables *CableService
	comps  *ComponentService
}

func newPowerFix(t *testing.T) *powerFix {
	t.Helper()
	rf := newRackFix(t)
	return &powerFix{rackFix: rf, power: NewPowerService(rf.app), cables: NewCableService(rf.app), comps: NewComponentService(rf.app)}
}

func (f *powerFix) create(t *testing.T, route string, body map[string]any) map[string]any {
	t.Helper()
	m, err := f.tryCreate(route, body)
	if err != nil {
		t.Fatalf("create %s %v: %v", route, body, err)
	}
	return m
}

func (f *powerFix) tryCreate(route string, body map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(body)
	out, err := f.power.Create(f.ctx, f.tenant, route, raw)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(out, &m)
}

func (f *powerFix) patch(route string, id uuid.UUID, body map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(body)
	out, err := f.power.Update(f.ctx, f.tenant, route, id, raw)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(out, &m)
}

func (f *powerFix) comp(t *testing.T, route string, body map[string]any) uuid.UUID {
	t.Helper()
	raw, err := f.comps.Create(f.ctx, f.tenant, route, compBody(t, body))
	if err != nil {
		t.Fatalf("create %s %v: %v", route, body, err)
	}
	return uuid.MustParse(fmt.Sprint(compDecode(t, raw)["id"]))
}

func (f *powerFix) cable(t *testing.T, a, b map[string]any) uuid.UUID {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"a_terminations": []any{a}, "b_terminations": []any{b}, "type": "power"})
	out, err := f.cables.Create(f.ctx, f.tenant, raw)
	if err != nil {
		t.Fatalf("cable %v -> %v: %v", a, b, err)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	return uuid.MustParse(fmt.Sprint(m["id"]))
}

func powerID(m map[string]any) uuid.UUID { return uuid.MustParse(fmt.Sprint(m["id"])) }

// destination is where origin's cached path ends ("" when it has none or it
// is incomplete).
func (f *powerFix) destination(t *testing.T, kind dcim.ObjectKind, id uuid.UUID) string {
	t.Helper()
	r, err := f.cables.Trace(f.ctx, f.tenant, kind, id)
	if err != nil {
		t.Fatalf("trace %s %s: %v", kind, id, err)
	}
	if len(r.Paths) != 1 || r.Paths[0].Destination == nil {
		return ""
	}
	d := r.Paths[0].Destination
	return string(d.Kind) + ":" + d.Name
}

// A panel and a feed: available power is NetBox's (|V| x A x util%, x 1.732
// three-phase); the location must be in the panel's site; the rack in the
// panel's site; a DC supply cannot be three-phase; the list rows carry the
// panel, rack and feed count; a panel cannot leave the site its feeds' racks
// are in.
func TestIntegration_Power_PanelsAndFeeds(t *testing.T) {
	f := newPowerFix(t)
	other := f.newSite(t, "Site B "+uuid.NewString()[:6])
	locB := f.newLocation(t, other, "Hall B")
	if _, err := f.tryCreate(PowerRoutePanels, map[string]any{"site_id": f.site, "location_id": locB, "name": "P1"}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("a location in another site: %v, want invalid", err)
	}
	loc := f.newLocation(t, f.site, "Hall A")
	panel := f.create(t, PowerRoutePanels, map[string]any{"site_id": f.site, "location_id": loc, "name": "Panel 1"})
	if _, err := f.tryCreate(PowerRoutePanels, map[string]any{"site_id": f.site, "name": "Panel 1"}); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("a duplicate panel name in the site: %v, want conflict", err)
	}
	rack := f.simpleRack(t, "R1")
	feed := f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": powerID(panel), "rack_id": rack, "name": "Feed A"})
	if fmt.Sprint(feed["available_power"]) != "1920" || feed["operational_status"] != "active" || feed["phase"] != "single-phase" {
		t.Fatalf("defaults: %v", feed)
	}
	three := f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": powerID(panel), "name": "Feed B",
		"phase": "three-phase", "voltage": 208, "amperage": 30, "type": "redundant"})
	if fmt.Sprint(three["available_power"]) != "8646" {
		t.Fatalf("three-phase 208 V 30 A 80%%: available_power %v, want 8646", three["available_power"])
	}
	for name, body := range map[string]map[string]any{
		"dc three-phase":     {"power_panel_id": powerID(panel), "name": "X1", "supply": "dc", "phase": "three-phase"},
		"zero voltage":       {"power_panel_id": powerID(panel), "name": "X2", "voltage": 0},
		"utilization > 100":  {"power_panel_id": powerID(panel), "name": "X3", "max_utilization": 120},
		"unknown status":     {"power_panel_id": powerID(panel), "name": "X4", "operational_status": "on"},
		"rack in other site": {"power_panel_id": powerID(panel), "name": "X5", "rack_id": f.rack(t, fmt.Sprintf(`{"name":"RB","site_id":%q}`, other))},
	} {
		if _, err := f.tryCreate(PowerRouteFeeds, body); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	dc := f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": powerID(panel), "name": "DC", "supply": "dc", "voltage": -48, "amperage": 10})
	if fmt.Sprint(dc["available_power"]) != "384" {
		t.Fatalf("-48 V DC 10 A 80%%: %v, want 384", dc["available_power"])
	}

	rows, total, err := f.power.List(f.ctx, f.tenant, PowerRouteFeeds, IPAMListParams{Filters: map[string]string{"rack_id": rack.String()}, Limit: 50})
	if err != nil || total != 1 {
		t.Fatalf("feeds on the rack: %d (%v)", total, err)
	}
	var row map[string]any
	_ = json.Unmarshal(rows[0], &row)
	if pp, _ := row["power_panel"].(map[string]any); pp["name"] != "Panel 1" {
		t.Fatalf("list row carries no panel: %v", row)
	}
	if rk, _ := row["rack"].(map[string]any); rk["name"] != "R1" {
		t.Fatalf("list row carries no rack: %v", row)
	}
	if _, total, _ := f.power.List(f.ctx, f.tenant, PowerRouteFeeds, IPAMListParams{Filters: map[string]string{"site_id": f.site.String()}, Limit: 50}); total != 3 {
		t.Fatalf("feeds by site: %d, want 3", total)
	}
	panels, _, err := f.power.List(f.ctx, f.tenant, PowerRoutePanels, IPAMListParams{Filters: map[string]string{"site_id": f.site.String()}, Limit: 50})
	if err != nil || len(panels) != 1 {
		t.Fatalf("panels: %d (%v)", len(panels), err)
	}
	_ = json.Unmarshal(panels[0], &row)
	if fmt.Sprint(row["feed_count"]) != "3" {
		t.Fatalf("panel feed_count %v, want 3", row["feed_count"])
	}

	if _, err := f.patch(PowerRoutePanels, powerID(panel), map[string]any{"site_id": other, "location_id": nil}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("moving a panel away from its feeds' rack: %v, want invalid", err)
	}

	// Tenant isolation: another tenant sees nothing and cannot hang a feed
	// on this tenant's panel.
	tb := testdb.NewTenant(t, f.owner)
	if _, err := f.power.Get(f.ctx, tb, PowerRoutePanels, powerID(panel)); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B read tenant A's panel: %v", err)
	}
	raw, _ := json.Marshal(map[string]any{"power_panel_id": powerID(panel), "name": "Stolen"})
	if _, err := f.power.Create(f.ctx, tb, PowerRouteFeeds, raw); err == nil {
		t.Fatal("tenant B created a feed on tenant A's panel")
	}
}

// Server PSU -> PDU outlet; the outlet draws from the PDU's inlet; the inlet
// is cabled to a feed. The PSU traces through the PDU to the feed — also when
// the inlet is cabled AFTER the PSU (its stored path ended at the outlet and
// did not contain the inlet); clearing the outlet's power port ends the path
// at the outlet; the asset summary sums draws and names the feed; a feed
// cannot cable to an outlet; a rack change moves the feed's termination; a
// feed delete sweeps its end.
//
// Mutation: drop withOutletsOfPorts from cablepath.Through → the PSU's path
// stays at the outlet after the inlet is cabled; drop the power_outlet case
// from componentCableAfterWrite → the PSU still reaches the feed after the
// outlet's power port is cleared.
func TestIntegration_Power_CablingAndTrace(t *testing.T) {
	f := newPowerFix(t)
	rack := f.simpleRack(t, "R1")
	rack2 := f.simpleRack(t, "R2")
	panel := f.create(t, PowerRoutePanels, map[string]any{"site_id": f.site, "name": "Panel 1"})
	feed := powerID(f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": powerID(panel), "rack_id": rack, "name": "Feed A"}))

	server := f.asset(t, "srv-1", uuid.Nil)
	pdu := f.asset(t, "pdu-1", uuid.Nil)
	psu1 := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": server, "name": "PSU1", "type": "iec-60320-c14", "maximum_draw": 500, "allocated_draw": 300})
	psu2 := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": server, "name": "PSU2", "type": "iec-60320-c14"})
	inlet := f.comp(t, ComponentPowerPort, map[string]any{"asset_id": pdu, "name": "Inlet", "type": "nema-l5-30p"})
	out1 := f.comp(t, ComponentPowerOutlet, map[string]any{"asset_id": pdu, "name": "Outlet 1", "type": "iec-60320-c13", "power_port_id": inlet, "feed_leg": "A"})

	f.cable(t, term(dcim.ObjectKindPowerPort, psu1), term(dcim.ObjectKindPowerOutlet, out1))
	if got := f.destination(t, dcim.ObjectKindPowerPort, psu1); got != "power_outlet:Outlet 1" {
		t.Fatalf("before the inlet is cabled: %q, want the outlet", got)
	}
	f.cable(t, term(dcim.ObjectKindPowerPort, inlet), term(dcim.ObjectKindPowerFeed, feed))
	if got := f.destination(t, dcim.ObjectKindPowerPort, psu1); got != "power_feed:Feed A" {
		t.Fatalf("after the inlet is cabled: %q, want the feed", got)
	}
	if got := f.destination(t, dcim.ObjectKindPowerFeed, feed); got != "power_port:Inlet" {
		t.Fatalf("the feed's trace: %q, want the PDU inlet", got)
	}

	sum, err := f.power.AssetPower(f.ctx, f.tenant, server)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.PowerPorts) != 2 || sum.Totals.MaximumDraw != 500 || sum.Totals.AllocatedDraw != 300 || sum.Totals.Recorded != 1 || sum.Totals.Connected != 1 {
		t.Fatalf("server totals %+v (%d ports)", sum.Totals, len(sum.PowerPorts))
	}
	if len(sum.Feeds) != 1 || sum.Feeds[0].ID != feed || sum.Feeds[0].AvailablePower != 1920 || sum.Feeds[0].PowerPanelName != "Panel 1" {
		t.Fatalf("server feeds %+v", sum.Feeds)
	}
	if e := sum.PowerPorts[0].Endpoint; e == nil || e.Kind != dcim.ObjectKindPowerFeed || e.PowerPanelName == nil || *e.PowerPanelName != "Panel 1" {
		t.Fatalf("PSU1 endpoint %+v", sum.PowerPorts[0].Endpoint)
	}
	if sum.PowerPorts[1].Endpoint != nil || sum.PowerPorts[1].PathComplete {
		t.Fatalf("an uncabled PSU claims an endpoint: %+v", sum.PowerPorts[1])
	}
	pduSum, err := f.power.AssetPower(f.ctx, f.tenant, pdu)
	if err != nil {
		t.Fatal(err)
	}
	if len(pduSum.PowerPorts) != 1 || pduSum.PowerPorts[0].Downstream.AllocatedDraw != 300 || pduSum.PowerPorts[0].Downstream.Outlets != 1 ||
		pduSum.PowerPorts[0].Downstream.Connected != 1 {
		t.Fatalf("PDU inlet downstream %+v", pduSum.PowerPorts)
	}
	if len(pduSum.PowerOutlets) != 1 || pduSum.PowerOutlets[0].Endpoint == nil || pduSum.PowerOutlets[0].Endpoint.Name != "PSU1" {
		t.Fatalf("PDU outlet endpoint %+v", pduSum.PowerOutlets)
	}
	_ = psu2

	// The query language reaches the feeds (QUERY_LANGUAGE §15): the server
	// and the PDU both draw from Feed A, through the PDU for the server.
	match := func(q string) map[uuid.UUID]bool {
		t.Helper()
		c, err := query.Compile(q, "asset", query.DefaultCatalog(), query.DefaultOptionsFor(query.DefaultCatalog()))
		if err != nil {
			t.Fatalf("compile %q: %v", q, err)
		}
		out := map[uuid.UUID]bool{}
		testdb.AsTenant(t, f.owner, f.tenant, func(tx *sql.Tx) {
			rows, err := tx.Query("SELECT a.id FROM assets a WHERE a.tenant_id = '"+f.tenant.String()+"' AND "+c.Where, c.Args...)
			if err != nil {
				t.Fatalf("run %q: %v", q, err)
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					t.Fatal(err)
				}
				out[id] = true
			}
		})
		return out
	}
	if got := match(`power_feed.status = active and power_feed.panel = "Panel 1"`); !got[server] || !got[pdu] || len(got) != 2 {
		t.Errorf("power_feed.status/panel: %v", got)
	}
	if got := match(`power_feed.available_power >= 1920 and power_feed.rack = R1`); !got[server] || len(got) != 2 {
		t.Errorf("power_feed.available_power/rack: %v", got)
	}
	if got := match(`power_feed.status = failed`); len(got) != 0 {
		t.Errorf("no feed has failed: %v", got)
	}

	// A feed cables to a power port only.
	out2 := f.comp(t, ComponentPowerOutlet, map[string]any{"asset_id": pdu, "name": "Outlet 2"})
	feed2 := powerID(f.create(t, PowerRouteFeeds, map[string]any{"power_panel_id": powerID(panel), "name": "Feed B"}))
	raw, _ := json.Marshal(map[string]any{"a_terminations": []any{term(dcim.ObjectKindPowerFeed, feed2)}, "b_terminations": []any{term(dcim.ObjectKindPowerOutlet, out2)}})
	if _, err := f.cables.Create(f.ctx, f.tenant, raw); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("feed to outlet: %v, want invalid", err)
	}
	if _, err := f.patch(PowerRouteFeeds, feed, map[string]any{"mark_connected": true}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("mark_connected on a cabled feed: %v, want invalid", err)
	}

	// The feed's termination follows its rack.
	if _, err := f.patch(PowerRouteFeeds, feed, map[string]any{"rack_id": rack2}); err != nil {
		t.Fatal(err)
	}
	var termRack uuid.UUID
	if err := f.owner.QueryRow(`SELECT rack_id FROM cable_terminations WHERE termination_kind = 'power_feed' AND termination_id = $1`, feed).Scan(&termRack); err != nil || termRack != rack2 {
		t.Fatalf("feed termination rack %v (%v), want %v", termRack, err, rack2)
	}

	// Clearing the outlet's power port ends the PSU's path at the outlet.
	if _, err := f.comps.Update(f.ctx, f.tenant, ComponentPowerOutlet, out1, compBody(t, map[string]any{"power_port_id": nil})); err != nil {
		t.Fatal(err)
	}
	if got := f.destination(t, dcim.ObjectKindPowerPort, psu1); got != "power_outlet:Outlet 1" {
		t.Fatalf("after clearing the outlet's power port: %q, want the outlet", got)
	}
	if _, err := f.comps.Update(f.ctx, f.tenant, ComponentPowerOutlet, out1, compBody(t, map[string]any{"power_port_id": inlet})); err != nil {
		t.Fatal(err)
	}
	if got := f.destination(t, dcim.ObjectKindPowerPort, psu1); got != "power_feed:Feed A" {
		t.Fatalf("after restoring the outlet's power port: %q, want the feed", got)
	}

	// Deleting the feed sweeps its end; the PSU no longer reaches a feed.
	if err := f.power.Delete(f.ctx, f.tenant, PowerRouteFeeds, feed); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM cable_terminations WHERE termination_kind = 'power_feed' AND termination_id = $1`, feed).Scan(&n); err != nil || n != 0 {
		t.Fatalf("feed termination left behind: %d (%v)", n, err)
	}
	if got := f.destination(t, dcim.ObjectKindPowerPort, psu1); got == "power_feed:Feed A" {
		t.Fatal("the PSU still reaches the deleted feed")
	}
	// Deleting the panel cascades its remaining feed.
	if err := f.power.Delete(f.ctx, f.tenant, PowerRoutePanels, powerID(panel)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.power.Get(f.ctx, f.tenant, PowerRouteFeeds, feed2); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("feed survived its panel: %v", err)
	}
}
