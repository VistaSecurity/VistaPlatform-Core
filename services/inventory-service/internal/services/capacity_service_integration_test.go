package services

// DB-integration tests for the facilities capacity roll-up (DCIM gap 6).
// Skipped unless TEST_DATABASE_URL is set; run with make test-integration-db.
// The service runs on the NON-OWNER app role, so RLS is in force exactly as in
// production.
//
// One hand-built tenant pins every figure, including both threshold boundaries
// (exactly 80 and exactly 95 are NOT over), the empty-rack, deprecated-rack,
// reservation, virtual-interface, router, archived-prefix and no-address
// cases; a second tenant proves RLS; the budget test runs the roll-up on the
// DATA_MODEL §12 fixture (Small by default, Scale1 with DCIM_SCALE=1).

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/testdb/dcimfixture"
)

func near(a, b float64) bool { return math.Abs(a-b) < 0.005 }

func TestIntegration_Capacity_RollUp(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	other := testdb.NewTenant(t, owner)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	siteA := uuid.MustParse(testdb.EnsureSite(t, owner, tenant, "Site A").(string))
	siteB := uuid.MustParse(testdb.EnsureSite(t, owner, tenant, "Site B").(string))

	// ---- racks --------------------------------------------------------
	rack := func(name string, site uuid.UUID, status string, used, total, pct *float64) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := owner.QueryRow(`INSERT INTO racks (tenant_id, name, site_id, u_height, operational_status) VALUES ($1,$2,$3,10,$4) RETURNING id`,
			tenant, name, site, status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if used != nil {
			exec(`INSERT INTO rack_utilization (rack_id, tenant_id, used_units, total_units, utilization) VALUES ($1,$2,$3,$4,$5)`, id, tenant, *used, *total, *pct)
		}
		return id
	}
	f := func(v float64) *float64 { return &v }
	rack("r80", siteA, "active", f(8), f(10), f(80))
	rack("r90", siteA, "active", f(9), f(10), f(90))
	rack("r95", siteB, "active", f(9.5), f(10), f(95))
	rack("r100", siteB, "active", f(10), f(10), f(100))
	empty := rack("empty", siteA, "active", nil, nil, nil)
	rack("gone", siteA, "deprecated", f(1), f(10), f(10))
	// Units 1-3 reserved (3 is named twice), 99 is outside the rack's range.
	exec(`INSERT INTO rack_reservations (tenant_id, rack_id, units, description) VALUES ($1,$2,'{1,2,3}','a'), ($1,$2,'{3,99}','b')`, tenant, empty)

	// ---- ports --------------------------------------------------------
	switchID := func(name string) uuid.UUID {
		id := ifaceSeedAsset(t, owner, tenant, "monitoring")
		exec(`UPDATE assets SET hostname=$2, display_name=$2 WHERE id=$1`, id, name)
		return id
	}
	var cable uuid.UUID
	if err := owner.QueryRow(`INSERT INTO cables (tenant_id) VALUES ($1) RETURNING id`, tenant).Scan(&cable); err != nil {
		t.Fatal(err)
	}
	// The cable the cabled port sits on is confirmed, so it is not a never-confirmed one.
	exec(`UPDATE cables SET lldp_confirmed_at = now() WHERE id = $1`, cable)
	iface := func(asset uuid.UUID, name, typ string, enabled, marked bool, cabled bool) {
		t.Helper()
		var cid any
		if cabled {
			cid = cable
		}
		exec(`INSERT INTO interfaces (tenant_id, asset_id, name, type, enabled, mark_connected, cable_id, cable_end) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tenant, asset, name, typ, enabled, marked, cid, func() any {
				if cabled {
					return "A"
				}
				return nil
			}())
	}
	s1 := switchID("sw-one")
	iface(s1, "g1", "1000base-t", true, false, true)    // cabled
	iface(s1, "g2", "1000base-t", true, true, false)    // marked connected
	iface(s1, "g3", "1000base-t", false, false, false)  // disabled: not free
	iface(s1, "g4", "1000base-t", true, false, false)   // free
	iface(s1, "v1", "virtual", true, false, false)      // not a port
	iface(s1, "w1", "ieee802.11ac", true, false, false) // not a port
	s2 := switchID("sw-two")
	iface(s2, "g1", "1000base-t", true, false, false)
	iface(s2, "g2", "1000base-t", true, false, false)
	router := switchID("rt-one")
	exec(`UPDATE assets SET class_key='router', class_path='hardware.network.router' WHERE id=$1`, router)
	iface(router, "g1", "1000base-t", true, false, false)

	// ---- prefixes -----------------------------------------------------
	var vrf uuid.UUID
	if err := owner.QueryRow(`INSERT INTO vrfs (tenant_id, name) VALUES ($1,'blue') RETURNING id`, tenant).Scan(&vrf); err != nil {
		t.Fatal(err)
	}
	prefix := func(cidr string, v any, status string, ips int, util float64, withUtil bool) {
		t.Helper()
		var id uuid.UUID
		if err := owner.QueryRow(`INSERT INTO prefixes (tenant_id, prefix, vrf_id, status) VALUES ($1,$2,$3,$4) RETURNING id`, tenant, cidr, v, status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if withUtil {
			exec(`INSERT INTO prefix_utilization (prefix_id, tenant_id, ip_count, utilization) VALUES ($1,$2,$3,$4)`, id, tenant, ips, util)
		}
	}
	prefix("10.0.0.0/24", nil, "active", 244, 96, true)
	prefix("10.0.1.0/24", nil, "active", 200, 80, true)
	prefix("10.0.2.0/24", nil, "active", 217, 85, true)
	prefix("10.0.3.0/24", nil, "active", 0, 0, false) // nothing recorded
	prefix("10.0.0.0/30", vrf, "active", 4, 100, true)
	prefix("2001:db8::/64", nil, "active", 5, 50, true)
	prefix("10.9.0.0/16", nil, "archived", 60000, 99, true) // not live

	// ---- cables -------------------------------------------------------
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	days := func(d int) time.Time { return now.AddDate(0, 0, -d) }
	cab := func(label, opStatus, status, source string, confirmed bool, created time.Time) {
		t.Helper()
		var lldp any
		if confirmed {
			lldp = now
		}
		exec(`INSERT INTO cables (tenant_id, label, operational_status, status, source_kind, lldp_confirmed_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			tenant, label, opStatus, status, source, lldp, created)
	}
	cab("c1", "connected", "active", "declared", false, days(1))
	cab("c2", "connected", "active", "declared", true, days(1))
	cab("c3", "connected", "active", "measured", false, days(1))
	cab("c4", "planned", "active", "declared", false, days(31))
	cab("c5", "planned", "active", "declared", false, days(91))
	cab("c6", "planned", "active", "declared", false, days(30)) // exactly 30: not over
	cab("c7", "planned", "active", "declared", false, days(5))
	cab("c8", "decommissioning", "active", "declared", false, days(1))
	cab("c9", "connected", "pending", "inferred", false, days(1))
	cab("c10", "planned", "archived", "declared", false, days(400))

	svc := NewCapacityService(app)
	svc.now = func() time.Time { return now }
	rep, err := svc.Report(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}

	// racks
	rt := rep.RackTotals
	if rt.Racks != 5 || rt.TotalUnits != 50 || rt.UsedUnits != 36.5 || rt.ReservedUnits != 3 || !near(rt.FreeUnits, 2+1+7+0.5+0) ||
		rt.RacksOver80 != 3 || rt.RacksOver95 != 1 || rep.SitesTotal != 2 {
		t.Errorf("rack totals wrong (80 and 95 are not over; deprecated excluded; 3 distinct reserved units): %+v sites=%d", rt, rep.SitesTotal)
	}
	if len(rep.Sites) != 2 || rep.Sites[0].SiteName != "Site B" {
		t.Fatalf("sites not ordered fullest first: %+v", rep.Sites)
	}
	sb, sa := rep.Sites[0], rep.Sites[1]
	if sb.Racks != 2 || sb.TotalUnits != 20 || sb.UsedUnits != 19.5 || !near(sb.FreeUnits, 0.5) || !near(sb.Utilization, 97.5) || sb.RacksOver80 != 2 || sb.RacksOver95 != 1 {
		t.Errorf("Site B: %+v", sb)
	}
	// total 10+10+10 (the empty rack falls back to its u_height 10)
	if sa.Racks != 3 || sa.TotalUnits != 30 || sa.UsedUnits != 17 || sa.ReservedUnits != 3 || !near(sa.FreeUnits, 2+1+7) || !near(sa.Utilization, 56.67) || sa.RacksOver80 != 1 || sa.RacksOver95 != 0 {
		t.Errorf("Site A: %+v", sa)
	}
	var names []string
	for _, r := range rep.RacksTop {
		names = append(names, r.RackName)
	}
	if strings.Join(names, ",") != "r100,r95,r90,r80,empty" {
		t.Errorf("fullest racks: %v", names)
	}

	// ports
	p := rep.Ports
	if p.Switches != 2 || p.Total != 6 || p.Cabled != 1 || p.MarkedConnected != 1 || p.Free != 3 {
		t.Errorf("ports (router, virtual and wireless excluded; disabled is not free): %+v", p)
	}
	if len(p.FewestFree) != 2 || p.FewestFree[0].Name != "sw-one" || p.FewestFree[0].Free != 1 || p.FewestFree[0].Total != 4 || p.FewestFree[1].Free != 2 {
		t.Errorf("fewest free: %+v", p.FewestFree)
	}

	// prefixes
	px := rep.Prefixes
	if px.Total != 6 || px.NoAddressesRecorded != 1 || px.Over80 != 3 || px.Over95 != 2 {
		t.Errorf("prefix counts (80 is not over; archived excluded): %+v", px)
	}
	if len(px.Fullest) != 5 || px.Fullest[0].Prefix != "10.0.0.0/30" || px.Fullest[0].VRFName == nil || *px.Fullest[0].VRFName != "blue" || px.Fullest[0].Size != "4" ||
		px.Fullest[1].Prefix != "10.0.0.0/24" || px.Fullest[1].VRFName != nil || px.Fullest[1].Size != "256" {
		t.Errorf("fullest prefixes: %+v", px.Fullest)
	}
	if last := px.Fullest[4]; last.Prefix != "2001:db8::/64" || last.Size != "18446744073709551616" {
		t.Errorf("IPv6 size: %+v", last)
	}

	// cables
	c := rep.Cables
	if c.ByStatus.Connected != 4 || c.ByStatus.Planned != 4 || c.ByStatus.Decommissioning != 1 || c.ProposedPending != 1 ||
		c.PlannedOver30Days != 2 || c.PlannedOver90Days != 1 || c.DeclaredNeverConfirmed != 1 {
		t.Errorf("cables (exactly 30 days is not over; archived and pending excluded): %+v", c)
	}
	if len(c.OldestPlanned) != 2 || *c.OldestPlanned[0].Label != "c5" || c.OldestPlanned[0].AgeDays != 91 || *c.OldestPlanned[1].Label != "c4" || c.OldestPlanned[1].AgeDays != 31 {
		t.Errorf("oldest planned: %+v", c.OldestPlanned)
	}

	// RLS: another tenant sees none of it, and its empty lists are arrays.
	rep2, err := svc.Report(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rep2)
	if rep2.RackTotals.Racks != 0 || rep2.Ports.Switches != 0 || rep2.Prefixes.Total != 0 || rep2.Cables.ByStatus.Planned != 0 || strings.Contains(string(raw), "null") {
		t.Errorf("tenant B sees tenant A's data, or an empty list serialised as null: %s", raw)
	}
}

// The roll-up must answer in under 500 ms on DATA_MODEL §12's tenant; the
// median of five reads is recorded (informative on PRs, enforced nightly).
func TestIntegration_Capacity_Budget(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	testdb.HoldSchemaShareLock(t, owner)
	scale := dcimfixture.Small()
	if os.Getenv("DCIM_SCALE") == "1" {
		scale = dcimfixture.Scale1()
	}
	ctx := context.Background()
	sum := dcimfixture.Populate(ctx, t, owner, tenant, scale)
	if sum.Counts["racks"] != scale.Racks() || sum.Counts["cables"] != scale.Cables() {
		t.Fatalf("fixture wrote %d racks / %d cables, want %d / %d (skipped %v)", sum.Counts["racks"], sum.Counts["cables"], scale.Racks(), scale.Cables(), sum.Skipped)
	}
	for _, tbl := range []string{"racks", "rack_utilization", "rack_reservations", "sites", "assets", "interfaces", "prefixes", "prefix_utilization", "cables", "vrfs"} {
		if _, err := owner.Exec(`ANALYZE ` + tbl); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewCapacityService(app)
	var rep CapacityReport
	ipamMedian(t, "facilities capacity roll-up", 500*time.Millisecond, func() error {
		var err error
		rep, err = svc.Report(ctx, tenant)
		return err
	})
	t.Logf("roll-up on %d racks / %d prefixes / %d cables: switches=%d ports=%d sites=%d/%d", rep.RackTotals.Racks, rep.Prefixes.Total, scale.Cables(),
		rep.Ports.Switches, rep.Ports.Total, len(rep.Sites), rep.SitesTotal)
	if rep.RackTotals.Racks != scale.Racks() || rep.SitesTotal != scale.Sites || rep.Ports.Switches == 0 || rep.Prefixes.Total != scale.Prefixes() ||
		len(rep.RacksTop) != 10 || len(rep.Sites) > 200 {
		t.Errorf("fixture roll-up shape wrong: racks %d sites %d switches %d prefixes %d top %d", rep.RackTotals.Racks, rep.SitesTotal, rep.Ports.Switches, rep.Prefixes.Total, len(rep.RacksTop))
	}
}
