package dcimfixture

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// ScaleEnv selects the shape the integration tests populate: "1" is Scale1()
// (make test-dcim-scale and the nightly job), anything else Small().
const ScaleEnv = "DCIM_SCALE"

func scaleFromEnv() Scale {
	if os.Getenv(ScaleEnv) == "1" {
		return Scale1()
	}
	return Small()
}

func count(t *testing.T, db *sql.DB, table string, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`, table), tenant).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestIntegration_DCIMFixture_PopulatesAtScale1(t *testing.T) {
	db := testdb.Connect(t)
	testdb.HoldSchemaShareLock(t, db)
	tenant := testdb.NewTenant(t, db)
	s := scaleFromEnv()
	ctx := context.Background()

	sum := Populate(ctx, t, db, tenant, s)
	t.Logf("populated %d assets in %v (skipped: %v)", len(sum.AssetIDs), sum.Elapsed, sum.Skipped)

	// The scale's assets plus row 4.6's cloud resources.
	if got := count(t, db, "assets", tenant); got != s.Assets()+CloudResources(s.Sites) {
		t.Fatalf("assets = %d, want %d", got, s.Assets()+CloudResources(s.Sites))
	}
	for table, want := range sum.Counts {
		if table == "assets" {
			// Checked above: the cloud populator (row 4.6) adds its resources
			// to the same table.
			continue
		}
		if got := count(t, db, table, tenant); got != want {
			t.Errorf("%s = %d, Summary says %d", table, got, want)
		}
	}
	if got := count(t, db, "prefixes", tenant); got != s.Prefixes() {
		t.Errorf("prefixes = %d, want %d", got, s.Prefixes())
	}
	if got := count(t, db, "ip_addresses", tenant); got != s.IPs() {
		t.Errorf("ip_addresses = %d, want %d", got, s.IPs())
	}
	if got := count(t, db, "vrfs", tenant); got != s.VRFs() {
		t.Errorf("vrfs = %d, want %d", got, s.VRFs())
	}
	// Row 2.1: DATA_MODEL §12's sites, each with its halls, and every asset
	// placed in its site and a hall of it.
	if got := count(t, db, "sites", tenant); got != s.Sites {
		t.Errorf("sites = %d, want %d", got, s.Sites)
	}
	if got := count(t, db, "locations", tenant); got != s.Sites*locationsPerSite {
		t.Errorf("locations = %d, want %d", got, s.Sites*locationsPerSite)
	}
	if got := count(t, db, "regions", tenant); got != regionCount+1 {
		t.Errorf("regions = %d, want %d", got, regionCount+1)
	}
	var unplaced int
	// The cloud populator's resources (row 4.6) are placed by the cloud
	// intake's account site in production, not by this populator's halls.
	if err := db.QueryRow(`SELECT count(*) FROM assets a WHERE a.tenant_id = $1 AND a.class_path NOT LIKE 'cloud_resource.%' AND (a.site_id IS NULL OR a.location_id IS NULL
		OR NOT EXISTS (SELECT 1 FROM locations l WHERE l.id = a.location_id AND l.site_id = a.site_id))`, tenant).Scan(&unplaced); err != nil {
		t.Fatal(err)
	}
	if unplaced != 0 {
		t.Errorf("%d assets are not in a hall of their own site", unplaced)
	}
	if sum.Counts["object_changes"] != 2*s.Assets() {
		t.Errorf("object_changes = %d, want %d", sum.Counts["object_changes"], 2*s.Assets())
	}

	// DATA_MODEL §12: change log page < 200 ms, for a random asset.
	r := rand.New(rand.NewPCG(7, 7))
	id := sum.AssetIDs[r.IntN(len(sum.AssetIDs))]
	start := time.Now()
	page, total, err := changes.List(ctx, db, changes.Filter{TenantID: tenant, ObjectKind: dcim.ObjectKind("asset"), ObjectID: id, Limit: 50})
	took := time.Since(start)
	if err != nil {
		t.Fatalf("changes.List: %v", err)
	}
	if total != 2 || len(page) != 2 {
		t.Fatalf("change page for %s: total=%d len=%d, want 2", id, total, len(page))
	}
	AssertUnder(t, "object_changes page (asset)", took, 200*time.Millisecond)

	// Row 1.2: every asset carries InterfacesPerAsset interfaces, each with its
	// primary MAC row.
	if sum.Counts["interfaces"] != s.Interfaces() {
		t.Errorf("interfaces = %d, want %d", sum.Counts["interfaces"], s.Interfaces())
	}
	if got := count(t, db, "mac_addresses", tenant); got != s.Interfaces() {
		t.Errorf("mac_addresses = %d, want %d", got, s.Interfaces())
	}

	// Row 3.1: a console port and a rear port per asset, FrontPortsPerRear
	// front ports mapped one to each rear position.
	if sum.Counts["console_ports"] != s.Assets() || sum.Counts["rear_ports"] != s.Assets() ||
		sum.Counts["front_ports"] != s.Assets()*FrontPortsPerRear {
		t.Errorf("console/rear/front ports = %d/%d/%d, want %d/%d/%d", sum.Counts["console_ports"], sum.Counts["rear_ports"],
			sum.Counts["front_ports"], s.Assets(), s.Assets(), s.Assets()*FrontPortsPerRear)
	}

	// Row 4.4: a wireless LAN group per site holding three LANs.
	if sum.Counts["wireless_lan_groups"] != s.Sites || sum.Counts["wireless_lans"] != s.Sites*WirelessLANsPerSite {
		t.Errorf("wireless groups/LANs = %d/%d, want %d/%d", sum.Counts["wireless_lan_groups"], sum.Counts["wireless_lans"], s.Sites, s.Sites*WirelessLANsPerSite)
	}

	// Row 2.2: the tenant's device catalogue, and every asset typed.
	// Row 3.2: CablesPerRack cables per rack, both ends terminated, and a
	// cached path for every cabled interface; the patched interfaces trace
	// through two panels to an interface.
	if sum.Counts["cables"] != s.Cables() {
		t.Errorf("cables = %d, want %d", sum.Counts["cables"], s.Cables())
	}
	if got := count(t, db, "cable_terminations", tenant); got != 2*s.Cables() {
		t.Errorf("cable_terminations = %d, want %d", got, 2*s.Cables())
	}
	var racked, sited int
	if err := db.QueryRow(`SELECT count(rack_id), count(site_id) FROM cable_terminations WHERE tenant_id = $1`, tenant).Scan(&racked, &sited); err != nil ||
		racked != 2*s.Cables() || sited != 2*s.Cables() {
		t.Errorf("cable ends with a rack / site = %d / %d (%v), want %d: the denormalised columns are not filled", racked, sited, err, 2*s.Cables())
	}
	if len(sum.PatchedInterfaces) != s.Racks() {
		t.Errorf("patched interfaces = %d, want one per rack (%d)", len(sum.PatchedInterfaces), s.Racks())
	}
	var complete int
	if err := db.QueryRow(`SELECT count(*) FROM cable_paths WHERE tenant_id = $1 AND is_complete AND jsonb_array_length(path) = 9 AND origin_id = $2`,
		tenant, sum.PatchedInterfaces[0]).Scan(&complete); err != nil || complete != 1 {
		t.Errorf("the first patched interface's path is not a complete 9-hop path through two panels (%d, %v)", complete, err)
	}
	if sum.Counts["device_types"] != CatalogueDeviceTypes() {
		t.Errorf("catalogue device types = %d, want %d", sum.Counts["device_types"], CatalogueDeviceTypes())
	}
	if got := count(t, db, "interface_templates", tenant); got != CatalogueDeviceTypes()*s.InterfacesPerAsset {
		t.Errorf("interface_templates = %d, want %d", got, CatalogueDeviceTypes()*s.InterfacesPerAsset)
	}
	// Row 2.8: a contact per site, every asset assigned its site's contact.
	if sum.Counts["contacts"] != s.Sites {
		t.Errorf("contacts = %d, want %d", sum.Counts["contacts"], s.Sites)
	}
	if want := VPNTunnels(len(sum.AssetIDs)); sum.Counts["tunnels"] != want {
		t.Errorf("tunnels = %d, want %d", sum.Counts["tunnels"], want)
	}
	if got := count(t, db, "contact_assignments", tenant); got != s.Assets() {
		t.Errorf("contact_assignments = %d, want %d", got, s.Assets())
	}
	// Row 5.3: the config contexts.
	if sum.Counts["config_contexts"] != ConfigContextsPerTenant {
		t.Errorf("config_contexts = %d, want %d", sum.Counts["config_contexts"], ConfigContextsPerTenant)
	}
	// Row 4.1: circuits, each with both ends.
	if sum.Counts["circuits"] != Circuits(s) {
		t.Errorf("circuits = %d, want %d", sum.Counts["circuits"], Circuits(s))
	}
	if got := count(t, db, "circuit_terminations", tenant); got != 2*Circuits(s) {
		t.Errorf("circuit_terminations = %d, want %d", got, 2*Circuits(s))
	}
	// Row 4.6: the cloud resources, every one hosted on the account.
	if want := CloudRelationships(s.Sites); sum.Counts["asset_relationships"] != want {
		t.Errorf("asset_relationships = %d, want %d", sum.Counts["asset_relationships"], want)
	}
	var hosted int
	if err := db.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND type = 'hosted_on'`, tenant).Scan(&hosted); err != nil || hosted != CloudResources(s.Sites)-1 {
		t.Errorf("hosted_on edges = %d (%v), want %d", hosted, err, CloudResources(s.Sites)-1)
	}
	// Cloud resources carry no device type (a device type is hardware's).
	var untyped int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND device_type_id IS NULL AND class_path NOT LIKE 'cloud_resource.%'`, tenant).Scan(&untyped); err != nil || untyped != 0 {
		t.Errorf("assets without a device type: %d (%v), want 0", untyped, err)
	}

	// Row 4.2: one cluster per site, hosts in each site's first rack, VMs (with
	// a virtual disk each) in its second.
	if sum.Counts["clusters"] != s.Sites {
		t.Errorf("clusters = %d, want %d", sum.Counts["clusters"], s.Sites)
	}
	var hosts, vms, disks int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM cluster_hosts WHERE tenant_id = $1),
		(SELECT count(*) FROM assets WHERE tenant_id = $1 AND cluster_id IS NOT NULL),
		(SELECT count(*) FROM virtual_disks WHERE tenant_id = $1)`, tenant).Scan(&hosts, &vms, &disks); err != nil {
		t.Fatal(err)
	}
	if hosts == 0 || vms == 0 || disks != vms {
		t.Errorf("cluster hosts %d, VMs %d, virtual disks %d — want hosts and VMs, one disk per VM", hosts, vms, disks)
	}
	// Row 2.3: DATA_MODEL §12's racks, each in its assets' hall, every asset
	// racked inside its rack with no two overlapping, and the utilisation
	// cache filled.
	if sum.Counts["racks"] != s.Racks() || count(t, db, "racks", tenant) != s.Racks() {
		t.Errorf("racks = %d, want %d", sum.Counts["racks"], s.Racks())
	}
	if got := count(t, db, "rack_utilization", tenant); got != s.Racks() {
		t.Errorf("rack_utilization = %d, want %d", got, s.Racks())
	}
	var bad int
	if err := db.QueryRow(`
		SELECT count(*) FROM assets a JOIN racks r ON r.id = a.rack_id
		  LEFT JOIN device_types dt ON dt.id = a.device_type_id
		 WHERE a.tenant_id = $1 AND (a.site_id <> r.site_id OR a.location_id IS DISTINCT FROM r.location_id
		    OR a.position < r.starting_unit OR a.position + COALESCE(dt.u_height, 1) > r.starting_unit + r.u_height
		    OR EXISTS (SELECT 1 FROM assets b LEFT JOIN device_types bt ON bt.id = b.device_type_id
		                WHERE b.tenant_id = a.tenant_id AND b.rack_id = a.rack_id AND b.id <> a.id
		                  AND b.position < a.position + COALESCE(dt.u_height, 1) AND a.position < b.position + COALESCE(bt.u_height, 1)))`,
		tenant).Scan(&bad); err != nil || bad != 0 {
		t.Errorf("racked assets outside their rack, its site/hall, or overlapping: %d (%v), want 0", bad, err)
	}

	// Row 2.4: a module bay with a module and two inventory items per asset,
	// a two-member virtual chassis per rack.
	if got := count(t, db, "inventory_items", tenant); sum.Counts["inventory_items"] != s.Assets()*HardwareItemsPerAsset || got != s.Assets()*HardwareItemsPerAsset {
		t.Errorf("inventory items = %d (counted %d), want %d", got, sum.Counts["inventory_items"], s.Assets()*HardwareItemsPerAsset)
	}
	if got := count(t, db, "modules", tenant); got != s.Assets() {
		t.Errorf("modules = %d, want %d", got, s.Assets())
	}
	if got := count(t, db, "virtual_chassis", tenant); got != s.Racks() {
		t.Errorf("virtual chassis = %d, want one per rack (%d)", got, s.Racks())
	}
}

func TestIntegration_DCIMFixture_Deterministic(t *testing.T) {
	db := testdb.Connect(t)
	testdb.HoldSchemaShareLock(t, db)
	ctx := context.Background()
	a := Populate(ctx, t, db, testdb.NewTenant(t, db), Small())
	b := Populate(ctx, t, db, testdb.NewTenant(t, db), Small())
	if a.Digest != b.Digest {
		t.Fatalf("same seed, different digests: %s vs %s", a.Digest, b.Digest)
	}
	if !slices.Equal(a.AssetNames, b.AssetNames) || !slices.Equal(a.AssetIDs, b.AssetIDs) {
		t.Fatal("same seed, different name/id sets")
	}
	other := Small()
	other.Seed = 2
	c := Populate(ctx, t, db, testdb.NewTenant(t, db), other)
	if c.Digest == a.Digest {
		t.Fatal("different seed produced the same digest; the seed is not driving generation")
	}
}

func TestIntegration_DCIMFixture_SkipsMissingTables(t *testing.T) {
	db := testdb.Connect(t)
	testdb.HoldSchemaShareLock(t, db)
	tenant := testdb.NewTenant(t, db)
	ran := false
	pops := []Populator{
		{Name: "assets", Requires: []string{"assets"}, Run: populateAssets},
		{Name: "future_table", Requires: []string{"dcimfixture_no_such_table"}, Run: func(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
			ran = true
			_, err := tx.ExecContext(ctx, `SELECT 1 FROM dcimfixture_no_such_table`) // errors if the guard is gone
			return 0, err
		}},
	}
	sum := populate(context.Background(), t, db, tenant, Small(), pops)
	if ran {
		t.Fatal("populator for a missing table ran")
	}
	if len(sum.Skipped) != 1 || sum.Skipped[0] != "future_table: table dcimfixture_no_such_table does not exist" {
		t.Fatalf("Skipped = %v", sum.Skipped)
	}
	if sum.Counts["assets"] != Small().Assets() {
		t.Fatalf("assets = %d", sum.Counts["assets"])
	}
}
