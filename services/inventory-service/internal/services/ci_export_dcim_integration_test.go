package services

// The DCIM half of the CI export (row 5.7) against a real Postgres populated
// by the DCIM fixture: per class, the exported shape (the allowlisted field
// keys, the structural edges and what they point at), the push scope (an
// unapproved object is not exported), tenant isolation under the RLS app
// role, and paging.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/testdb/dcimfixture"
)

// dcimExportFieldKeys is every field each class may export: the allowlist the
// test holds the queries to. A key outside it fails; so does a class that
// exports none of its identifying keys.
var dcimExportFieldKeys = map[string]map[string]bool{
	"rack":       keySet("name", "site", "location", "facility_id", "status", "serial", "asset_tag", "form_factor", "width", "u_height", "used_units", "utilization"),
	"prefix":     keySet("prefix", "network", "prefix_length", "netmask", "ip_version", "vrf", "vlan", "vlan_vid", "role", "status", "environment", "site"),
	"ip_address": keySet("address", "prefix_length", "ip_version", "dns_name", "mac_address", "vrf", "role", "status", "interface", "asset"),
	"circuit":    keySet("cid", "provider", "type", "status", "commit_rate_kbps", "install_date", "termination_date", "a_site", "z_site"),
	"vlan":       keySet("name", "vid", "site", "status"),
	"interface":  keySet("name", "label", "type", "mac_address", "speed_kbps", "mtu", "enabled", "mgmt_only", "asset"),
	"site":       keySet("name", "slug", "facility", "status", "region", "time_zone", "physical_address", "latitude", "longitude"),
}

// dcimExportRequired are the keys every exported object of the class has.
var dcimExportRequired = map[string][]string{
	"rack":       {"name", "site", "u_height"},
	"prefix":     {"prefix", "network", "prefix_length", "netmask"},
	"ip_address": {"address", "prefix_length", "ip_version"},
	"circuit":    {"cid", "provider", "type", "status"},
	"vlan":       {"name", "vid"},
	"interface":  {"name", "type", "asset"},
	"site":       {"name", "slug", "status"},
}

func keySet(keys ...string) map[string]bool {
	out := map[string]bool{}
	for _, k := range keys {
		out[k] = true
	}
	return out
}

func TestIntegration_CIExport_DCIMClasses(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, owner), "postgres")}
	testdb.HoldSchemaShareLock(t, owner)
	svc := NewCIExportService(app, nil)
	ctx := context.Background()

	tenant, other := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	scale := dcimfixture.Small()
	dcimfixture.Populate(ctx, t, owner, tenant, scale)

	// One IP address assigned to an interface, so the IP-on-adapter edge and
	// the interface/asset fields are exercised; one PENDING prefix, which the
	// push scope must leave out.
	var ifaceID, assetID uuid.UUID
	if err := owner.QueryRow(`SELECT i.id, i.asset_id FROM interfaces i WHERE i.tenant_id = $1 AND i.status = 'active' ORDER BY i.id LIMIT 1`, tenant).Scan(&ifaceID, &assetID); err != nil {
		t.Fatalf("pick an interface: %v", err)
	}
	var assignedIP, pendingPrefix uuid.UUID
	if err := owner.QueryRow(`INSERT INTO ip_addresses (tenant_id, address, assigned_kind, assigned_id, dns_name, mac_address)
		VALUES ($1, '198.51.100.7/24', 'interface', $2, 'mgmt.example.test', '00:11:22:33:44:55') RETURNING id`, tenant, ifaceID).Scan(&assignedIP); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(`INSERT INTO prefixes (tenant_id, prefix, status) VALUES ($1, '203.0.113.0/24', 'pending') RETURNING id`, tenant).Scan(&pendingPrefix); err != nil {
		t.Fatal(err)
	}

	// The fixture's circuits terminate on provider networks; land one A end
	// at a site so the circuit-terminates-at-site edge has something to say.
	var circuitID, siteID uuid.UUID
	if err := owner.QueryRow(`SELECT c.id, (SELECT s.id FROM sites s WHERE s.tenant_id = $1 ORDER BY s.id LIMIT 1)
		FROM circuits c WHERE c.tenant_id = $1 ORDER BY c.id LIMIT 1`, tenant).Scan(&circuitID, &siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE circuit_terminations SET termination_kind = 'site', termination_id = $2
		WHERE circuit_id = $1 AND term_side = 'A'`, circuitID, siteID); err != nil {
		t.Fatal(err)
	}

	exported := map[string]map[uuid.UUID]CIExportDCIMItem{}
	for _, class := range DCIMExportClasses() {
		items, err := svc.ExportDCIM(ctx, tenant, class, uuid.Nil, MaxCIExportPage)
		if err != nil {
			t.Fatalf("export %s: %v", class, err)
		}
		if len(items) == 0 {
			t.Errorf("%s: the fixture tenant exported nothing", class)
			continue
		}
		exported[class] = map[uuid.UUID]CIExportDCIMItem{}
		for _, it := range items {
			exported[class][it.ID] = it
			if it.Category != class || it.DisplayName == "" {
				t.Errorf("%s %s: category %q, display name %q", class, it.ID, it.Category, it.DisplayName)
			}
			for k, v := range it.Fields {
				if !dcimExportFieldKeys[class][k] {
					t.Errorf("%s exports field %q, which is not on its allowlist", class, k)
				}
				if v == "" {
					t.Errorf("%s %s: field %q is empty; an unset field must be absent", class, it.ID, k)
				}
			}
			for _, k := range dcimExportRequired[class] {
				if _, ok := it.Fields[k]; !ok {
					t.Errorf("%s %s has no %q: %v", class, it.ID, k, it.Fields)
				}
			}
		}
	}

	// The edges point at objects the export (or the asset export) holds.
	inScopeAsset := func(id uuid.UUID) bool {
		var ok bool
		_ = owner.QueryRow(`SELECT EXISTS (SELECT 1 FROM v_ci_inventory WHERE id = $1 AND ci_category = 'infrastructure_asset')`, id).Scan(&ok)
		return ok
	}
	edges := map[string]int{}
	for class, items := range exported {
		for _, it := range items {
			for _, r := range it.Relations {
				edges[r.Type]++
				switch r.ToCategory {
				case "infrastructure_asset":
					if !inScopeAsset(r.ToID) {
						t.Errorf("%s %s: edge %s to asset %s, which is not in push scope", class, it.ID, r.Type, r.ToID)
					}
				default:
					if _, ok := exported[r.ToCategory][r.ToID]; !ok {
						t.Errorf("%s %s: edge %s to %s %s, which the export does not hold", class, it.ID, r.Type, r.ToCategory, r.ToID)
					}
				}
			}
		}
	}
	for _, rel := range []string{DCIMRelHouses, DCIMRelInstalledOn, DCIMRelAssignedTo, DCIMRelInVLAN, DCIMRelTerminatesAt} {
		if edges[rel] == 0 {
			t.Errorf("no %s edge was exported (edges: %v)", rel, edges)
		}
	}

	// The assigned address carries its interface and asset, the six-octet MAC
	// and the edge to its interface.
	ip, ok := exported["ip_address"][assignedIP]
	if !ok {
		t.Fatal("the assigned IP address was not exported")
	}
	if ip.Fields["address"] != "198.51.100.7" || ip.Fields["prefix_length"] != "24" || ip.Fields["mac_address"] != "00:11:22:33:44:55" ||
		ip.Fields["interface"] == "" || ip.Fields["asset"] == "" || ip.DisplayName != "mgmt.example.test" {
		t.Errorf("assigned IP exported as %q %v", ip.DisplayName, ip.Fields)
	}
	if len(ip.Relations) != 1 || ip.Relations[0].ToID != ifaceID || ip.Relations[0].Type != DCIMRelAssignedTo {
		t.Errorf("assigned IP relations = %+v, want one %s to %s", ip.Relations, DCIMRelAssignedTo, ifaceID)
	}
	if c := exported["circuit"][circuitID]; c.Fields["a_site"] == "" || len(c.Relations) != 1 || c.Relations[0].ToID != siteID {
		t.Errorf("circuit landed at a site exported as %v %+v", c.Fields, c.Relations)
	}
	if _, leaked := exported["prefix"][pendingPrefix]; leaked {
		t.Error("a pending prefix was exported: only approved prefixes are in push scope")
	}

	// Another tenant sees none of it.
	for _, class := range DCIMExportClasses() {
		items, err := svc.ExportDCIM(ctx, other, class, uuid.Nil, MaxCIExportPage)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 0 {
			t.Errorf("tenant B's %s export holds %d of tenant A's objects", class, len(items))
		}
	}

	// Paging: two pages of one, in id order, cover the first two racks.
	p1, err := svc.ExportDCIM(ctx, tenant, "rack", uuid.Nil, 1)
	if err != nil || len(p1) != 1 {
		t.Fatalf("page 1: %v %d", err, len(p1))
	}
	p2, err := svc.ExportDCIM(ctx, tenant, "rack", p1[0].ID, 1)
	if err != nil || len(p2) != 1 || p2[0].ID.String() <= p1[0].ID.String() {
		t.Fatalf("page 2 after %s: %v %+v", p1[0].ID, err, p2)
	}

	if _, err := svc.ExportDCIM(ctx, tenant, "device", uuid.Nil, 10); err == nil {
		t.Error("an unknown class was answered")
	}
}
