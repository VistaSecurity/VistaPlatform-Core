package query_test

// The IPAM fields on the asset target (QUERY_LANGUAGE §15 D2, DCIM row 1.3)
// over real rows: an asset's addresses, the longest-match prefix of each IN
// ITS VRF, that prefix's VLAN, and the address's VRF.
//
// Mutation: drop the VRF fold from the LATERAL prefix lookup in sql/ipam.go →
// "prefix lookup stays inside the address's VRF" goes red (the global /28
// would answer for the address in VRF blue).

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func ipamRow(t *testing.T, db *sql.DB, q string, args ...any) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(q, args...).Scan(&id); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return id
}

func TestIntegration_QueryIPAMFields(t *testing.T) {
	db := testdb.Connect(t)
	requireInventorySchema(t, db)
	testdb.HoldSchemaShareLock(t, db)
	tenant := testdb.NewTenant(t, db)

	blue := ipamRow(t, db, `INSERT INTO vrfs (tenant_id, name) VALUES ($1, 'blue') RETURNING id`, tenant)
	grp := ipamRow(t, db, `INSERT INTO vlan_groups (tenant_id, name, slug) VALUES ($1, 'g', 'g') RETURNING id`, tenant)
	v10 := ipamRow(t, db, `INSERT INTO vlans (tenant_id, vid, name, group_id) VALUES ($1, 10, 'voice', $2) RETURNING id`, tenant, grp)
	ipamRow(t, db, `INSERT INTO prefixes (tenant_id, prefix, vrf_id, operational_status) VALUES ($1, '10.10.0.0/16', $2, 'container') RETURNING id`, tenant, blue)
	ipamRow(t, db, `INSERT INTO prefixes (tenant_id, prefix, vrf_id, vlan_id, network_type) VALUES ($1, '10.10.0.0/24', $2, $3, 'voice') RETURNING id`, tenant, blue, v10)
	// A MORE specific prefix in the global table must not answer for an
	// address in VRF blue.
	ipamRow(t, db, `INSERT INTO prefixes (tenant_id, prefix, operational_status) VALUES ($1, '10.10.0.0/28', 'deprecated') RETURNING id`, tenant)

	inBlue := ipamRow(t, db, `INSERT INTO ip_addresses (tenant_id, address, vrf_id, dns_name) VALUES ($1, '10.10.0.5/24', $2, 'pbx.corp') RETURNING id`, tenant, blue)
	inGlobal := ipamRow(t, db, `INSERT INTO ip_addresses (tenant_id, address, role) VALUES ($1, '10.10.0.6/28', 'vip') RETURNING id`, tenant)

	pbx := insertAsset(t, db, tenant, "pbx", 0, nil)
	lb := insertAsset(t, db, tenant, "lb", 0, nil)
	bare := insertAsset(t, db, tenant, "no-address", 0, nil)
	if _, err := db.Exec(`UPDATE assets SET primary_ip4_id = $1 WHERE tenant_id = $2 AND id = $3`, inBlue, tenant, pbx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assets SET oob_ip_id = $1 WHERE tenant_id = $2 AND id = $3`, inGlobal, tenant, lb); err != nil {
		t.Fatal(err)
	}

	only := func(t *testing.T, q string, want ...uuid.UUID) {
		t.Helper()
		got := matchIDs(t, db, tenant, q)
		for _, w := range want {
			if !got[w] {
				t.Errorf("%q: missing %s", q, w)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%q: matched %d assets, want %d (%v)", q, len(got), len(want), got)
		}
	}

	t.Run("ip.address is CIDR containment over the asset's addresses", func(t *testing.T) {
		only(t, "ip.address:10.10.0.0/24", pbx, lb)
		only(t, "ip.address:10.10.0.5/32", pbx)
		only(t, "ip.address:192.168.0.0/16")
	})
	t.Run("ip fields", func(t *testing.T) {
		only(t, `ip.dns_name="pbx.corp"`, pbx)
		only(t, "ip.role:vip", lb)
		only(t, "exists(ip.address)", pbx, lb)
	})
	t.Run("prefix lookup stays inside the address's VRF", func(t *testing.T) {
		only(t, "prefix.prefix:10.10.0.0/24", pbx, lb) // lb's /28 is inside 10.10.0.0/24 too
		only(t, "prefix.network_type:voice", pbx)
		only(t, "prefix.status:deprecated", lb) // the global /28 is lb's, never pbx's
	})
	t.Run("vlan and vrf", func(t *testing.T) {
		only(t, "vlan.vid=10", pbx)
		only(t, "vlan.name:voice and vrf.name:blue", pbx)
	})
	t.Run("!= negates the whole EXISTS", func(t *testing.T) {
		// "No address of the asset is in a deprecated prefix" — true for pbx
		// and for an asset with no address at all.
		only(t, "prefix.status != deprecated", pbx, bare)
	})
}

// TestIntegration_QueryInterfaceAddresses: since DCIM row 1.4 the identity
// engine files an asset's observed addresses on its interfaces, never as
// identifier rows. `ip.address`, `id.ip_address` and free text must still
// find the asset by them.
//
// Mutation: drop the interface arm from sql/ipam.go's address set, or the
// ip_addresses arm from the compiler's identifierRows, and the matching
// subtest goes red.
func TestIntegration_QueryInterfaceAddresses(t *testing.T) {
	db := testdb.Connect(t)
	requireInventorySchema(t, db)
	testdb.HoldSchemaShareLock(t, db)
	tenant := testdb.NewTenant(t, db)

	host := insertAsset(t, db, tenant, "iface-host", 0, nil)
	other := insertAsset(t, db, tenant, "iface-other", 0, nil)
	if _, err := db.Exec(testdb.SeedAssetAddressSQL, tenant, host, "10.90.0.5", "tenant", "measured", "sensor:it"); err != nil {
		t.Fatal(err)
	}
	// The other asset once held the address too, and a person rejected it
	// there: no query may find that asset by it (the asset page, which reads
	// identifiersql, does not show it either).
	if _, err := db.Exec(testdb.SeedAssetAddressSQL, tenant, other, "10.90.0.5", "tenant", "measured", "sensor:it"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE ip_addresses SET status = 'rejected'
		 WHERE tenant_id = $1 AND assigned_id IN (SELECT id FROM interfaces WHERE tenant_id = $1 AND asset_id = $2)`,
		tenant, other); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"ip.address:10.90.0.0/24", "id.ip_address:10.90.0.5", `"10.90.0.5"`,
		"identifier:(kind:ip_address value:10.90.0.5)"} {
		got := matchIDs(t, db, tenant, q)
		if len(got) != 1 || !got[host] {
			t.Errorf("%q matched %v, want only the host", q, got)
		}
	}
}
