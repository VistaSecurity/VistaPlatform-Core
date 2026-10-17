package ipam_test

// Schema-level guards for the IPAM tables (BUILD_PLAN row 1.3): RLS on the
// tenant tables and the catalogues, and the identity indexes that make "the
// same prefix twice in one VRF" impossible. They drive the real schema as the
// non-owner app role, so a dropped policy or index goes red here.

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// try runs one statement under a savepoint so a refused write does not abort
// the surrounding (always rolled back) transaction.
func try(t *testing.T, tx *sql.Tx, q string, args ...any) error {
	t.Helper()
	if _, err := tx.Exec(`SAVEPOINT s`); err != nil {
		t.Fatal(err)
	}
	_, err := tx.Exec(q, args...)
	if err != nil {
		if _, rerr := tx.Exec(`ROLLBACK TO SAVEPOINT s`); rerr != nil {
			t.Fatal(rerr)
		}
		return err
	}
	_, _ = tx.Exec(`RELEASE SAVEPOINT s`)
	return nil
}

func count(t *testing.T, tx *sql.Tx, q string, args ...any) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func setup(t *testing.T) (*sql.DB, uuid.UUID, uuid.UUID) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)
	return db, testdb.NewTenant(t, db), testdb.NewTenant(t, db)
}

func TestIntegration_Prefixes_RLS(t *testing.T) {
	db, a, b := setup(t)
	var id uuid.UUID
	if err := db.QueryRow(`INSERT INTO prefixes (tenant_id, prefix) VALUES ($1, '10.20.0.0/16') RETURNING id`, a).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM prefixes WHERE id = $1`, id) })

	testdb.AsTenant(t, db, a, func(tx *sql.Tx) {
		if n := count(t, tx, `SELECT count(*) FROM prefixes WHERE id = $1`, id); n != 1 {
			t.Fatalf("owner tenant sees %d rows", n)
		}
	})
	testdb.AsTenant(t, db, b, func(tx *sql.Tx) {
		if n := count(t, tx, `SELECT count(*) FROM prefixes WHERE id = $1`, id); n != 0 {
			t.Fatalf("another tenant sees the prefix (%d rows)", n)
		}
		if err := try(t, tx, `INSERT INTO prefixes (tenant_id, prefix) VALUES ($1, '10.21.0.0/16')`, a); err == nil {
			t.Fatal("tenant B inserted a prefix into tenant A (WITH CHECK missing)")
		}
		if err := try(t, tx, `UPDATE prefixes SET description = 'x' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	})
	testdb.AsRoleNoTenant(t, db, func(tx *sql.Tx) {
		if n := count(t, tx, `SELECT count(*) FROM prefixes`); n != 0 {
			t.Fatalf("no tenant context sees %d prefixes", n)
		}
	})
	var desc sql.NullString
	_ = db.QueryRow(`SELECT description FROM prefixes WHERE id = $1`, id).Scan(&desc)
	if desc.Valid {
		t.Fatal("tenant B's UPDATE reached tenant A's prefix")
	}
}

func TestIntegration_IPAddresses_RLS(t *testing.T) {
	db, a, b := setup(t)
	var id uuid.UUID
	if err := db.QueryRow(`INSERT INTO ip_addresses (tenant_id, address) VALUES ($1, '10.20.0.5/24') RETURNING id`, a).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM ip_addresses WHERE id = $1`, id) })
	testdb.AsTenant(t, db, b, func(tx *sql.Tx) {
		if n := count(t, tx, `SELECT count(*) FROM ip_addresses WHERE id = $1`, id); n != 0 {
			t.Fatalf("another tenant sees the address")
		}
		if err := try(t, tx, `INSERT INTO ip_addresses (tenant_id, address) VALUES ($1, '10.20.0.6/24')`, a); err == nil {
			t.Fatal("cross-tenant insert accepted")
		}
		// The composite FK refuses a gateway / NAT reference into another
		// tenant even for a row the writer owns.
		var own uuid.UUID
		if err := tx.QueryRow(`INSERT INTO ip_addresses (tenant_id, address) VALUES ($1, '10.9.9.9/32') RETURNING id`, b).Scan(&own); err != nil {
			t.Fatal(err)
		}
		if err := try(t, tx, `UPDATE ip_addresses SET nat_inside_id = $1 WHERE id = $2`, id, own); err == nil {
			t.Fatal("an address referenced another tenant's address")
		}
	})
	testdb.AsTenant(t, db, a, func(tx *sql.Tx) {
		if n := count(t, tx, `SELECT count(*) FROM ip_addresses WHERE id = $1`, id); n != 1 {
			t.Fatalf("owner sees %d", n)
		}
	})
}

func TestIntegration_IPAM_CataloguesReadableNotWritable(t *testing.T) {
	db, a, b := setup(t)
	testdb.AsTenant(t, db, a, func(tx *sql.Tx) {
		if n := count(t, tx, `SELECT count(*) FROM rirs WHERE tenant_id IS NULL`); n < 8 {
			t.Fatalf("platform RIRs visible: %d", n)
		}
		if n := count(t, tx, `SELECT count(*) FROM prefix_roles WHERE tenant_id IS NULL`); n < 7 {
			t.Fatalf("platform prefix roles visible: %d", n)
		}
		if _, err := tx.Exec(`DELETE FROM rirs WHERE slug = 'arin'`); err != nil {
			t.Fatal(err)
		}
		if n := count(t, tx, `SELECT count(*) FROM rirs WHERE slug = 'arin' AND tenant_id IS NULL`); n != 1 {
			t.Fatal("a tenant deleted a platform RIR")
		}
		if _, err := tx.Exec(`UPDATE prefix_roles SET weight = 1 WHERE slug = 'guest' AND tenant_id IS NULL`); err != nil {
			t.Fatal(err)
		}
		if n := count(t, tx, `SELECT count(*) FROM prefix_roles WHERE slug = 'guest' AND weight = 1`); n != 0 {
			t.Fatal("a tenant edited a platform prefix role")
		}
		if err := try(t, tx, `INSERT INTO rirs (tenant_id, name, slug) VALUES (NULL, 'Mine', 'mine')`); err == nil {
			t.Fatal("a tenant created a platform RIR")
		}
		if err := try(t, tx, `INSERT INTO rirs (tenant_id, name, slug) VALUES ($1, 'Mine', 'mine')`, a); err != nil {
			t.Fatalf("own RIR refused: %v", err)
		}
	})
	_ = b
}

func TestIntegration_Prefixes_IdentityUniqueWithinVRF_GlobalIsNullVRF(t *testing.T) {
	db, a, b := setup(t)
	testdb.AsTenant(t, db, a, func(tx *sql.Tx) {
		var vrf uuid.UUID
		if err := tx.QueryRow(`INSERT INTO vrfs (tenant_id, name) VALUES ($1, 'blue') RETURNING id`, a).Scan(&vrf); err != nil {
			t.Fatal(err)
		}
		mustOK := func(q string, args ...any) {
			t.Helper()
			if err := try(t, tx, q, args...); err != nil {
				t.Fatal(err)
			}
		}
		mustOK(`INSERT INTO prefixes (tenant_id, prefix) VALUES ($1, '10.0.0.0/24')`, a)
		// Global is ONE table: NULL vrf_id twice is a duplicate, not "two unknowns".
		if err := try(t, tx, `INSERT INTO prefixes (tenant_id, prefix) VALUES ($1, '10.0.0.0/24')`, a); err == nil || !strings.Contains(err.Error(), "prefixes_identity_uniq") {
			t.Fatalf("duplicate global prefix accepted: %v", err)
		}
		// The same prefix in a VRF is a different prefix.
		mustOK(`INSERT INTO prefixes (tenant_id, prefix, vrf_id) VALUES ($1, '10.0.0.0/24', $2)`, a, vrf)
		if err := try(t, tx, `INSERT INTO prefixes (tenant_id, prefix, vrf_id) VALUES ($1, '10.0.0.0/24', $2)`, a, vrf); err == nil {
			t.Fatal("duplicate prefix within a VRF accepted")
		}
		// A rejected row is outside identity.
		mustOK(`INSERT INTO prefixes (tenant_id, prefix, status) VALUES ($1, '10.0.0.0/24', 'rejected')`, a)
		// A cidr with host bits is refused by the type; the service normalises.
		if err := try(t, tx, `INSERT INTO prefixes (tenant_id, prefix) VALUES ($1, '10.0.1.5/24')`, a); err == nil {
			t.Fatal("cidr accepted host bits")
		}
	})
	// Identity is per tenant.
	testdb.AsTenant(t, db, b, func(tx *sql.Tx) {
		if err := try(t, tx, `INSERT INTO prefixes (tenant_id, prefix) VALUES ($1, '10.0.0.0/24')`, b); err != nil {
			t.Fatalf("another tenant's identical prefix refused: %v", err)
		}
	})
}

func TestIntegration_VLAN_VidUniquePerGroup(t *testing.T) {
	db, a, _ := setup(t)
	testdb.AsTenant(t, db, a, func(tx *sql.Tx) {
		var g1, g2 uuid.UUID
		if err := tx.QueryRow(`INSERT INTO vlan_groups (tenant_id, name, slug) VALUES ($1, 'g1', 'g1') RETURNING id`, a).Scan(&g1); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(`INSERT INTO vlan_groups (tenant_id, name, slug) VALUES ($1, 'g2', 'g2') RETURNING id`, a).Scan(&g2); err != nil {
			t.Fatal(err)
		}
		if err := try(t, tx, `INSERT INTO vlans (tenant_id, vid, name, group_id) VALUES ($1, 10, 'a', $2)`, a, g1); err != nil {
			t.Fatal(err)
		}
		if err := try(t, tx, `INSERT INTO vlans (tenant_id, vid, name, group_id) VALUES ($1, 10, 'b', $2)`, a, g1); err == nil || !strings.Contains(err.Error(), "vlans_group_vid_uniq") {
			t.Fatalf("duplicate vid in one group accepted: %v", err)
		}
		if err := try(t, tx, `INSERT INTO vlans (tenant_id, vid, name, group_id) VALUES ($1, 10, 'c', $2)`, a, g2); err != nil {
			t.Fatalf("same vid in another group refused: %v", err)
		}
		var site uuid.UUID
		if err := tx.QueryRow(`INSERT INTO sites (tenant_id, name, slug) VALUES ($1, 'vlan site', 'vlan-site') RETURNING id`, a).Scan(&site); err != nil {
			t.Fatal(err)
		}
		if err := try(t, tx, `INSERT INTO vlans (tenant_id, vid, name, site_id) VALUES ($1, 20, 's', $2)`, a, site); err != nil {
			t.Fatal(err)
		}
		if err := try(t, tx, `INSERT INTO vlans (tenant_id, vid, name, site_id) VALUES ($1, 20, 's2', $2)`, a, site); err == nil {
			t.Fatal("duplicate vid in one site accepted")
		}
		for _, vid := range []int{0, 4095} {
			if err := try(t, tx, `INSERT INTO vlans (tenant_id, vid, name) VALUES ($1, $2, 'x')`, a, vid); err == nil {
				t.Fatalf("vid %d accepted", vid)
			}
		}
	})
}
