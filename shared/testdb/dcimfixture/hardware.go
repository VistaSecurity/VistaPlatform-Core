package dcimfixture

// Modules, inventory items and virtual chassis (DCIM row 2.4). Per asset: one
// module bay "Network Module" (position 1) holding a module of the fixture's
// own module type, and two power-supply inventory items ("Power Supply A",
// "Power Supply B", role psu, discovered). Per rack: its first two assets are
// the members of one virtual chassis, at positions 1 and 2, the first the
// master. Set-based SQL, so Scale1's ~150k assets stay fast.

import (
	"context"
	"database/sql"

	"github.com/lib/pq"
)

// HardwareItemsPerAsset is how many inventory items every asset carries.
const HardwareItemsPerAsset = 2

func populateHardware(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 {
		return -1, nil
	}
	var mfr, mt string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO manufacturers (tenant_id, name, slug) VALUES ($1, 'Fixture Modules', 'fixture-modules')
		ON CONFLICT ((COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)), slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, e.Tenant).Scan(&mfr); err != nil {
		return 0, err
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO module_types (tenant_id, manufacturer_id, model, slug, part_number)
		VALUES ($1, $2, 'FX-NM-8X', 'fx-nm-8x', 'FX-NM-8X') RETURNING id`, e.Tenant, mfr).Scan(&mt); err != nil {
		return 0, err
	}
	ids := make([]string, len(e.Assets))
	for i, a := range e.Assets {
		ids[i] = a.ID.String()
	}
	for _, q := range []string{
		`INSERT INTO module_bays (tenant_id, asset_id, name, position, status)
		 SELECT a.tenant_id, a.id, 'Network Module', '1', 'active' FROM assets a WHERE a.tenant_id = $1 AND $2::uuid IS NOT NULL AND a.id = ANY($3::uuid[])`,
		`INSERT INTO modules (tenant_id, asset_id, module_bay_id, module_type_id, serial, source_kind, status)
		 SELECT b.tenant_id, b.asset_id, b.id, $2::uuid, 'FXM-' || substr(b.asset_id::text, 1, 8), 'measured', 'active'
		   FROM module_bays b WHERE b.tenant_id = $1 AND b.asset_id = ANY($3::uuid[])`,
		`INSERT INTO inventory_items (tenant_id, asset_id, name, role_id, part_id, serial, discovered, source_kind, status)
		 SELECT a.tenant_id, a.id, 'Power Supply ' || s.x,
		        (SELECT r.id FROM inventory_item_roles r WHERE r.tenant_id IS NULL AND r.slug = 'psu'),
		        'FX-PWR-715', 'FXP-' || substr(a.id::text, 1, 8) || s.x, true, 'measured', 'active'
		   FROM assets a CROSS JOIN (VALUES ('A'), ('B')) s(x) WHERE a.tenant_id = $1 AND $2::uuid IS NOT NULL AND a.id = ANY($3::uuid[])`,
	} {
		// Every statement takes ($1 tenant, $2 module type, $3 the generated
		// assets — other populators add assets of their own, cloud resources).
		if _, err := tx.ExecContext(ctx, q, e.Tenant, mt, pq.Array(ids)); err != nil {
			return 0, err
		}
	}
	// One chassis per rack: the rack's first two assets, in generation order
	// (the digest is order-sensitive).
	members := map[[2]int][]string{}
	var order [][2]int
	for _, a := range e.Assets {
		k := [2]int{a.Site, a.Rack}
		if _, seen := members[k]; !seen {
			order = append(order, k)
		}
		if len(members[k]) < 2 {
			members[k] = append(members[k], a.ID.String())
		}
	}
	for _, k := range order {
		ids := members[k]
		if len(ids) < 2 {
			continue
		}
		var vc string
		if err := tx.QueryRowContext(ctx, `INSERT INTO virtual_chassis (tenant_id, name, master_asset_id, source_kind)
			VALUES ($1, $2, $3::uuid, 'measured') RETURNING id`, e.Tenant, RackName(k[0], k[1])+"-vc", ids[0]).Scan(&vc); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET virtual_chassis_id = $2::uuid,
			vc_position = CASE WHEN id = $3::uuid THEN 1 ELSE 2 END, vc_priority = CASE WHEN id = $3::uuid THEN 15 ELSE 14 END
			WHERE tenant_id = $1 AND id IN ($3::uuid, $4::uuid)`, e.Tenant, vc, ids[0], ids[1]); err != nil {
			return 0, err
		}
		e.Witness(RackName(k[0], k[1]) + "-vc")
	}
	return len(e.Assets) * HardwareItemsPerAsset, nil
}
