package dcimfixture

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// The device catalogue populator (DCIM BUILD_PLAN row 2.2).
//
// It writes tenant-scoped catalogue rows (the platform rows are seed.sql's,
// which a test database may or may not have): CatalogueManufacturers
// manufacturers with CatalogueTypesPerManufacturer device types each, every
// type carrying Scale.InterfacesPerAsset interface templates named as the
// interfaces populator names them, plus one device role per asset class. Every
// asset is then given a device type (round-robin, by class) and the role of its
// class, so the asset list's device_type / device_role fields and the Hardware
// card have data at scale.
const (
	CatalogueManufacturers        = 5
	CatalogueTypesPerManufacturer = 4
)

// CatalogueDeviceTypes is how many device types the populator writes.
func CatalogueDeviceTypes() int { return CatalogueManufacturers * CatalogueTypesPerManufacturer }

func populateCatalogue(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 {
		return -1, nil
	}
	var types []uuid.UUID
	for m := 0; m < CatalogueManufacturers; m++ {
		name := fmt.Sprintf("Fixture Manufacturer %d", m+1)
		e.Witness(name)
		var mid uuid.UUID
		if err := tx.QueryRowContext(ctx, `INSERT INTO manufacturers (tenant_id, name, slug) VALUES ($1, $2, $3) RETURNING id`,
			e.Tenant, name, fmt.Sprintf("fixture-manufacturer-%d", m+1)).Scan(&mid); err != nil {
			return 0, err
		}
		for d := 0; d < CatalogueTypesPerManufacturer; d++ {
			model := fmt.Sprintf("FX-%d%02d", m+1, d+1)
			e.Witness(model)
			var dt uuid.UUID
			if err := tx.QueryRowContext(ctx, `INSERT INTO device_types (tenant_id, manufacturer_id, model, slug, part_number, u_height)
				VALUES ($1, $2, $3, lower($3), $3, $4) RETURNING id`, e.Tenant, mid, model, 1+d%2).Scan(&dt); err != nil {
				return 0, err
			}
			types = append(types, dt)
		}
	}
	per := e.Scale.InterfacesPerAsset
	if per > 0 {
		names := make([]string, per)
		for p := 0; p < per; p++ {
			names[p], _ = ifnames.Canonical(ifnames.VendorCisco, InterfaceName(p))
		}
		err := copyRows(ctx, tx, "interface_templates", []string{"tenant_id", "device_type_id", "name", "type"},
			len(types)*per, func(i int) []any {
				return []any{e.Tenant, types[i/per], names[i%per], "1000base-t"}
			})
		if err != nil {
			return 0, err
		}
	}
	roles := map[string]uuid.UUID{}
	for _, a := range e.Assets {
		if _, ok := roles[a.Class]; ok {
			continue
		}
		var id uuid.UUID
		if err := tx.QueryRowContext(ctx, `INSERT INTO device_roles (tenant_id, name, slug) VALUES ($1, $2, $3) RETURNING id`,
			e.Tenant, "Fixture "+a.Class, "fixture-"+a.Class).Scan(&id); err != nil {
			return 0, err
		}
		roles[a.Class] = id
	}
	// One UPDATE per (type, role) pair rather than one per asset.
	byPair := map[[2]uuid.UUID][]uuid.UUID{}
	for i, a := range e.Assets {
		k := [2]uuid.UUID{types[i%len(types)], roles[a.Class]}
		byPair[k] = append(byPair[k], a.ID)
	}
	for k, ids := range byPair {
		strs := make([]string, len(ids))
		for i, id := range ids {
			strs[i] = id.String()
		}
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET device_type_id = $2, device_role_id = $3
			WHERE tenant_id = $1 AND id = ANY($4::uuid[])`, e.Tenant, k[0], k[1], pq.Array(strs)); err != nil {
			return 0, err
		}
	}
	return len(types), nil
}
