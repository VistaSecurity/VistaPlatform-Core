package dcimfixture

// Racks and placement (DCIM row 2.3). DATA_MODEL §12's 5,000 racks at Scale1:
// every site holds RacksPerSite 42U racks `rack-0042-07`, each in the hall its
// assets are in (rack r of a site is in hall r % locationsPerSite, as
// Env.placement puts them), and every asset of the rack is racked bottom-up on
// the front face, one after the other, each taking its device type's u_height
// (1U when the catalogue populator did not run). rack_utilization is filled
// from the placements, as the placement service would leave it.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// RackUHeight is the height of every generated rack.
const RackUHeight = 42

func populateRacks(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	s := e.Scale
	if len(e.Sites) == 0 || len(e.Assets) == 0 {
		return -1, nil
	}
	rows, err := tx.QueryContext(ctx, `
		INSERT INTO racks (tenant_id, site_id, location_id, name, u_height)
		SELECT $1, st.id, l.id, 'rack-' || substr(st.name, 6) || '-' || lpad(r::text, 2, '0'), $4
		  FROM sites st
		  CROSS JOIN generate_series(0, $2 - 1) r
		  JOIN locations l ON l.site_id = st.id AND l.slug = 'hall-' || ((r % $3) + 1)
		 WHERE st.tenant_id = $1
		RETURNING id, name`, e.Tenant, s.RacksPerSite, locationsPerSite, RackUHeight)
	if err != nil {
		return 0, err
	}
	byName := map[string]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			_ = rows.Close()
			return 0, err
		}
		byName[name] = id
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	e.Racks = make([][]uuid.UUID, s.Sites)
	for site := 0; site < s.Sites; site++ {
		for r := 0; r < s.RacksPerSite; r++ {
			id, ok := byName[RackName(site, r)]
			if !ok {
				return 0, fmt.Errorf("rack %s was not written", RackName(site, r))
			}
			e.Racks[site] = append(e.Racks[site], id)
			e.Witness(RackName(site, r))
		}
	}

	// Each asset's height, from its device type when it has one.
	heights := map[uuid.UUID]float64{}
	hrows, err := tx.QueryContext(ctx, `SELECT a.id, COALESCE(dt.u_height, 1)::float8 FROM assets a
		LEFT JOIN device_types dt ON dt.id = a.device_type_id WHERE a.tenant_id = $1`, e.Tenant)
	if err != nil {
		return 0, err
	}
	for hrows.Next() {
		var id uuid.UUID
		var h float64
		if err := hrows.Scan(&id, &h); err != nil {
			_ = hrows.Close()
			return 0, err
		}
		heights[id] = h
	}
	if err := hrows.Close(); err != nil {
		return 0, err
	}
	// Assets are generated rack by rack, slot by slot: stack each rack's
	// slots from U1.
	var ids, racks []string
	var positions []float64
	cursor := map[[2]int]float64{}
	for _, a := range e.Assets {
		k := [2]int{a.Site, a.Rack}
		pos, ok := cursor[k]
		if !ok {
			pos = 1
		}
		h := heights[a.ID]
		if pos+h-1 > RackUHeight {
			continue // the rack is full; the asset stays unracked
		}
		ids = append(ids, a.ID.String())
		racks = append(racks, e.Racks[a.Site][a.Rack].String())
		positions = append(positions, pos)
		cursor[k] = pos + h
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE assets a SET rack_id = p.rack_id, position = p.position, face = 'front'
		  FROM unnest($2::uuid[], $3::uuid[], $4::numeric[]) AS p(id, rack_id, position)
		 WHERE a.tenant_id = $1 AND a.id = p.id`, e.Tenant, pq.Array(ids), pq.Array(racks), pq.Array(positions)); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO rack_utilization (rack_id, tenant_id, used_units, total_units, utilization)
		SELECT r.id, r.tenant_id, COALESCE(u.used, 0), r.u_height, round(COALESCE(u.used, 0) * 100.0 / r.u_height, 2)
		  FROM racks r
		  LEFT JOIN (SELECT a.rack_id, sum(COALESCE(dt.u_height, 1)) AS used
		               FROM assets a LEFT JOIN device_types dt ON dt.id = a.device_type_id
		              WHERE a.tenant_id = $1 AND a.rack_id IS NOT NULL GROUP BY a.rack_id) u ON u.rack_id = r.id
		 WHERE r.tenant_id = $1`, e.Tenant); err != nil {
		return 0, err
	}
	return s.Racks(), nil
}
