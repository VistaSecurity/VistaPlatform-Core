package dcimfixture

// Regions, site groups, sites and locations (DCIM row 2.1). DATA_MODEL §12's
// 500 sites at Scale1: every site `site-0042` is in one of regionCount
// regions (each beneath a "World" root) and one of siteGroupCount site
// groups, and holds locationsPerSite halls. Assets are placed in their site
// (populateAssets reads Env.Sites) and in the hall their rack is in.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

const (
	regionCount      = 5
	siteGroupCount   = 3
	locationsPerSite = 2
)

// RegionName, SiteGroupName and HallName are the stable names.
func RegionName(i int) string    { return fmt.Sprintf("region-%02d", i) }
func SiteGroupName(i int) string { return fmt.Sprintf("group-%02d", i) }
func HallName(site, hall int) string {
	return fmt.Sprintf("hall-%04d-%d", site, hall+1)
}

func populateSites(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	s := e.Scale
	var world uuid.UUID
	if err := tx.QueryRowContext(ctx, `INSERT INTO regions (tenant_id, name, slug) VALUES ($1, 'World', 'world') RETURNING id`, e.Tenant).Scan(&world); err != nil {
		return 0, err
	}
	e.Witness("World")
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO regions (tenant_id, name, slug, parent_id)
		SELECT $1, 'region-' || lpad(i::text, 2, '0'), 'region-' || lpad(i::text, 2, '0'), $3 FROM generate_series(0, $2 - 1) i`,
		e.Tenant, regionCount, world); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO site_groups (tenant_id, name, slug)
		SELECT $1, 'group-' || lpad(i::text, 2, '0'), 'group-' || lpad(i::text, 2, '0') FROM generate_series(0, $2 - 1) i`,
		e.Tenant, siteGroupCount); err != nil {
		return 0, err
	}
	for i := 0; i < regionCount; i++ {
		e.Witness(RegionName(i))
	}
	for i := 0; i < siteGroupCount; i++ {
		e.Witness(SiteGroupName(i))
	}
	rows, err := tx.QueryContext(ctx, `
		INSERT INTO sites (tenant_id, name, slug, region_id, group_id, facility, time_zone)
		SELECT $1, 'site-' || lpad(s::text, 4, '0'), 'site-' || lpad(s::text, 4, '0'), r.id, g.id, 'DC' || s, 'UTC'
		  FROM generate_series(0, $2 - 1) s
		  JOIN regions r ON r.tenant_id = $1 AND r.name = 'region-' || lpad((s % $3)::text, 2, '0')
		  JOIN site_groups g ON g.tenant_id = $1 AND g.name = 'group-' || lpad((s % $4)::text, 2, '0')
		RETURNING id, name`, e.Tenant, s.Sites, regionCount, siteGroupCount)
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
	e.Sites = make([]uuid.UUID, s.Sites)
	for i := range e.Sites {
		e.Sites[i] = byName[SiteName(i)]
		e.Witness(SiteName(i))
	}
	rows, err = tx.QueryContext(ctx, `
		INSERT INTO locations (tenant_id, site_id, name, slug)
		SELECT $1, st.id, 'hall-' || substr(st.name, 6) || '-' || h, 'hall-' || h
		  FROM sites st CROSS JOIN generate_series(1, $2) h
		 WHERE st.tenant_id = $1
		RETURNING id, name`, e.Tenant, locationsPerSite)
	if err != nil {
		return 0, err
	}
	halls := map[string]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			_ = rows.Close()
			return 0, err
		}
		halls[name] = id
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	e.Locations = make([][]uuid.UUID, s.Sites)
	for i := range e.Locations {
		for h := 0; h < locationsPerSite; h++ {
			e.Locations[i] = append(e.Locations[i], halls[HallName(i, h)])
			e.Witness(HallName(i, h))
		}
	}
	// The count is the sites table's, as Summary.Counts is keyed by table;
	// regions, site groups and locations are asserted on their own.
	return s.Sites, nil
}

// placement is an asset's (site_id, location_id), nil when the sites
// populator did not run.
func (e *Env) placement(a Asset) (any, any) {
	if a.Site >= len(e.Sites) {
		return nil, nil
	}
	var loc any
	if halls := e.Locations[a.Site]; len(halls) > 0 {
		loc = halls[a.Rack%len(halls)]
	}
	return e.Sites[a.Site], loc
}
