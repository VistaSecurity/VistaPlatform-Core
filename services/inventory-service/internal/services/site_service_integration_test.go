package services

// DCIM row 2.1: regions, site groups, sites and locations. Skips without
// TEST_DATABASE_URL (make test-integration-db; nightly test-backend).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func siteFixture(t *testing.T) (*SiteService, *captureRecorder, uuid.UUID, *database.DB) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewSiteService(db)
	rec := &captureRecorder{}
	svc.SetChangeRecorder(rec)
	return svc, rec, tenant, db
}

func mustSite(t *testing.T, svc *SiteService, tenant uuid.UUID, in models.SiteInput) *models.Site {
	t.Helper()
	s, err := svc.CreateSite(context.Background(), tenant, uuid.Nil, in)
	if err != nil {
		t.Fatalf("create site %v: %v", in.Name, err)
	}
	return s
}

func mustLocation(t *testing.T, svc *SiteService, tenant, site uuid.UUID, parent *uuid.UUID, name string) *models.Location {
	t.Helper()
	l, err := svc.CreateLocation(context.Background(), tenant, uuid.Nil, models.LocationInput{SiteID: &site, ParentID: parent, Name: sp(name)})
	if err != nil {
		t.Fatalf("create location %s: %v", name, err)
	}
	return l
}

// RLS on all four tables under the app role: a tenant reads only its own rows
// and cannot write a row owned by another tenant (USING doubles as WITH
// CHECK). Dropping any one of the four policies turns its table red.
func TestIntegration_Sites_RLSOnAllFourTables(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	app := testdb.ConnectAsAppRole(t, raw)
	a, b := testdb.NewTenant(t, raw), testdb.NewTenant(t, raw)

	as := func(tenant uuid.UUID, fn func(tx *sqlx.Tx) error) error {
		tx, err := sqlx.NewDb(app, "postgres").Beginx()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	siteA := uuid.New()
	if err := as(a, func(tx *sqlx.Tx) error {
		for _, q := range []string{
			`INSERT INTO regions (tenant_id, name, slug) VALUES ($1, 'Europe', 'europe')`,
			`INSERT INTO site_groups (tenant_id, name, slug) VALUES ($1, 'Branches', 'branches')`,
		} {
			if _, e := tx.Exec(q, a); e != nil {
				return e
			}
		}
		if _, e := tx.Exec(`INSERT INTO sites (id, tenant_id, name, slug) VALUES ($2, $1, 'HQ', 'hq')`, a, siteA); e != nil {
			return e
		}
		_, e := tx.Exec(`INSERT INTO locations (tenant_id, site_id, name, slug) VALUES ($1, $2, 'Hall 1', 'hall-1')`, a, siteA)
		return e
	}); err != nil {
		t.Fatalf("insert as own tenant: %v", err)
	}
	for _, table := range []string{"regions", "site_groups", "sites", "locations"} {
		var n int
		_ = as(b, func(tx *sqlx.Tx) error { return tx.Get(&n, `SELECT COUNT(*) FROM `+table) })
		if n != 0 {
			t.Errorf("tenant B sees %d of tenant A's %s", n, table)
		}
		_ = as(a, func(tx *sqlx.Tx) error { return tx.Get(&n, `SELECT COUNT(*) FROM `+table) })
		if n != 1 {
			t.Errorf("tenant A sees %d %s, want 1", n, table)
		}
	}
	for table, q := range map[string]string{
		"regions":     `INSERT INTO regions (tenant_id, name, slug) VALUES ($1, 'Smuggled', 'smuggled')`,
		"site_groups": `INSERT INTO site_groups (tenant_id, name, slug) VALUES ($1, 'Smuggled', 'smuggled')`,
		"sites":       `INSERT INTO sites (tenant_id, name, slug) VALUES ($1, 'Smuggled', 'smuggled')`,
	} {
		if err := as(b, func(tx *sqlx.Tx) error { _, e := tx.Exec(q, a); return e }); err == nil {
			t.Errorf("tenant B inserted a %s row owned by tenant A", table)
		}
	}
	if err := as(b, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`INSERT INTO locations (tenant_id, site_id, name, slug) VALUES ($1, $2, 'Smuggled', 'smuggled')`, a, siteA)
		return e
	}); err == nil {
		t.Error("tenant B inserted a locations row owned by tenant A")
	}
}

// The location-belongs-to-the-asset's-site rule, through the asset write path
// a person's edit takes (AssetService.UpdateAsset → ResolveAssetPlacement).
// Remove the site comparison in ValidateAssetPlacement and the mismatched pair
// is stored.
func TestIntegration_Sites_AssetLocationMustBeInTheAssetsSite(t *testing.T) {
	svc, rec, tenant, db := siteFixture(t)
	assets := NewAssetService(db)
	assets.SetSiteService(svc)
	hq := mustSite(t, svc, tenant, models.SiteInput{Name: sp("HQ")})
	dc := mustSite(t, svc, tenant, models.SiteInput{Name: sp("DC")})
	room := mustLocation(t, svc, tenant, hq.ID, nil, "Hall 2")
	cage := mustLocation(t, svc, tenant, dc.ID, nil, "Cage 1")

	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status) VALUES($1,$2,'a.example.test','server','hardware.computer.server','monitoring')`, id, tenant); err != nil {
		t.Fatal(err)
	}
	str := func(u uuid.UUID) *string { v := u.String(); return &v }
	placement := func() (string, string) {
		got, err := assets.GetAssetByID(tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		s, l := "", ""
		if got.Site != nil {
			s = got.Site.Name
		}
		if got.Location != nil {
			l = got.Location.Path
		}
		return s, l
	}

	// A location in another site is refused, and nothing is written.
	if _, _, err := assets.UpdateAsset(tenant, id, models.AssetInput{SiteID: str(hq.ID), LocationID: str(cage.ID)}, uuid.Nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("site HQ with DC's cage: %v, want ErrInvalidInput", err)
	}
	if s, l := placement(); s != "" || l != "" {
		t.Fatalf("a refused placement was written: (%q, %q)", s, l)
	}
	// The matching pair is stored, and the asset reads Site › Location.
	if _, _, err := assets.UpdateAsset(tenant, id, models.AssetInput{SiteID: str(hq.ID), LocationID: str(room.ID)}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if s, l := placement(); s != "HQ" || l != "HQ / Hall 2" {
		t.Fatalf("placement = (%q, %q), want (HQ, HQ / Hall 2)", s, l)
	}
	// Changing only the location to one in another site is refused too.
	if _, _, err := assets.UpdateAsset(tenant, id, models.AssetInput{LocationID: str(cage.ID)}, uuid.Nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("DC's cage under HQ: %v, want ErrInvalidInput", err)
	}
	// Moving the site drops a location that is not in it.
	if _, _, err := assets.UpdateAsset(tenant, id, models.AssetInput{SiteID: str(dc.ID)}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if s, l := placement(); s != "DC" || l != "" {
		t.Errorf("after moving to DC: (%q, %q), want (DC, no location)", s, l)
	}
	// Clearing the site clears both.
	if _, _, err := assets.UpdateAsset(tenant, id, models.AssetInput{SiteID: sp("")}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if s, l := placement(); s != "" || l != "" {
		t.Errorf("after clearing: (%q, %q)", s, l)
	}
	// A location alone places the asset in that location's site.
	if _, _, err := assets.UpdateAsset(tenant, id, models.AssetInput{LocationID: str(cage.ID)}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if s, l := placement(); s != "DC" || l != "DC / Cage 1" {
		t.Errorf("location alone: (%q, %q), want (DC, DC / Cage 1)", s, l)
	}
	// Each accepted move is on the asset's Changes record.
	moves := 0
	for _, c := range rec.got {
		if c.ObjectKind == dcim.ObjectKindAsset && c.ObjectID == id {
			moves++
		}
	}
	if moves != 4 {
		t.Errorf("recorded %d asset placement changes, want 4", moves)
	}
}

// Site delete: refused while assets are in it, reassigned when asked.
// Remove the SiteInUseError check and the first delete succeeds, orphaning
// the asset's placement.
func TestIntegration_Sites_DeleteRefusesWithAssets_ReassignsWhenAsked(t *testing.T) {
	svc, _, tenant, db := siteFixture(t)
	ctx := context.Background()
	hq := mustSite(t, svc, tenant, models.SiteInput{Name: sp("HQ")})
	dc := mustSite(t, svc, tenant, models.SiteInput{Name: sp("DC")})
	hall := mustLocation(t, svc, tenant, hq.ID, nil, "Hall 1")
	asset := uuid.New()
	if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,site_id,location_id) VALUES($1,$2,'h','server','hardware.computer.server','monitoring',$3,$4)`, asset, tenant, hq.ID, hall.ID); err != nil {
		t.Fatal(err)
	}
	var prefix uuid.UUID
	if err := db.QueryRow(`INSERT INTO prefixes (tenant_id, prefix, scope_kind, scope_id) VALUES ($1, '198.51.100.0/24', 'location', $2) RETURNING id`, tenant, hall.ID).Scan(&prefix); err != nil {
		t.Fatal(err)
	}
	var inUse *SiteInUseError
	if err := svc.DeleteSite(ctx, tenant, uuid.Nil, hq.ID, nil); !errors.As(err, &inUse) || inUse.Assets != 1 {
		t.Fatalf("delete with an asset in the site: %v, want SiteInUseError{1}", err)
	}
	if err := svc.DeleteSite(ctx, tenant, uuid.Nil, hq.ID, &hq.ID); !errors.Is(err, ErrSiteInvalid) {
		t.Errorf("reassign to itself: %v, want ErrSiteInvalid", err)
	}
	if err := svc.DeleteSite(ctx, tenant, uuid.Nil, hq.ID, &dc.ID); err != nil {
		t.Fatalf("delete with reassign_to: %v", err)
	}
	var site, loc, scopeKind, scopeID string
	if err := db.QueryRow(`SELECT coalesce(site_id::text,''), coalesce(location_id::text,'') FROM assets WHERE id=$1`, asset).Scan(&site, &loc); err != nil {
		t.Fatal(err)
	}
	if site != dc.ID.String() || loc != "" {
		t.Errorf("asset after reassign: site %s location %q, want DC and none", site, loc)
	}
	if err := db.QueryRow(`SELECT coalesce(scope_kind,''), coalesce(scope_id::text,'') FROM prefixes WHERE id=$1`, prefix).Scan(&scopeKind, &scopeID); err != nil {
		t.Fatal(err)
	}
	if scopeKind != "site" || scopeID != dc.ID.String() {
		t.Errorf("prefix scoped to the deleted site's location is now (%s, %s), want (site, DC)", scopeKind, scopeID)
	}
	// An empty site deletes without a target.
	if err := svc.DeleteSite(ctx, tenant, uuid.Nil, mustSite(t, svc, tenant, models.SiteInput{Name: sp("Empty")}).ID, nil); err != nil {
		t.Errorf("delete an empty site: %v", err)
	}
}

// The trees: a location's parent is in its own site; no node is its own
// ancestor; depth is capped; deleting a region moves its children and sites
// up to its parent.
func TestIntegration_Sites_TreeRules(t *testing.T) {
	svc, _, tenant, _ := siteFixture(t)
	ctx := context.Background()
	hq := mustSite(t, svc, tenant, models.SiteInput{Name: sp("HQ")})
	dc := mustSite(t, svc, tenant, models.SiteInput{Name: sp("DC")})
	hall := mustLocation(t, svc, tenant, hq.ID, nil, "Hall 1")
	if _, err := svc.CreateLocation(ctx, tenant, uuid.Nil, models.LocationInput{SiteID: &dc.ID, ParentID: &hall.ID, Name: sp("Cage")}); !errors.Is(err, ErrSiteInvalid) {
		t.Errorf("parent in another site: %v, want ErrSiteInvalid", err)
	}
	if _, err := svc.UpdateLocation(ctx, tenant, uuid.Nil, hall.ID, models.LocationInput{SiteID: &dc.ID, Set: map[string]bool{"site_id": true}}); !errors.Is(err, ErrSiteInvalid) {
		t.Errorf("moving a location to another site: %v, want ErrSiteInvalid", err)
	}
	if _, err := svc.CreateLocation(ctx, tenant, uuid.Nil, models.LocationInput{SiteID: &hq.ID, Name: sp("Hall 1")}); !errors.Is(err, ErrSiteConflict) {
		t.Errorf("a second top-level Hall 1 in one site: %v, want ErrSiteConflict", err)
	}
	if _, err := svc.CreateLocation(ctx, tenant, uuid.Nil, models.LocationInput{SiteID: &dc.ID, Name: sp("Hall 1")}); err != nil {
		t.Errorf("Hall 1 in another site: %v", err)
	}

	var chain []*models.Region
	var parent *uuid.UUID
	for i := 0; i < maxSiteTreeDepth; i++ {
		r, err := svc.CreateRegion(ctx, tenant, uuid.Nil, models.RegionInput{Name: sp("R" + strings.Repeat("x", i)), ParentID: parent})
		if err != nil {
			t.Fatalf("region level %d: %v", i+1, err)
		}
		chain = append(chain, r)
		parent = &r.ID
	}
	if _, err := svc.CreateRegion(ctx, tenant, uuid.Nil, models.RegionInput{Name: sp("too deep"), ParentID: parent}); !errors.Is(err, ErrSiteInvalid) {
		t.Errorf("region level %d: %v, want ErrSiteInvalid", maxSiteTreeDepth+1, err)
	}
	if _, err := svc.UpdateRegion(ctx, tenant, uuid.Nil, chain[0].ID, models.RegionInput{ParentID: &chain[2].ID, Set: map[string]bool{"parent_id": true}}); !errors.Is(err, ErrSiteInvalid) {
		t.Errorf("a region under its own descendant: %v, want ErrSiteInvalid", err)
	}
	// Delete the middle of the chain: its child and its site move up to its parent.
	if _, err := svc.UpdateSite(ctx, tenant, uuid.Nil, hq.ID, models.SiteInput{RegionID: &chain[1].ID, Set: map[string]bool{"region_id": true}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteRegion(ctx, tenant, uuid.Nil, chain[1].ID); err != nil {
		t.Fatal(err)
	}
	child, err := svc.GetRegion(ctx, tenant, chain[2].ID)
	if err != nil || child.ParentID == nil || *child.ParentID != chain[0].ID {
		t.Errorf("child after its parent's delete: %+v %v, want re-parented to the root", child, err)
	}
	moved, err := svc.GetSite(ctx, tenant, hq.ID)
	if err != nil || moved.RegionID == nil || *moved.RegionID != chain[0].ID {
		t.Errorf("site after its region's delete: %+v %v, want moved to the region's parent", moved.RegionID, err)
	}
}

// Placement queries: site, site.group and site.region (with descendants) and
// location (by path, matching ancestors), run through the real asset list.
func TestIntegration_Sites_QueryFields(t *testing.T) {
	svc, _, tenant, db := siteFixture(t)
	ctx := context.Background()
	assets := NewAssetService(db)
	europe, _ := svc.CreateRegion(ctx, tenant, uuid.Nil, models.RegionInput{Name: sp("Europe")})
	nl, _ := svc.CreateRegion(ctx, tenant, uuid.Nil, models.RegionInput{Name: sp("Netherlands"), ParentID: &europe.ID})
	branches, _ := svc.CreateSiteGroup(ctx, tenant, uuid.Nil, models.RegionInput{Name: sp("Branches")})
	ams := mustSite(t, svc, tenant, models.SiteInput{Name: sp("AMS-1"), RegionID: &nl.ID, GroupID: &branches.ID})
	nyc := mustSite(t, svc, tenant, models.SiteInput{Name: sp("NYC-1")})
	hall := mustLocation(t, svc, tenant, ams.ID, nil, "Hall 2")
	cage := mustLocation(t, svc, tenant, ams.ID, &hall.ID, "Cage 7")
	mk := func(host string, site uuid.UUID, loc *uuid.UUID) {
		if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,site_id,location_id) VALUES($1,$2,$3,'server','hardware.computer.server','monitoring',$4,$5)`, uuid.New(), tenant, host, site, loc); err != nil {
			t.Fatal(err)
		}
	}
	mk("a.example.test", ams.ID, &cage.ID)
	mk("b.example.test", ams.ID, nil)
	mk("c.example.test", nyc.ID, nil)
	for q, want := range map[string]int{
		`site = "AMS-1"`:                       2,
		`site = ams-1`:                         2,
		`site != "AMS-1"`:                      1,
		`site.region = Europe`:                 2, // Netherlands is beneath Europe
		`site.region = Netherlands`:            2,
		`site.group = Branches`:                2,
		`location = "Hall 2"`:                  1, // Cage 7 is inside Hall 2
		`location = "AMS-1 / Hall 2 / Cage 7"`: 1,
		`exists(location)`:                     1,
		`site.id = "` + nyc.ID.String() + `"`:  1,
	} {
		_, total, err := assets.GetAssets(tenant, models.AssetFilters{Query: q, Page: 1, PageSize: 50, AssetStatus: []string{"monitoring"}})
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if total != want {
			t.Errorf("%s matched %d, want %d", q, total, want)
		}
	}
	buckets, err := assets.GetAssetFacets(tenant, models.AssetFilters{}, "site", 20)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]int{}
	for _, b := range buckets {
		labels[b.Label] = b.Count
	}
	if labels["AMS-1"] != 2 || labels["NYC-1"] != 1 {
		t.Errorf("site facet = %v, want AMS-1:2 NYC-1:1 labelled by name", labels)
	}
}

// The schema re-applies over populated sites and locations (the chart's
// schema-migration Job re-runs the whole file on every upgrade).
func TestIntegration_Sites_SchemaReappliesOverPopulatedData(t *testing.T) {
	svc, _, tenant, db := siteFixture(t)
	hq := mustSite(t, svc, tenant, models.SiteInput{Name: sp("Keep")})
	loc := mustLocation(t, svc, tenant, hq.ID, nil, "Hall")
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,site_id,location_id) VALUES($1,$2,'h','server','hardware.computer.server','monitoring',$3,$4)`, id, tenant, hq.ID, loc.ID); err != nil {
		t.Fatal(err)
	}
	testdb.ForceApplySchema(t, db.DB.DB)
	var site, l uuid.UUID
	if err := db.QueryRow(`SELECT site_id, location_id FROM assets WHERE id=$1`, id).Scan(&site, &l); err != nil || site != hq.ID || l != loc.ID {
		t.Errorf("placement after a second schema apply: %v %v %v", site, l, err)
	}
}

// A prefix's and a VLAN group's scope must name a region, site group, site or
// location of the tenant (the service check DATA_MODEL section 5 asks for; the
// CHECK only spells the kind). Remove checkIPAMScope from the prefix spec and
// the dangling and the other tenant's scopes are stored.
func TestIntegration_Sites_IPAMScopeResolves(t *testing.T) {
	f := newIPAMFixture(t)
	other := testdb.NewTenant(t, f.owner)
	var mine, theirs uuid.UUID
	if err := f.owner.QueryRow(`INSERT INTO sites (tenant_id, name, slug) VALUES ($1, 'HQ', 'hq') RETURNING id`, f.tenant).Scan(&mine); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(`INSERT INTO sites (tenant_id, name, slug) VALUES ($1, 'HQ', 'hq') RETURNING id`, other).Scan(&theirs); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]map[string]any{
		"dangling site":         {"prefix": "192.0.2.0/24", "scope_kind": "site", "scope_id": uuid.New().String()},
		"another tenant's":      {"prefix": "192.0.2.0/25", "scope_kind": "site", "scope_id": theirs.String()},
		"kind without an id":    {"prefix": "192.0.2.128/25", "scope_kind": "site"},
		"wrong kind for the id": {"prefix": "198.51.100.0/24", "scope_kind": "region", "scope_id": mine.String()},
	} {
		if err := f.tryCreate("prefixes", body); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("prefix with %s scope: %v, want ErrIPAMInvalid", name, err)
		}
	}
	p := f.create(t, "prefixes", map[string]any{"prefix": "203.0.113.0/24", "scope_kind": "site", "scope_id": mine.String()})
	if p["scope_id"] != mine.String() {
		t.Errorf("prefix scope = %v, want the tenant's site", p["scope_id"])
	}
	if err := f.tryCreate("vlan-groups", map[string]any{"name": "g", "scope_kind": "site", "scope_id": theirs.String()}); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("VLAN group scoped to another tenant's site: %v, want ErrIPAMInvalid", err)
	}
	if err := f.tryCreate("vlans", map[string]any{"vid": 10, "name": "v", "site_id": theirs.String()}); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("VLAN in another tenant's site: %v, want ErrIPAMInvalid", err)
	}
}
