package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SegmentPlacement(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	other := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()
	location, segment := uuid.NewString(), uuid.NewString()
	if _, err := db.Exec(`WITH s AS (INSERT INTO sites(tenant_id,name,slug) VALUES($2,'North',regexp_replace(lower('North'),'[^a-z0-9]+','-','g')) RETURNING id) INSERT INTO locations(id,tenant_id,site_id,name,slug) SELECT $1,$2,s.id,'North',regexp_replace(lower('North'),'[^a-z0-9]+','-','g') FROM s`, location, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO prefixes(id,tenant_id,description,prefix,environment,scope_kind,scope_id,source_kind,status) VALUES($1,$2,'North','192.0.2.0/24','production','location',$3,'declared','active')`, segment, tenant, location); err != nil {
		t.Fatal(err)
	}
	source := identity.Source{Kind: identity.SourceMeasured, Ref: "placement-test"}
	for _, tc := range []struct {
		name, tenant, site, segment             string
		rollback, want                          bool
		conflictingLocation, conflictingSegment bool
	}{
		{name: "fill", tenant: tenant, segment: segment, want: true},
		{name: "conflict", tenant: tenant, site: "Curated", segment: segment},
		{name: "location-conflict", tenant: tenant, segment: segment, conflictingLocation: true},
		{name: "segment-conflict", tenant: tenant, segment: segment, conflictingSegment: true},
		{name: "cross-tenant", tenant: other, segment: segment},
		{name: "default", tenant: tenant, segment: "tenant/default"},
		{name: "rollback", tenant: tenant, segment: segment, rollback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := repo.CreateAsset(ctx, tc.tenant, identity.NewAsset{ClassKey: "server", Hostname: "aabbccddeeff.local", Source: source})
			if err != nil {
				t.Fatal(err)
			}
			if tc.site != "" {
				// A site of its own the segment's location is not in.
				if _, err = db.Exec(`INSERT INTO sites(tenant_id,name,slug) VALUES($1,$2,lower($2)) ON CONFLICT DO NOTHING`, tc.tenant, tc.site); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE assets SET site_id=(SELECT id FROM sites WHERE tenant_id=assets.tenant_id AND name=$2) WHERE id=$1`, ref.ID, tc.site); err != nil {
					t.Fatal(err)
				}
			}
			preservedLocation := ""
			if tc.conflictingLocation {
				preservedLocation = uuid.NewString()
				if _, err = db.Exec(`WITH s AS (INSERT INTO sites(tenant_id,name,slug) VALUES($2,'Elsewhere','elsewhere') RETURNING id) INSERT INTO locations(id,tenant_id,site_id,name,slug) SELECT $1,$2,s.id,'Curated','curated' FROM s`, preservedLocation, tc.tenant); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE assets SET location_id=$2, site_id=(SELECT site_id FROM locations WHERE id=$2) WHERE id=$1`, ref.ID, preservedLocation); err != nil {
					t.Fatal(err)
				}
			}
			if tc.conflictingSegment {
				different := uuid.NewString()
				if _, err = db.Exec(`INSERT INTO prefixes(id,tenant_id,description,prefix,environment,source_kind,status) VALUES($1,$2,'Other','203.0.113.0/24','production','declared','active')`, different, tc.tenant); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE assets SET prefix_id=$2 WHERE id=$1`, ref.ID, different); err != nil {
					t.Fatal(err)
				}
			}

			sentinel := errors.New("rollback")
			err = repo.RunInTx(ctx, tc.tenant, func(r *pgrepo.Repository) error {
				if err := r.ProjectSegmentLocation(ctx, ref, tc.segment, source); err != nil {
					return err
				}
				if err := r.PromoteNames(ctx, ref, "server.example.test", "server.example.test", "measured-active"); err != nil {
					return err
				}
				if tc.rollback {
					return sentinel
				}
				return nil
			})
			if err != nil && !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
			if !tc.rollback {
				if err = repo.ProjectSegmentLocation(ctx, ref, tc.segment, source); err != nil {
					t.Fatal(err)
				}
			}
			// An outer rollback must undo placement and its audit together.
			var site, loc, class, name string
			var n int
			if err = db.QueryRow(`SELECT coalesce((SELECT st.name FROM sites st WHERE st.id = assets.site_id),''),coalesce(location_id::text,''),class_key,hostname FROM assets WHERE id=$1`, ref.ID).Scan(&site, &loc, &class, &name); err != nil {
				t.Fatal(err)
			}
			if tc.want {
				if site != "North" || loc != location {
					t.Fatalf("placement %s %s", site, loc)
				}
			} else if wantSite := map[bool]string{true: "Elsewhere", false: tc.site}[tc.conflictingLocation]; site != wantSite || loc != preservedLocation {
				t.Fatalf("overwrote placement %s %s", site, loc)
			}
			expectedName := "server.example.test"
			if tc.rollback {
				expectedName = "aabbccddeeff.local"
			}
			if name != expectedName {
				t.Fatalf("name=%s want %s", name, expectedName)
			}

			if class != "server" {
				t.Fatalf("changed class %s", class)
			}
			if err = db.QueryRow(`SELECT count(*) FROM asset_history WHERE asset_id=$1 AND changes_json ? 'location_id'`, ref.ID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			expected := 0
			if tc.want {
				expected = 1
			}
			if n != expected {
				t.Fatalf("history %d want %d", n, expected)
			}
		})
	}
}

// TestIntegration_InheritSegmentLocation: placement from the segment the asset
// is ALREADY in, never from anywhere else. An asset in a located segment with
// no placement takes the segment's location and site (with history); one with
// no segment gets nothing; one in a segment without a location gets no
// location; a disagreeing site is kept.
//
// Environment rides the same path: an asset recording none takes its
// segment's (located or not, with history), and one that already states an
// environment keeps it — the segment never overrules a stated value.
//
// MUTATION: drop the a.prefix_id fallback from projectSegmentLocation's
// prefix join and "fill" goes red; drop its disagreeing-site guard and
// "curated" is overwritten; drop the `currentEnv == ""` guard and
// "stated-environment" is overwritten; make the locations join INNER again and
// "segment-without-location" loses its environment.
func TestIntegration_InheritSegmentLocation(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()
	location, located, bare := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := db.Exec(`WITH s AS (INSERT INTO sites(tenant_id,name,slug) VALUES($2,'South',regexp_replace(lower('South'),'[^a-z0-9]+','-','g')) RETURNING id) INSERT INTO locations(id,tenant_id,site_id,name,slug) SELECT $1,$2,s.id,'South',regexp_replace(lower('South'),'[^a-z0-9]+','-','g') FROM s`, location, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO prefixes(id,tenant_id,description,prefix,environment,scope_kind,scope_id,source_kind,status) VALUES($1,$2,'South','198.18.0.0/24','production','location',$3,'declared','active')`, located, tenant, location); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO prefixes(id,tenant_id,description,prefix,environment,source_kind,status) VALUES($1,$2,'Bare','198.18.1.0/24','production','declared','active')`, bare, tenant); err != nil {
		t.Fatal(err)
	}
	source := identity.Source{Kind: identity.SourceMeasured, Ref: "inherit-test"}
	for _, tc := range []struct {
		name, segment, site, env string
		wantSite, wantLoc        string
		wantEnv                  string
		// wantEnvRow: the environment fill is recorded, naming the segment.
		wantEnvRow bool
	}{
		{name: "fill", segment: located, wantSite: "South", wantLoc: location, wantEnv: "production", wantEnvRow: true},
		{name: "unsegmented", segment: ""},
		{name: "segment-without-location", segment: bare, wantEnv: "production", wantEnvRow: true},
		{name: "curated", segment: located, site: "Curated", wantSite: "Curated", wantEnv: "production", wantEnvRow: true},
		{name: "stated-environment", segment: located, env: "staging", wantSite: "South", wantLoc: location, wantEnv: "staging"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := repo.CreateAsset(ctx, tenant, identity.NewAsset{ClassKey: "server", Hostname: "inherit-" + tc.name, NetworkSegment: tc.segment, Source: source})
			if err != nil {
				t.Fatal(err)
			}
			if tc.site != "" {
				if _, err = db.Exec(`INSERT INTO sites(tenant_id,name,slug) VALUES($1,$2,lower($2)) ON CONFLICT DO NOTHING`, tenant, tc.site); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = db.Exec(`UPDATE assets SET site_id=(SELECT id FROM sites WHERE tenant_id=assets.tenant_id AND name=$2), environment=NULLIF($3,'')::environment_type WHERE id=$1`, ref.ID, tc.site, tc.env); err != nil {
				t.Fatal(err)
			}
			if err := repo.InheritSegmentLocation(ctx, ref, source); err != nil {
				t.Fatal(err)
			}
			var site, loc, env string
			var n int
			if err = db.QueryRow(`SELECT coalesce((SELECT st.name FROM sites st WHERE st.id = assets.site_id),''),coalesce(location_id::text,''),coalesce(environment::text,'') FROM assets WHERE id=$1`, ref.ID).Scan(&site, &loc, &env); err != nil {
				t.Fatal(err)
			}
			if site != tc.wantSite || loc != tc.wantLoc {
				t.Fatalf("placement (%q, %s), want (%q, %s)", site, loc, tc.wantSite, tc.wantLoc)
			}
			if env != tc.wantEnv {
				t.Fatalf("environment %q, want %q", env, tc.wantEnv)
			}
			if err = db.QueryRow(`SELECT count(*) FROM asset_history WHERE asset_id=$1 AND changes_json ? 'location_id' AND changes_json->>'prefix_id'=$2`, ref.ID, located).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if want := map[bool]int{true: 1, false: 0}[tc.wantLoc != ""]; n != want {
				t.Fatalf("history %d want %d", n, want)
			}
			segmentForRow := tc.segment
			if segmentForRow == "" {
				segmentForRow = located
			}
			if err = db.QueryRow(`SELECT count(*) FROM asset_history WHERE asset_id=$1 AND changes_json->'environment'->>'to'=$2 AND changes_json->>'prefix_id'=$3`, ref.ID, tc.wantEnv, segmentForRow).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if want := map[bool]int{true: 1, false: 0}[tc.wantEnvRow]; n != want {
				t.Fatalf("environment history rows %d want %d", n, want)
			}
		})
	}
}
