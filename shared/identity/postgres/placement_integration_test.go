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
	if _, err := db.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,'North','site');`, location, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,location_id) VALUES($1,$2,'North','cidr','192.0.2.0/24','production',$3)`, segment, tenant, location); err != nil {
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
			if _, err = db.Exec(`UPDATE assets SET site=$2 WHERE id=$1`, ref.ID, tc.site); err != nil {
				t.Fatal(err)
			}
			preservedLocation := ""
			if tc.conflictingLocation {
				preservedLocation = uuid.NewString()
				if _, err = db.Exec(`INSERT INTO locations(id,tenant_id,name,location_type) VALUES($1,$2,'Curated','site')`, preservedLocation, tc.tenant); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE assets SET location_id=$2 WHERE id=$1`, ref.ID, preservedLocation); err != nil {
					t.Fatal(err)
				}
			}
			if tc.conflictingSegment {
				different := uuid.NewString()
				if _, err = db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'Other','cidr','203.0.113.0/24','production')`, different, tc.tenant); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE assets SET network_segment_id=$2 WHERE id=$1`, ref.ID, different); err != nil {
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
			if err = db.QueryRow(`SELECT coalesce(site,''),coalesce(location_id::text,''),class_key,hostname FROM assets WHERE id=$1`, ref.ID).Scan(&site, &loc, &class, &name); err != nil {
				t.Fatal(err)
			}
			if tc.want {
				if site != "North" || loc != location {
					t.Fatalf("placement %s %s", site, loc)
				}
			} else if site != tc.site || loc != preservedLocation {
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
