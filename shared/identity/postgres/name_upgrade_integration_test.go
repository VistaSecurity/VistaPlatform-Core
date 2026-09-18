package postgres_test

import (
	"context"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"testing"
)

func TestIntegration_LegacyNameProtection(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()
	for _, tc := range []struct {
		name            string
		manual, promote bool
	}{
		{"operator-name", false, false}, {"aabbccddeeff.local", true, false}, {"aabbccddeeff.local", false, true},
	} {
		ref, err := repo.CreateAsset(ctx, tenant, identity.NewAsset{ClassKey: "server", Hostname: tc.name, DisplayName: tc.name, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE assets SET metadata='{}' WHERE id=$1`, ref.ID); err != nil {
			t.Fatal(err)
		}
		if tc.manual {
			if _, err = db.Exec(`INSERT INTO asset_history(tenant_id,asset_id,source,action,changes_json) VALUES($1,$2,'manual','updated','{"hostname":"aabbccddeeff.local"}')`, tenant, ref.ID); err != nil {
				t.Fatal(err)
			}
		}
		if err = repo.PromoteNames(ctx, ref, "better.example.test", "better.example.test", "measured-active"); err != nil {
			t.Fatal(err)
		}
		rows, err := repo.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil {
			t.Fatal(err)
		}
		want := tc.name
		if tc.promote {
			want = "better.example.test"
		}
		if rows[0].Hostname != want {
			t.Fatalf("%+v got %s want %s", tc, rows[0].Hostname, want)
		}
	}
}

func TestIntegration_PromoteNamesRejectsOtherOwnersAndAuditsChanges(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()
	engine, err := identity.New(identity.Config{Repo: repo, AutoAcceptThreshold: 0.6})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(serial, name string) identity.Resolution {
		t.Helper()
		o := observation(tenant, serial, "")
		o.Hostname = name
		o.DisplayName = name
		o.Identifiers = append(o.Identifiers, identity.Identifier{Kind: identity.KindHostname, Value: name, Scope: identity.ScopeTenantDefault, Confidence: 1})
		var res identity.Resolution
		err := repo.RunInTx(ctx, tenant, func(r *pgrepo.Repository) error {
			var e error
			res, e = engine.WithRepository(r).Resolve(ctx, o)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	a := resolve("OWN-A", "aabbccddeeff.local")
	b := resolve("", "other.example.test")
	if _, err := db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	res := resolve("OWN-A", "other.example.test")
	if res.Asset.ID != a.Asset.ID || len(res.Unattached) == 0 {
		t.Fatalf("not the rejected identifier path: %+v other=%s", res, b.Asset.ID)
	}
	rows, err := repo.LoadSummaries(ctx, tenant, []string{a.Asset.ID})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Hostname != "aabbccddeeff.local" {
		t.Fatalf("borrowed another asset name: %+v", rows)
	}
	resolve("OWN-A", "correct.example.test")
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND changes_json #>> '{hostname,to}'='correct.example.test'`, tenant, a.Asset.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("name audit rows=%d", n)
	}
}
