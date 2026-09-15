package database_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The general-asset-inventory additive schema (BUILD_PLAN workstream 0.2,
// DATA_MODEL §1–§4). These tests guard the three properties the tables have to
// hold from the day they land, before any writer exists:
//
//  1. schema.sql stays re-appliable over POPULATED tables. The chart re-applies
//     the whole file on every helm upgrade under ON_ERROR_STOP=1, and a
//     double-apply against an EMPTY database proves almost nothing: every
//     constraint-adding statement is trivially satisfiable on an empty table.
//     Rows are written BETWEEN the two passes here for exactly that reason
//     (CLAUDE.md, "Double-apply against an EMPTY database proves almost
//     nothing").
//  2. Every tenant-scoped table is RLS-isolated under the non-owner app role
//     services actually connect as. A missing policy is invisible to the owner
//     connection, so this is the only place it shows.
//  3. asset_identifiers' uniqueness is ACROSS assets, not per asset. That
//     index is the entire identification mechanism (ADR-0002 D3): a conflict is
//     the signal that produces a merge proposal, and if the index is per-asset
//     or absent there is no signal to react to.
//
// They skip unless TEST_DATABASE_URL is set (`make test-integration-db`).

// newTenantScopedTables are the tables workstream 0.2 adds that carry a
// tenant_id and must be isolated by it. Partitioned tables are named by their
// PARENT, which is where the policy lives and where every query goes.
var newTenantScopedTables = []string{
	"asset_classes",
	"assets",
	"asset_endpoints",
	"asset_identifiers",
	"asset_management",
	"asset_credentials",
	"asset_relationships",
	"asset_facts",
	"software_products",
	"software_installs",
	"findings",
	// Workstream 3.2's coverage record. Listed here rather than left out
	// because the two questions this file asks about a tenant table are exactly
	// the two that matter for it: does RLS isolate it (its rows say which
	// producer has looked at which asset, which is a tenant's inventory
	// posture), and do its rows survive a second schema apply (a customer's
	// `helm upgrade` re-runs the whole file over a populated database).
	"producer_assessments",
	// The `eol` producer's per-install lifecycle record — what the catalogue
	// resolved for each software install. Same two questions: its rows are a
	// tenant's software posture, and a customer's upgrade re-applies the file
	// over a populated table.
	"software_install_lifecycle",
}

// newPlatformTables carry no tenant_id: platform catalogues every tenant reads,
// written by platform admins. They have NO RLS, which is the existing pattern
// for `algorithms` and `platform_frameworks` — asserted here so that "no
// policy" stays a decision rather than becoming an oversight nobody notices.
var newPlatformTables = []string{
	"eol_catalogue",
	"vulnerability_catalogue",
	"vulnerability_matches",
	"classification_rules",
}

// TestIntegration_AssetInventorySchema_ReappliesOverPopulatedTables applies
// schema.sql and seed.sql, writes a row into every new table, then applies both
// again — which is what a customer's `helm upgrade` does to a database with a
// year of inventory in it.
//
// It uses a FRESH throwaway database, like the grant-order guard, rather than
// the shared integration database: the shared one is already populated and
// re-applied by other packages, so a statement that only fails on the first
// apply (or only against rows this test writes) would be masked.
func TestIntegration_AssetInventorySchema_ReappliesOverPopulatedTables(t *testing.T) {
	admin := testdb.Connect(t) // skips unless TEST_DATABASE_URL is set

	dbName := "assetinv_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE %q", dbName)); err != nil {
		t.Fatalf("create throwaway database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %q WITH (FORCE)", dbName))
	})

	fresh := openNamed(t, dbName)

	// The role-split section grants to crypto_user's default privileges; the
	// ephemeral harness runs as postgres, so create it as
	// scripts/run-integration-db-tests.sh does.
	if _, err := fresh.Exec("CREATE ROLE crypto_user"); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("create crypto_user: %v", err)
	}

	root := testdb.RepoRoot(t)
	apply := func(pass int, rel string) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if _, err := fresh.Exec(string(b)); err != nil {
			t.Fatalf("pass %d: apply %s: %v", pass, rel, err)
		}
	}

	apply(1, "scripts/database/schema.sql")
	apply(1, "scripts/database/seed.sql")

	tenantA := seedAssetInventoryRows(t, fresh, "ai-a")
	tenantB := seedAssetInventoryRows(t, fresh, "ai-b")

	// The second pass is the assertion. A non-idempotent statement, or an
	// ADD CONSTRAINT the rows above violate, fails here and nowhere else.
	apply(2, "scripts/database/schema.sql")
	apply(2, "scripts/database/seed.sql")

	// The rows must still be there: a DROP ... CASCADE or a recreated table
	// would pass the apply and silently take the data with it.
	for _, tbl := range append(append([]string{}, newTenantScopedTables...), newPlatformTables...) {
		var n int
		if err := fresh.QueryRow("SELECT count(*) FROM public." + tbl).Scan(&n); err != nil {
			t.Fatalf("count %s after re-apply: %v", tbl, err)
		}
		if n == 0 {
			t.Errorf("%s is EMPTY after the second apply — rows written between the passes did not survive", tbl)
		}
	}

	// The seed's platform class rows must reconcile rather than duplicate:
	// the upsert restates every generated column, so a second run is an UPDATE.
	var platformClasses int
	if err := fresh.QueryRow(`SELECT count(*) FROM asset_classes WHERE tenant_id IS NULL`).Scan(&platformClasses); err != nil {
		t.Fatalf("count platform classes: %v", err)
	}
	if platformClasses != len(assetclass.All) {
		t.Errorf("platform asset_classes rows after two applies = %d, want %d (the seed upsert duplicated or dropped rows)",
			platformClasses, len(assetclass.All))
	}

	// The two sort/provenance columns must survive the re-apply with their
	// values, and the unparseable version must still be NULL rather than
	// backfilled with anything. NULL here is the answer "this version does not
	// parse", which the query language turns into UNKNOWN; a lexical stand-in
	// would silently order "1.10" before "1.9".
	var withSort, nullSort, withRef int
	if err := fresh.QueryRow(`
		SELECT count(*) FILTER (WHERE service_version_sort IS NOT NULL),
		       count(*) FILTER (WHERE service_version IS NOT NULL AND service_version_sort IS NULL)
		  FROM asset_endpoints`).Scan(&withSort, &nullSort); err != nil {
		t.Fatalf("read service_version_sort after re-apply: %v", err)
	}
	if withSort == 0 {
		t.Error("no asset_endpoints row kept its service_version_sort across the re-apply")
	}
	if nullSort == 0 {
		t.Error("the unparseable-version endpoint lost its NULL service_version_sort — " +
			"NULL is the answer \"does not parse\", not a missing value to fill in")
	}
	if err := fresh.QueryRow(`SELECT count(*) FROM assets WHERE class_source_ref IS NOT NULL`).Scan(&withRef); err != nil {
		t.Fatalf("read class_source_ref after re-apply: %v", err)
	}
	if withRef == 0 {
		t.Error("no assets row kept its class_source_ref across the re-apply")
	}

	// And the tenant subclasses each fixture wrote must be untouched by it.
	for _, tenant := range []uuid.UUID{tenantA, tenantB} {
		var n int
		if err := fresh.QueryRow(`SELECT count(*) FROM asset_classes WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
			t.Fatalf("count tenant classes: %v", err)
		}
		if n != 1 {
			t.Errorf("tenant %s subclass rows = %d, want 1 (the platform upsert touched tenant rows)", tenant, n)
		}
	}
}

// TestIntegration_AssetInventorySchema_SeedsEveryPlatformClass proves the
// generated region in seed.sql actually ran and carries the whole taxonomy.
//
// It compares against shared/assetclass.All rather than a literal count, so the
// test does not churn when a class is added — and, more to the point, so the
// database and the Go registry cannot disagree. They are generated from the
// same standards/asset-classes.yaml; this is where "generated from the same
// file" is checked against a real apply rather than assumed.
func TestIntegration_AssetInventorySchema_SeedsEveryPlatformClass(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	if len(assetclass.All) == 0 {
		t.Fatal("shared/assetclass.All is empty — the generated registry did not load")
	}

	var count int
	if err := db.QueryRow(`SELECT count(*) FROM asset_classes WHERE tenant_id IS NULL AND is_fixed`).Scan(&count); err != nil {
		t.Fatalf("count platform classes: %v", err)
	}
	if count != len(assetclass.All) {
		t.Fatalf("seeded platform asset_classes = %d, want %d (len(assetclass.All)) — "+
			"the generated region in seed.sql is stale or did not apply", count, len(assetclass.All))
	}

	// Not just the count: every key, path, parent and precedence must match, or
	// the two registries agree on size and on nothing else.
	for _, c := range assetclass.All {
		var path, parent, cyclonedx string
		var precedence []byte
		err := db.QueryRow(`
			SELECT path, coalesce(parent_key, ''), cyclonedx_type, identifier_precedence::text
			  FROM asset_classes WHERE tenant_id IS NULL AND key = $1`, c.Key).
			Scan(&path, &parent, &cyclonedx, &precedence)
		if err == sql.ErrNoRows {
			t.Errorf("class %q is in assetclass.All but has no seeded row", c.Key)
			continue
		}
		if err != nil {
			t.Fatalf("read class %q: %v", c.Key, err)
		}
		if path != c.Path {
			t.Errorf("class %q path: db=%q registry=%q", c.Key, path, c.Path)
		}
		if parent != c.Parent {
			t.Errorf("class %q parent: db=%q registry=%q", c.Key, parent, c.Parent)
		}
		if cyclonedx != c.CycloneDXType {
			t.Errorf("class %q cyclonedx_type: db=%q registry=%q", c.Key, cyclonedx, c.CycloneDXType)
		}
		// identifier_precedence comes back as Postgres array literal text; a
		// per-element compare would need a parser, so compare membership and
		// order through the literal, which is enough to catch a reordering.
		want := "{" + strings.Join(c.IdentifierPrecedence, ",") + "}"
		if string(precedence) != want {
			t.Errorf("class %q identifier_precedence: db=%s registry=%s", c.Key, precedence, want)
		}
	}
}

// TestIntegration_AssetInventorySchema_RLSIsolatesEveryNewTable opens a real
// connection as crypto_app (NOBYPASSRLS — the role services connect as under
// serviceRls) and proves that with tenant A's context set, not one of B's rows
// is visible in any new table, and that a cross-tenant INSERT is refused.
//
// The owner connection bypasses RLS, so a table that shipped with no policy at
// all would look perfectly isolated to every other test in the suite.
func TestIntegration_AssetInventorySchema_RLSIsolatesEveryNewTable(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)

	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)
	fixtureA := insertAssetInventoryFixture(t, owner, tenantA)
	fixtureB := insertAssetInventoryFixture(t, owner, tenantB)

	app := testdb.ConnectAsAppRole(t, owner)

	for _, tbl := range newTenantScopedTables {
		t.Run(tbl+"/read-deny", func(t *testing.T) {
			testdb.AsTenant(t, app, tenantA, func(tx *sql.Tx) {
				// asset_classes is the hybrid case: a tenant SEES the platform
				// rows (tenant_id IS NULL) it classifies against, and its own.
				// Never another tenant's.
				var leaked int
				if err := tx.QueryRow(
					`SELECT count(*) FROM public.`+tbl+` WHERE tenant_id = $1`, tenantB,
				).Scan(&leaked); err != nil {
					t.Fatalf("count tenant B rows in %s as tenant A: %v", tbl, err)
				}
				if leaked != 0 {
					t.Errorf("%s: tenant A can see %d of tenant B's rows — RLS is missing or not enforced", tbl, leaked)
				}

				var own int
				if err := tx.QueryRow(
					`SELECT count(*) FROM public.`+tbl+` WHERE tenant_id = $1`, tenantA,
				).Scan(&own); err != nil {
					t.Fatalf("count own rows in %s: %v", tbl, err)
				}
				if own == 0 {
					t.Errorf("%s: tenant A cannot see its OWN rows — the policy is too strict, "+
						"which fails just as loudly in production as a leak (fixtures: A=%s B=%s)",
						tbl, fixtureA.assetID, fixtureB.assetID)
				}
			})
		})

		t.Run(tbl+"/fail-closed", func(t *testing.T) {
			testdb.AsRoleNoTenant(t, app, func(tx *sql.Tx) {
				var n int
				// asset_classes deliberately shows platform rows with no tenant
				// context, since USING allows tenant_id IS NULL. Count only the
				// tenant-owned rows, which must be invisible.
				if err := tx.QueryRow(
					`SELECT count(*) FROM public.` + tbl + ` WHERE tenant_id IS NOT NULL`,
				).Scan(&n); err != nil {
					t.Fatalf("count %s with no tenant context: %v", tbl, err)
				}
				if n != 0 {
					t.Errorf("%s: %d tenant rows visible with no app.tenant_id set — RLS is not failing closed", tbl, n)
				}
			})
		})
	}

	// WITH CHECK: writing a row stamped with another tenant's id must be
	// refused, not silently accepted and then hidden.
	t.Run("assets/write-deny", func(t *testing.T) {
		testdb.AsTenant(t, app, tenantA, func(tx *sql.Tx) {
			_, err := tx.Exec(`
				INSERT INTO public.assets (tenant_id, class_key, class_path, display_name)
				VALUES ($1, 'server', 'hardware.computer.server', 'smuggled')`, tenantB)
			if err == nil {
				t.Fatal("cross-tenant INSERT into assets succeeded — WITH CHECK is missing or not enforced")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
				t.Fatalf("cross-tenant INSERT into assets failed with the wrong error: %v", err)
			}
		})
	})

	t.Run("asset_classes/write-deny-platform-row", func(t *testing.T) {
		testdb.AsTenant(t, app, tenantA, func(tx *sql.Tx) {
			// A tenant may READ platform classes but must not be able to mint
			// one: the fixed taxonomy is the platform's, and a tenant row with
			// tenant_id NULL would be indistinguishable from it.
			_, err := tx.Exec(`
				INSERT INTO public.asset_classes (tenant_id, key, path, label, cyclonedx_type)
				VALUES (NULL, 'smuggled_platform_class', 'smuggled_platform_class', 'Smuggled', 'device')`)
			if err == nil {
				t.Fatal("a tenant inserted a PLATFORM asset_classes row (tenant_id IS NULL) — " +
					"WITH CHECK must be strict even though USING is permissive")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
				t.Fatalf("platform-row INSERT failed with the wrong error: %v", err)
			}
		})
	})

	// The other half of "READ platform rows, WRITE only your own". WITH CHECK
	// constrains the NEW row, and a DELETE produces no new row, so DELETE is
	// governed by USING alone — a single admitting `USING (tenant_id IS NULL
	// OR …)` policy therefore lets any tenant delete the platform class
	// registry for every tenant on the install. That is why asset_classes
	// carries two policies (own-rows FOR ALL + platform-rows FOR SELECT)
	// rather than the one-policy hybrid form.
	t.Run("asset_classes/delete-deny-platform-row", func(t *testing.T) {
		var before int
		if err := owner.QueryRow(
			`SELECT count(*) FROM public.asset_classes WHERE tenant_id IS NULL`).Scan(&before); err != nil {
			t.Fatalf("count platform classes: %v", err)
		}
		if before == 0 {
			t.Fatal("no platform classes seeded — this test would pass vacuously")
		}
		testdb.AsTenant(t, app, tenantA, func(tx *sql.Tx) {
			res, err := tx.Exec(`DELETE FROM public.asset_classes WHERE tenant_id IS NULL`)
			if err != nil {
				return // refused outright is also a pass
			}
			if n, _ := res.RowsAffected(); n != 0 {
				t.Fatalf("a tenant DELETEd %d PLATFORM asset_classes row(s). RLS reuses USING for "+
					"DELETE (there is no new row for WITH CHECK to constrain), so an admitting "+
					"USING hands every tenant the whole registry. Keep the split policies.", n)
			}
		})
	})

	// Same shape for UPDATE: USING picks the row, WITH CHECK vets the result.
	t.Run("asset_classes/update-deny-platform-row", func(t *testing.T) {
		testdb.AsTenant(t, app, tenantA, func(tx *sql.Tx) {
			res, err := tx.Exec(
				`UPDATE public.asset_classes SET label = 'hijacked' WHERE tenant_id IS NULL`)
			if err != nil {
				return
			}
			if n, _ := res.RowsAffected(); n != 0 {
				t.Fatalf("a tenant UPDATEd %d PLATFORM asset_classes row(s)", n)
			}
		})
	})

	// A tenant must still be able to do the thing the hybrid table exists for:
	// read the platform taxonomy, and create its own leaf subclass. Without
	// this the delete-deny test above could be "passed" by locking tenants out
	// of the table entirely, which is the same bug pointed the other way.
	t.Run("asset_classes/tenant-can-read-platform-and-write-own", func(t *testing.T) {
		testdb.AsTenant(t, app, tenantA, func(tx *sql.Tx) {
			var platform int
			if err := tx.QueryRow(
				`SELECT count(*) FROM public.asset_classes WHERE tenant_id IS NULL`).Scan(&platform); err != nil {
				t.Fatalf("read platform classes as a tenant: %v", err)
			}
			if platform == 0 {
				t.Fatal("a tenant cannot see the platform classes it must classify against")
			}
			if _, err := tx.Exec(`
				INSERT INTO public.asset_classes (tenant_id, key, parent_key, path, label, cyclonedx_type)
				VALUES ($1, 'rls_probe_subclass', 'server',
				        'hardware.computer.server.rls_probe_subclass', 'Probe', 'device')`,
				tenantA); err != nil {
				t.Fatalf("a tenant cannot create its own leaf subclass: %v", err)
			}
		})
	})

	// Every FK in this block carries tenant_id so a cross-tenant reference is
	// unrepresentable. software_installs.product_id is the one that could
	// plausibly have been left bare, and a bare one fails quietly: the install
	// joins to a product RLS then hides, so it renders with no product and no
	// error, and the other tenant's ON DELETE CASCADE reaches across.
	t.Run("software_installs/product-fk-is-tenant-scoped", func(t *testing.T) {
		productB := uuid.NewString()
		assetA := uuid.NewString()
		if _, err := owner.Exec(`
			INSERT INTO public.software_products (id, tenant_id, name) VALUES ($1, $2, 'b-only')`,
			productB, tenantB); err != nil {
			t.Fatalf("seed tenant B product: %v", err)
		}
		if _, err := owner.Exec(`
			INSERT INTO public.assets (id, tenant_id, class_key, class_path, display_name)
			VALUES ($1, $2, 'server', 'hardware.computer.server', 'a')`, assetA, tenantA); err != nil {
			t.Fatalf("seed tenant A asset: %v", err)
		}
		// As the OWNER, so RLS cannot be what refuses it — the FK must.
		_, err := owner.Exec(`
			INSERT INTO public.software_installs (tenant_id, asset_id, product_id)
			VALUES ($1, $2, $3)`, tenantA, assetA, productB)
		if err == nil {
			t.Fatal("an install for tenant A referenced tenant B's product. The FK must be " +
				"(tenant_id, product_id) -> software_products(tenant_id, id), not product_id alone.")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			t.Fatalf("cross-tenant install failed with the wrong error: %v", err)
		}
	})

	// A policy on a partitioned PARENT is applied to queries that name the
	// parent. Naming a partition directly is a separate relation reference and
	// consults only that partition's own policies — so with RLS off on the
	// partition, the blanket GRANT hands crypto_app every tenant's rows, one
	// identifier away from the policy. Measured before the fix: 3 rows through
	// `assets`, 4 through assets_part_0..7. The partitions therefore carry RLS
	// enabled with NO policy, which is default-deny.
	//
	// All FOUR partitioned tables in the instance, not just the two this
	// workstream added. `sensor_discoveries_partitioned` and
	// `crypto_implementations_partitioned` pre-date it and carry the same hole;
	// phase 1 dropped the third (`network_assets_partitioned`) outright and
	// enabled RLS on these two, and a guard that covered only the new tables
	// would leave the older instance of the same bug untested — which is how it
	// survived this long.
	//
	// The partition name is NOT derivable from the parent: the new tables are
	// `assets` → `assets_part_N`, the old ones `sensor_discoveries_partitioned`
	// → `sensor_discoveries_part_N`.
	for _, tbl := range []struct{ parent, partPrefix string }{
		{"assets", "assets"},
		{"asset_endpoints", "asset_endpoints"},
		{"sensor_discoveries_partitioned", "sensor_discoveries"},
		{"crypto_implementations_partitioned", "crypto_implementations"},
	} {
		// The catalogue check FIRST, because the behavioural one below is
		// data-dependent: it can only see a leak from a partition that happens
		// to hold another tenant's row, and a tenant id hashes into one of
		// eight. Removing a single ENABLE and re-running proved exactly that —
		// the behavioural check passed, because no fixture row was in the
		// partition that had been opened up. A guard whose failure depends on
		// which partition a uuid hashed into is a guard that cannot be relied
		// on to fail, so the property is also asserted directly, where it holds
		// for all eight whether or not they contain anything.
		t.Run(tbl.parent+"/every-partition-has-rls-enabled", func(t *testing.T) {
			for i := 0; i < 8; i++ {
				part := fmt.Sprintf("%s_part_%d", tbl.partPrefix, i)
				var enabled bool
				if err := owner.QueryRow(`
					SELECT c.relrowsecurity FROM pg_class c
					  JOIN pg_namespace n ON n.oid = c.relnamespace
					 WHERE n.nspname = 'public' AND c.relname = $1`, part).Scan(&enabled); err != nil {
					t.Fatalf("read relrowsecurity for %s: %v", part, err)
				}
				if !enabled {
					t.Errorf("public.%s has RLS DISABLED. A policy on the partitioned parent does not "+
						"cover a query that names a partition directly, and the blanket GRANT at the "+
						"foot of schema.sql hands crypto_app every tenant's rows through it. Each "+
						"partition needs its own ENABLE ROW LEVEL SECURITY (no policy: default-deny).", part)
				}
			}
		})

		t.Run(tbl.parent+"/partitions-are-not-a-back-door", func(t *testing.T) {
			testdb.AsTenant(t, app, tenantA, func(tx *sql.Tx) {
				var viaParent int
				if err := tx.QueryRow(
					`SELECT count(*) FROM public.` + tbl.parent).Scan(&viaParent); err != nil {
					t.Fatalf("count %s through the parent: %v", tbl.parent, err)
				}
				if viaParent == 0 {
					t.Fatalf("%s returns nothing through the parent — the fixtures or the "+
						"policy are wrong, and this test would pass vacuously", tbl.parent)
				}
				for i := 0; i < 8; i++ {
					part := fmt.Sprintf("public.%s_part_%d", tbl.partPrefix, i)
					var n int
					if err := tx.QueryRow(`SELECT count(*) FROM ` + part).Scan(&n); err != nil {
						// A hard refusal is also a pass; what must not happen is rows.
						continue
					}
					if n != 0 {
						t.Errorf("%s returned %d row(s) to a tenant session. RLS on the parent "+
							"does NOT cover a direct partition reference — each partition needs "+
							"ENABLE ROW LEVEL SECURITY (no policy) of its own.", part, n)
					}
				}
			})
		})
	}

	t.Run("platform catalogues carry no policy", func(t *testing.T) {
		for _, tbl := range newPlatformTables {
			var relrowsecurity bool
			if err := owner.QueryRow(`
				SELECT c.relrowsecurity FROM pg_class c
				  JOIN pg_namespace n ON n.oid = c.relnamespace
				 WHERE n.nspname = 'public' AND c.relname = $1`, tbl).Scan(&relrowsecurity); err != nil {
				t.Fatalf("read relrowsecurity for %s: %v", tbl, err)
			}
			if relrowsecurity {
				t.Errorf("%s has RLS enabled but no tenant_id to isolate by — either it grew a "+
					"tenant column (then move it to newTenantScopedTables) or the ENABLE is a mistake "+
					"that will make it invisible to crypto_app", tbl)
			}
		}
	})
}

// TestIntegration_AssetInventorySchema_IdentifierIsUniqueAcrossAssets pins the
// index that IS the identification engine (ADR-0002 D3).
//
// An identifier value maps to at most ONE asset. The conflict raised here is
// not a failure to swallow — it is the signal that produces a merge proposal in
// Approvals. If this index were per-asset (or absent), two observations of the
// same machine under different names would become two assets forever, which is
// the duplicate problem the whole initiative exists to fix.
func TestIntegration_AssetInventorySchema_IdentifierIsUniqueAcrossAssets(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	tenant := testdb.NewTenant(t, db)
	first := insertAsset(t, db, tenant, "server", "hardware.computer.server", "host-one")
	second := insertAsset(t, db, tenant, "server", "hardware.computer.server", "host-two")

	const mac = "00:de:ad:be:ef:01"
	if _, err := db.Exec(`
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, source_kind, source_ref)
		VALUES ($1, $2, 'mac_address', $3, 'measured', 'sensor:one')`, tenant, first, mac); err != nil {
		t.Fatalf("first identifier insert: %v", err)
	}

	_, err := db.Exec(`
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, source_kind, source_ref)
		VALUES ($1, $2, 'mac_address', $3, 'measured', 'sensor:two')`, tenant, second, mac)
	if err == nil {
		t.Fatal("the same identifier value was accepted on a SECOND asset — " +
			"asset_identifiers_value_uniq is per-asset or missing, so a conflict can never " +
			"raise the merge proposal ADR-0002 D3 depends on")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
		t.Fatalf("second insert failed with the wrong error (want a unique violation): %v", err)
	}

	// The other polarity: `scope` is part of the key, so the same value in a
	// different scope is a different identifier and must be allowed. Without
	// this, a hostname reused in two network segments could never be recorded.
	if _, err := db.Exec(`
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, scope, source_kind, source_ref)
		VALUES ($1, $2, 'mac_address', $3, 'segment-b', 'measured', 'sensor:two')`, tenant, second, mac); err != nil {
		t.Fatalf("same value in a DIFFERENT scope was rejected, but scope is part of the key: %v", err)
	}

	// And a different tenant is always a different namespace.
	other := testdb.NewTenant(t, db)
	otherAsset := insertAsset(t, db, other, "server", "hardware.computer.server", "host-three")
	if _, err := db.Exec(`
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, source_kind, source_ref)
		VALUES ($1, $2, 'mac_address', $3, 'measured', 'sensor:three')`, other, otherAsset, mac); err != nil {
		t.Fatalf("the same identifier in ANOTHER tenant was rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

type assetInventoryFixture struct {
	tenantID  uuid.UUID
	assetID   uuid.UUID
	productID uuid.UUID
}

func insertAsset(t *testing.T, db *sql.DB, tenant uuid.UUID, classKey, classPath, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	// class_source_ref is written here (not left NULL) so the column is
	// exercised by the double-apply and the RLS reads rather than merely
	// existing: a class the query language's `proposed_by` sugar reads has to
	// carry the producer that assigned it.
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, class_key, class_path, display_name, asset_status,
		                    class_source_kind, class_source_ref, class_confidence)
		VALUES ($1, $2, $3, $4, $5, 'monitoring', 'inferred', 'classifier:rules-v1', 0.90)`,
		id, tenant, classKey, classPath, name); err != nil {
		t.Fatalf("insert asset %s: %v", name, err)
	}
	return id
}

// insertAssetInventoryFixture writes one row into every new tenant-scoped
// table for the given tenant. Every table in newTenantScopedTables must be
// covered — the RLS test asserts the tenant can see its OWN rows, so a table
// left unpopulated here would fail rather than silently pass.
func insertAssetInventoryFixture(t *testing.T, db *sql.DB, tenant uuid.UUID) assetInventoryFixture {
	t.Helper()
	short := strings.ReplaceAll(tenant.String(), "-", "")[:8]

	// A tenant leaf subclass beneath a fixed platform class.
	if _, err := db.Exec(`
		INSERT INTO asset_classes (tenant_id, key, parent_key, path, label, cyclonedx_type, is_fixed)
		VALUES ($1, $2, 'server', 'hardware.computer.server.' || $2, 'Fixture subclass', 'device', false)`,
		tenant, "fixture_"+short); err != nil {
		t.Fatalf("insert tenant asset class: %v", err)
	}

	host := insertAsset(t, db, tenant, "server", "hardware.computer.server", "fixture-host-"+short)
	peer := insertAsset(t, db, tenant, "hypervisor", "virtual.hypervisor", "fixture-hv-"+short)

	// service_version_sort is the normalised key, NOT the raw version: "1.10"
	// sorts before "1.9" as text, so a lexical fallback inverts every version
	// predicate the query language builds on it (QUERY_LANGUAGE §5.5).
	if _, err := db.Exec(`
		INSERT INTO asset_endpoints (tenant_id, asset_id, fqdn, port, transport, protocol,
		                             service_name, service_version, service_version_sort)
		VALUES ($1, $2, $3, 443, 'tcp', 'TLS', 'nginx', '1.25.3', '00001.00025.00003')`,
		tenant, host, "fixture-"+short+".example.test"); err != nil {
		t.Fatalf("insert asset endpoint: %v", err)
	}
	// A second endpoint whose version does not parse: service_version_sort must
	// be NULL rather than a lexical stand-in, so the comparison evaluates
	// UNKNOWN. Also the NULL-fqdn/NULL-port shape the unique expression exists
	// to collapse.
	if _, err := db.Exec(`
		INSERT INTO asset_endpoints (tenant_id, asset_id, address, transport,
		                             service_name, service_version, service_version_sort)
		VALUES ($1, $2, '198.51.100.7', 'none', 'mystery', 'nightly-build', NULL)`,
		tenant, host); err != nil {
		t.Fatalf("insert unparseable-version endpoint: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, source_kind, source_ref)
		VALUES ($1, $2, 'hostname', $3, 'measured', 'fixture')`,
		tenant, host, "fixture-"+short); err != nil {
		t.Fatalf("insert asset identifier: %v", err)
	}

	// Rows on the two PRE-EXISTING partitioned tables. They are not part of the
	// additive schema this file is about, but the partition-direct subtest below
	// covers all four partitioned tables in the instance and needs a row in each
	// or it passes vacuously — the failure mode it exists to catch.
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations_partitioned (tenant_id, asset_id, protocol, discovery_method)
		VALUES ($1, $2, 'TLS', 'passive')`, tenant, host); err != nil {
		t.Fatalf("insert crypto implementation fixture: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO sensor_discoveries_partitioned (tenant_id, sensor_id, batch_id, protocol, dest_ip, port, confidence)
		VALUES ($1, $2, $3, 'TLS', '198.51.100.9', 443, 1.0)`, tenant, uuid.New(), uuid.New()); err != nil {
		t.Fatalf("insert sensor discovery fixture: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO asset_management (tenant_id, asset_id, management_url, management_protocol, connection_status)
		VALUES ($1, $2, 'https://fixture.example.test', 'https', 'connected')`, tenant, peer); err != nil {
		t.Fatalf("insert asset management: %v", err)
	}

	// password_enc holds ciphertext in production; the fixture only needs a
	// value, and deliberately does not look like a plausible password.
	if _, err := db.Exec(`
		INSERT INTO asset_credentials (tenant_id, asset_id, username, password_enc)
		VALUES ($1, $2, 'fixture', 'CIPHERTEXT-PLACEHOLDER')`, tenant, peer); err != nil {
		t.Fatalf("insert asset credentials: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, type, source_kind, source_ref, status)
		VALUES ($1, $2, $3, 'virtualized_by', 'measured', 'fixture', 'active')`, tenant, host, peer); err != nil {
		t.Fatalf("insert asset relationship: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref)
		VALUES ($1, $2, 'os.name', '"Ubuntu"'::jsonb, 'measured', 'fixture')`, tenant, host); err != nil {
		t.Fatalf("insert asset fact: %v", err)
	}

	product := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO software_products (id, tenant_id, name, vendor, version, version_sort, purl, source_kind)
		VALUES ($1, $2, 'openssl', 'OpenSSL', '3.0.2', '00003.00000.00002', $3, 'measured')`,
		product, tenant, "pkg:deb/fixture/openssl@3.0.2-"+short); err != nil {
		t.Fatalf("insert software product: %v", err)
	}

	install := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO software_installs (id, tenant_id, asset_id, product_id, install_path, source_kind, source_ref)
		VALUES ($1, $2, $3, $4, '/usr/lib/ssl', 'measured', 'fixture')`, install, tenant, host, product); err != nil {
		t.Fatalf("insert software install: %v", err)
	}

	// The eol producer's per-install record, in the shape the producer writes
	// for a supported package: a citation and a date. The shape CHECK makes
	// the other combinations unwritable, so this is the row a re-apply has to
	// keep and RLS has to isolate.
	if _, err := db.Exec(`
		INSERT INTO software_install_lifecycle (tenant_id, install_id, assessment, catalogue_id, eol_date)
		VALUES ($1, $2, 'supported', $3, '2028-04-01')`, tenant, install, uuid.New()); err != nil {
		t.Fatalf("insert software install lifecycle: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO findings (tenant_id, producer, kind, subject_type, subject_id, subject_label,
		                      severity, score, summary, source_kind)
		VALUES ($1, 'eol', 'os_end_of_life', 'asset', $2, 'fixture', 'high', 70,
		        'Fixture finding.', 'measured')`, tenant, host); err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	// The coverage record: the finding above says what the producer FOUND, this
	// says it looked. Two producers, one of which does not feed risk, so a
	// re-apply that lost the (tenant, asset, producer) key would show up here
	// as a collision rather than as silence.
	if _, err := db.Exec(`
		INSERT INTO producer_assessments (tenant_id, asset_id, producer)
		VALUES ($1, $2, 'eol'), ($1, $2, 'hygiene')`, tenant, host); err != nil {
		t.Fatalf("insert producer assessments: %v", err)
	}

	return assetInventoryFixture{tenantID: tenant, assetID: host, productID: product}
}

// seedAssetInventoryRows writes the same per-tenant fixture into a standalone
// database (one that has no testdb tenant helper attached to it), plus one row
// in each platform catalogue. Returns the tenant id.
func seedAssetInventoryRows(t *testing.T, db *sql.DB, slugPrefix string) uuid.UUID {
	t.Helper()
	tenant := uuid.New()
	slug := slugPrefix + "-" + strings.ReplaceAll(tenant.String(), "-", "")[:8]
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenant, "Asset inventory "+slug, slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	insertAssetInventoryFixture(t, db, tenant)

	// Platform catalogues, once — ON CONFLICT so the second tenant's call is a
	// no-op rather than a unique violation.
	for _, stmt := range []string{
		`INSERT INTO eol_catalogue (product_kind, vendor, product, cycle, eol_date, source_kind)
		 VALUES ('os', 'Canonical', 'ubuntu', '22.04', '2027-04-01', 'imported')
		 ON CONFLICT (product_kind, coalesce(vendor, ''), product, cycle) DO NOTHING`,
		`INSERT INTO vulnerability_catalogue (cve_id, cvss_version, cvss_score, severity, description, source_kind)
		 VALUES ('CVE-2026-00001', '3.1', 9.8, 'critical', 'Fixture row.', 'imported')
		 ON CONFLICT (cve_id) DO NOTHING`,
		`INSERT INTO vulnerability_matches (cve_id, cpe_match_string)
		 VALUES ('CVE-2026-00001', 'cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*')
		 ON CONFLICT (cve_id, coalesce(cpe_match_string, ''), coalesce(purl_range, '')) DO NOTHING`,
		`INSERT INTO classification_rules (rule_kind, pattern, class_key, vendor, confidence)
		 VALUES ('oui', '00:de:ad', 'switch', 'Fixture Networks', 0.80)
		 ON CONFLICT (rule_kind, pattern) DO NOTHING`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("seed platform catalogue row: %v\nstmt: %s", err, stmt)
		}
	}

	return tenant
}

// TestIntegration_AssetInventorySchema_AssetHistoryTargetsAssets pins the two
// things workstream 0.2 changed about the pre-existing asset_history table.
//
// Its composite FK referenced network_assets_partitioned, so a history row for
// one of the new `assets` rows was refused outright with a foreign-key
// violation. That made the table unusable by the identification engine
// (workstream 0.4), which records `merge_proposed` when an identifier
// collision opens a merge proposal, and by the 0.6 writer generally. The
// repoint is lossless because the table has never had a writer.
//
// `action` was also unconstrained text: a typo in a writer would be accepted
// and stay invisible until somebody filtered a timeline by an action that
// never matched — a write that reports success while recording nothing
// findable.
func TestIntegration_AssetInventorySchema_AssetHistoryTargetsAssets(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)

	tenant := testdb.NewTenant(t, owner)
	fixture := insertAssetInventoryFixture(t, owner, tenant)

	t.Run("accepts a row for an assets row", func(t *testing.T) {
		if _, err := owner.Exec(`
			INSERT INTO public.asset_history (asset_id, tenant_id, source, action)
			VALUES ($1, $2, 'identification', 'merge_proposed')`,
			fixture.assetID, tenant); err != nil {
			t.Fatalf("asset_history rejected a row for an `assets` row: %v\n"+
				"Its FK must reference assets(tenant_id, id), not network_assets_partitioned.", err)
		}
	})

	// DATA_MODEL §2 plus merge_proposed. Every one must be accepted, or a
	// writer that is correct by the design document fails at runtime.
	t.Run("accepts the whole action vocabulary", func(t *testing.T) {
		for _, action := range []string{
			"created", "updated", "merged_from", "merged_into", "merge_proposed",
			"approved", "denied", "classified", "endpoint_added",
			// The edge lifecycle (workstream 2.8, ADR-0003). `edge_added` alone
			// could not tell a declaration from an accepted proposal.
			"edge_added", "edge_removed", "edge_accepted", "edge_rejected",
			"archived",
		} {
			if _, err := owner.Exec(`
				INSERT INTO public.asset_history (asset_id, tenant_id, source, action)
				VALUES ($1, $2, 'probe', $3)`, fixture.assetID, tenant, action); err != nil {
				t.Errorf("asset_history rejected the documented action %q: %v", action, err)
			}
		}
	})

	t.Run("rejects an unregistered action", func(t *testing.T) {
		_, err := owner.Exec(`
			INSERT INTO public.asset_history (asset_id, tenant_id, source, action)
			VALUES ($1, $2, 'probe', 'merge_propsed')`, fixture.assetID, tenant)
		if err == nil {
			t.Fatal("asset_history accepted a misspelled action — the CHECK on `action` is missing, " +
				"so a typo in a writer lands silently and the row is never found by any filter")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "check constraint") {
			t.Fatalf("unregistered action failed with the wrong error: %v", err)
		}
	})

	t.Run("rejects a row for an asset that does not exist", func(t *testing.T) {
		_, err := owner.Exec(`
			INSERT INTO public.asset_history (asset_id, tenant_id, source, action)
			VALUES ($1, $2, 'probe', 'created')`, uuid.New(), tenant)
		if err == nil {
			t.Fatal("asset_history accepted a row for a nonexistent asset — the FK is missing")
		}
	})
}

// TestIntegration_AssetInventorySchema_FindingsReuseTheInactiveRow pins the
// partial unique index predicate. "Open" means NOT ARCHIVED — deliberately not
// `detection_state = 'ACTIVE'`. (It is the predicate the retired compliance
// findings table used, and workstream 3.1 kept it when that table's producer
// moved onto this one.)
//
// The difference is the INACTIVE state. A condition that stops being detected
// keeps its row; when it returns, the reconciler flips that row back to ACTIVE
// and bumps occurrence_count. Keying the index on ACTIVE alone leaves the
// INACTIVE row unmatched, so every resurfacing inserts a SECOND row — and
// occurrence_count and first_seen, the columns that exist to carry a finding's
// history, then each describe one episode of it instead of all of them.
func TestIntegration_AssetInventorySchema_FindingsReuseTheInactiveRow(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)

	tenant := testdb.NewTenant(t, owner)
	fixture := insertAssetInventoryFixture(t, owner, tenant)

	insert := func(summary string) error {
		_, err := owner.Exec(`
			INSERT INTO public.findings
				(tenant_id, producer, kind, subject_type, subject_id, severity, summary)
			VALUES ($1, 'hygiene', 'no_owner', 'asset', $2, 'low', $3)`,
			tenant, fixture.assetID, summary)
		return err
	}
	setState := func(state string) {
		t.Helper()
		if _, err := owner.Exec(
			`UPDATE public.findings SET detection_state = $1 WHERE tenant_id = $2 AND producer = 'hygiene'`,
			state, tenant); err != nil {
			t.Fatalf("set detection_state=%s: %v", state, err)
		}
	}

	if err := insert("first sighting"); err != nil {
		t.Fatalf("first finding: %v", err)
	}

	setState("INACTIVE")
	if err := insert("resurfaced"); err == nil {
		t.Fatal("a second finding was inserted for a subject that already has an INACTIVE one. " +
			"The predicate must be `detection_state <> 'ARCHIVED'`: on ACTIVE alone the reconciler " +
			"cannot find the row it is meant to revive, so every recurrence appends instead.")
	}

	// ARCHIVED is the soft-delete state and must NOT block a fresh finding —
	// the same check pointed the other way, so "fixed" cannot mean "nothing
	// can ever be inserted twice".
	setState("ARCHIVED")
	if err := insert("after the old row was archived"); err != nil {
		t.Fatalf("an ARCHIVED row blocked a new finding for the same subject: %v", err)
	}
}
