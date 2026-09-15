package services

// The hierarchical class facet — the dashboard's class bars and the rail's
// class branch.
//
// It was rewritten in seeds part 3 for cost: it expanded every ASSET into its
// ancestor prefixes and then grouped, so the LATERAL ran once per asset. The
// expense was not the work — the expansion itself was 76 ms at 50,000 assets —
// it was that `generate_series(1, <expr>)` carries no row estimate, so the
// planner costed the join at fifty million rows and crossed the JIT threshold:
// 164 of the 243 ms were spent COMPILING a plan for a query touching 1,389
// pages. Counting the distinct class paths FIRST and summing across the
// expansion runs the LATERAL a dozen times instead of fifty thousand, and the
// estimate that falls out never reaches the threshold. Measured 243 ms → 13 ms.
//
// That kind of rewrite is exactly the kind that can change the ANSWER without
// changing the shape of it, so this pins the arithmetic:
//
//   - every ancestor of a class counts, not only the leaf (a parent reading
//     zero is how a hierarchical facet usually goes wrong);
//   - an asset is counted ONCE per ancestor, not once per asset per ancestor —
//     the difference between sum-of-groups and count-of-rows is invisible
//     until two assets share a path;
//   - the filters still apply.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AssetFacets_ClassCountsEveryAncestorOnce(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	add := func(hostname, classKey, classPath string) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status,
			                    last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'monitoring', NOW(), NOW(), NOW(), NOW())`,
			uuid.New(), tenant, hostname, classKey, classPath); err != nil {
			t.Fatalf("insert %s: %v", hostname, err)
		}
	}

	// Three servers and one switch, so `hardware` has four, `hardware.computer`
	// three, and the two leaves three and one. Three assets SHARE a path, which
	// is what separates "sum the per-path counts" from "count the expanded
	// rows" — both give the same answer when every path is unique.
	add("srv-1", "server", "hardware.computer.server")
	add("srv-2", "server", "hardware.computer.server")
	add("srv-3", "server", "hardware.computer.server")
	add("sw-1", "switch", "hardware.network_device.switch")
	// There is no unclassified case to cover here: `assets.class_path` is NOT
	// NULL, so every row is on some branch.

	buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{}, "class", 50)
	if err != nil {
		t.Fatalf("GetAssetFacets(class): %v", err)
	}
	got := map[string]int{}
	for _, b := range buckets {
		got[b.Key] = b.Count
	}

	for key, want := range map[string]int{
		"hardware":                       4,
		"hardware.computer":              3,
		"hardware.computer.server":       3,
		"hardware.network_device":        1,
		"hardware.network_device.switch": 1,
	} {
		if got[key] != want {
			t.Errorf("class facet %q = %d, want %d (buckets: %v)", key, got[key], want, got)
		}
	}
	if len(got) != 5 {
		t.Errorf("got %d buckets (%v), want exactly the 5 ancestors of the two classes", len(got), got)
	}

	// The label is the LEAF key resolved through the class registry, while the
	// bucket key stays the PATH — that is what the query language's `class:`
	// term matches on.
	for _, b := range buckets {
		if b.Key == "hardware.computer.server" && b.Label == "" {
			t.Error("the leaf bucket has no label; the rail would render a blank row")
		}
	}
}

// The facet still narrows. A rewrite that dropped the caller's predicate would
// pass every count assertion above, because the fixture there has no filter.
func TestIntegration_AssetFacets_ClassRespectsTheQueryPredicate(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	add := func(hostname, classKey, classPath, env string) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, environment, asset_status,
			                    last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'monitoring', NOW(), NOW(), NOW(), NOW())`,
			uuid.New(), tenant, hostname, classKey, classPath, env); err != nil {
			t.Fatalf("insert %s: %v", hostname, err)
		}
	}
	add("prod-1", "server", "hardware.computer.server", "production")
	add("prod-2", "server", "hardware.computer.server", "production")
	add("dev-1", "server", "hardware.computer.server", "development")

	buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{Query: `environment="production"`}, "class", 50)
	if err != nil {
		t.Fatalf("GetAssetFacets(class, production): %v", err)
	}
	for _, b := range buckets {
		if b.Key == "hardware.computer.server" && b.Count != 2 {
			t.Errorf("hardware.computer.server = %d under environment=production, want 2 — the predicate is not reaching the class facet", b.Count)
		}
		if b.Key == "hardware" && b.Count != 2 {
			t.Errorf("hardware = %d under environment=production, want 2 — an ancestor counted outside the filter", b.Count)
		}
	}
}
