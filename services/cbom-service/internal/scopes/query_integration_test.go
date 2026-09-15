package scopes

// A scope's query, end to end against a real Postgres: it is stored, versioned
// and audited as TEXT, and the seeded defaults are legal.
//
// What it deliberately does NOT do is re-check what a query MEANS. That is
// shared/query's job, checked once there for every surface — and the whole
// point of the change is that cbom-service no longer has an opinion about it.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ScopeQuery_StoredVersionedAndAudited(t *testing.T) {
	raw := testdb.Connect(t)
	tenant := testdb.NewTenant(t, raw)
	// scopes.tenant_id has no FK to tenants, so dropping the tenant row does not
	// take the scopes with it.
	t.Cleanup(func() {
		_, _ = raw.Exec(`DELETE FROM public.scopes WHERE tenant_id = ANY($1)`, pq.Array([]uuid.UUID{tenant}))
	})
	repo := NewRepository(&database.DB{DB: sqlx.NewDb(raw, "postgres")})
	ctx := context.Background()
	user := uuid.New()

	seeded, err := repo.SeedDefaultsIfMissing(ctx, tenant, user)
	if err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	if !seeded {
		t.Fatal("a fresh tenant must get the three system scopes")
	}

	list, err := repo.List(ctx, tenant)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d seeded scopes, want 3", len(list))
	}

	byName := map[string]Scope{}
	for _, s := range list {
		byName[s.Name] = s
	}

	t.Run("the seeded queries survive the round trip and still validate", func(t *testing.T) {
		for name, want := range map[string]string{
			string(DefaultAll):        "",
			string(DefaultProduction): "environment:production",
		} {
			got, ok := byName[name]
			if !ok {
				t.Fatalf("seeded scope %q is missing", name)
			}
			if got.Query != want {
				t.Errorf("%s query = %q, want %q", name, got.Query, want)
			}
		}
		nonDev := byName[string(DefaultNonDevTest)]
		if !strings.Contains(nonDev.Query, "environment") || !strings.Contains(nonDev.Query, "tag:") {
			t.Errorf("Non-Dev/Test lost an arm in the round trip: %q", nonDev.Query)
		}
		for _, s := range list {
			if _, err := ValidateQuery(s.Query); err != nil {
				t.Errorf("seeded scope %q does not validate after a round trip: %v", s.Name, err)
			}
		}
	})

	t.Run("editing the query bumps the version and writes an audit row", func(t *testing.T) {
		prod := byName[string(DefaultProduction)]
		updated, err := repo.Update(ctx, tenant, prod.ID, user, UpdateRequest{
			Name:  prod.Name,
			Query: "environment:production and not tag:pci-out-of-scope",
		})
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if updated.Version != prod.Version+1 {
			t.Errorf("version = %d, want %d — a changed boundary must be a new version, "+
				"because an artifact pins scope_id + scope_version", updated.Version, prod.Version+1)
		}

		var before, after string
		if err := raw.QueryRow(`SELECT query_before, query_after FROM scopes_audit
			WHERE scope_id = $1 ORDER BY created_at DESC LIMIT 1`, prod.ID).Scan(&before, &after); err != nil {
			t.Fatalf("read the audit row: %v", err)
		}
		if before != prod.Query || after != updated.Query {
			t.Errorf("audit recorded %q -> %q, want %q -> %q", before, after, prod.Query, updated.Query)
		}
	})

	t.Run("an unchanged save does NOT bump the version", func(t *testing.T) {
		// The version bump compares the stored TEXT, so a canonical-form round
		// trip has to be stable: re-saving a scope unchanged must not look like
		// an edit, or every open-and-close of the editor would invent a version
		// an artifact could pin.
		all := byName[string(DefaultAll)]
		again, err := repo.Update(ctx, tenant, all.ID, user, UpdateRequest{Name: all.Name, Query: all.Query})
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if again.Version != all.Version {
			t.Errorf("version = %d, want %d — re-saving an unchanged scope must not bump it",
				again.Version, all.Version)
		}
	})
}

// TestIntegration_SeededNonDevTest_KeepsUnmeasuredAssets runs the seeded
// Non-Dev/Test query against real rows, which is the only way to see the thing
// that went wrong.
//
// `not environment in (development, test)` alone EXCLUDES an asset whose
// environment is unset: a comparison against an absent value is UNKNOWN and so
// is its negation (QUERY_LANGUAGE §5.2), and SQL agrees — `NOT (NULL IN (…))`
// is NULL, and a NULL WHERE drops the row. On a discovered inventory that is
// most assets, so the scope would have quietly narrowed a CBOM's attestation
// boundary to only what somebody had already labelled. The jsonb predicate it
// replaced kept them, because its `inSet` returned FALSE for an unset value
// rather than unknown.
//
// The scope's name is a promise about dev and test, not about the unmeasured.
// This is the test of that promise, and it is EXECUTED rather than asserted on
// the query text, because the text read correctly both before and after.
func TestIntegration_SeededNonDevTest_KeepsUnmeasuredAssets(t *testing.T) {
	raw := testdb.Connect(t)
	tenant := testdb.NewTenant(t, raw)

	seed := func(hostname string, environment *string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := raw.Exec(`
			INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path,
			                    environment, asset_status, last_seen_at, first_discovered_at)
			VALUES ($1,$2,$3,$3,'server','hardware.computer.server',$4::environment_type,'monitoring',NOW(),NOW())`,
			id, tenant, hostname, environment); err != nil {
			t.Fatalf("insert %s: %v", hostname, err)
		}
		return id
	}
	production, development := "production", "development"
	prod := seed("prod.example.test", &production)
	dev := seed("dev.example.test", &development)
	// The one that matters: discovered, never labelled.
	unmeasured := seed("unlabelled.example.test", nil)

	var nonDevTest string
	for _, s := range systemDefaults(tenant, uuid.New()) {
		if s.Name == string(DefaultNonDevTest) {
			nonDevTest = s.Query
		}
	}
	if nonDevTest == "" {
		t.Fatal("the Non-Dev/Test default is missing")
	}

	cat := query.DefaultCatalog()
	opts := query.DefaultOptionsFor(cat)
	opts.SQL.ParamStart = 2
	opts.SQL.OuterAlias = "a"
	compiled, err := query.Compile(nonDevTest, AssetTarget, cat, opts)
	if err != nil {
		t.Fatalf("the seeded query does not compile: %v", err)
	}

	rows, err := raw.Query(
		`SELECT a.id FROM assets a WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND (`+compiled.Where+`)`,
		append([]any{tenant}, compiled.Args...)...)
	if err != nil {
		t.Fatalf("run the seeded query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	matched := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		matched[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	if !matched[unmeasured] {
		t.Error("an asset with NO environment must stay IN Non-Dev/Test — it is not dev and it is " +
			"not test, and dropping it silently narrows the boundary a CBOM attests to")
	}
	if !matched[prod] {
		t.Error("a production asset must be in Non-Dev/Test")
	}
	if matched[dev] {
		t.Error("a development asset must be excluded — that is the whole scope")
	}
}
