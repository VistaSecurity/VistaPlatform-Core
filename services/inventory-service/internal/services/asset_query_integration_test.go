package services

// The query language against a real Postgres, and the two properties a list
// page has to hold whatever its size.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedAsset writes one asset with n endpoints and one identifier.
func seedAsset(t *testing.T, db *database.DB, tenant uuid.UUID, hostname, class, classPath, env string, risk int, endpoints int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, display_name, primary_address, class_key, class_path,
		                    environment, asset_status, risk_score, risk_assessed_by,
		                    last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,$3,'198.51.100.10',$4,$5,$6::environment_type,'monitoring',$7,
		        CASE WHEN $7 > 0 THEN ARRAY['crypto']::text[] ELSE ARRAY[]::text[] END,
		        NOW(),NOW(),NOW(),NOW())`,
		id, tenant, hostname, class, classPath, env, risk); err != nil {
		t.Fatalf("insert asset %s: %v", hostname, err)
	}
	for i := 0; i < endpoints; i++ {
		if _, err := db.Exec(`
			INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, protocol, status,
			                             first_seen_at, last_seen_at, created_at, updated_at)
			VALUES ($1,$2,$3,'198.51.100.10',$4,'tcp','TLS','active',NOW(),NOW(),NOW(),NOW())`,
			uuid.New(), tenant, id, 440+i); err != nil {
			t.Fatalf("insert endpoint %d for %s: %v", i, hostname, err)
		}
	}
	if _, err := db.Exec(`
		INSERT INTO asset_identifiers (id, tenant_id, asset_id, kind, value, source_kind, confidence,
		                               first_seen_at, last_seen_at, created_at, updated_at)
		VALUES ($1,$2,$3,'fqdn',$4,'measured',1,NOW(),NOW(),NOW(),NOW())`,
		uuid.New(), tenant, id, hostname); err != nil {
		t.Fatalf("insert identifier for %s: %v", hostname, err)
	}
	return id
}

// TestIntegration_AssetQuery_FiltersAndDoesNotMultiply is the list's two
// headline properties at once: a query-language predicate actually selects, and
// an asset with five endpoints is ONE row with five endpoints in it.
//
// The endpoint-multiplication half is the one worth stating: the pre-phase-1
// model made a host exposing five services five assets, and the obvious way to
// "fix" the read is a join that brings them all back as five rows.
func TestIntegration_AssetQuery_FiltersAndDoesNotMultiply(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	// See newIdentityFixture: this test applies the schema, so it must hold the
	// shared schema lock while it writes or it can deadlock against another
	// package binary's apply and report as a failure of the logic under test.
	testdb.HoldSchemaShareLock(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	fiveEndpoints := seedAsset(t, db, tenant, "web-01.example.test", "server", "hardware.computer.server", "production", 75, 5)
	seedAsset(t, db, tenant, "db-01.example.test", "managed_database", "cloud_resource.managed_database", "staging", 20, 1)
	// An asset with NO endpoints — an at-rest resource. It must still be one
	// row, with an empty endpoint list and no fabricated port.
	atRest := seedAsset(t, db, tenant, "bucket.example.test", "object_storage", "cloud_resource.object_storage", "production", 0, 0)

	t.Run("one row per asset, endpoints alongside", func(t *testing.T) {
		assets, total, err := svc.GetAssets(tenant, models.AssetFilters{Query: "class:server"})
		if err != nil {
			t.Fatalf("GetAssets: %v", err)
		}
		if total != 1 || len(assets) != 1 {
			t.Fatalf("a host with five endpoints must be ONE row, got total=%d rows=%d", total, len(assets))
		}
		a := assets[0]
		if a.ID != fiveEndpoints {
			t.Fatalf("wrong asset: %s", a.ID)
		}
		if len(a.Endpoints) != 5 {
			t.Errorf("the row must carry all five endpoints, got %d", len(a.Endpoints))
		}
		if a.PrimaryEndpoint == nil {
			t.Error("an asset with endpoints must name a primary one")
		}
		if len(a.Identifiers) != 1 {
			t.Errorf("identifiers must be loaded with the page, got %d", len(a.Identifiers))
		}
	})

	t.Run("an asset with no endpoints is a row, not a fabricated port", func(t *testing.T) {
		assets, _, err := svc.GetAssets(tenant, models.AssetFilters{Query: "class:object_storage"})
		if err != nil {
			t.Fatalf("GetAssets: %v", err)
		}
		if len(assets) != 1 || assets[0].ID != atRest {
			t.Fatalf("expected the at-rest asset, got %d rows", len(assets))
		}
		if assets[0].PrimaryEndpoint != nil {
			t.Errorf("an at-rest resource has NO endpoint; got %+v", assets[0].PrimaryEndpoint)
		}
		if assets[0].Endpoints == nil {
			t.Error("the endpoint list must marshal as [] rather than null")
		}
	})

	t.Run("the class facet is a subtree", func(t *testing.T) {
		// `class:cloud_resource` must reach both cloud children and neither
		// server. Getting this wrong in the safe-looking direction (exact
		// match) makes every parent facet read zero.
		assets, total, err := svc.GetAssets(tenant, models.AssetFilters{Query: "class:cloud_resource"})
		if err != nil {
			t.Fatalf("GetAssets: %v", err)
		}
		if total != 2 {
			t.Fatalf("class:cloud_resource must match the whole branch, got %d", total)
		}
		for _, a := range assets {
			if strings.HasPrefix(a.ClassPath, "hardware") {
				t.Errorf("a hardware asset leaked into the cloud_resource subtree: %s", a.ClassPath)
			}
		}
	})

	t.Run("the risk band comes from the ladder", func(t *testing.T) {
		high, _, err := svc.GetAssets(tenant, models.AssetFilters{Query: "risk >= high"})
		if err != nil {
			t.Fatalf("GetAssets: %v", err)
		}
		if len(high) != 1 || high[0].ID != fiveEndpoints {
			t.Fatalf("risk >= high must select the 75-scoring asset, got %d rows", len(high))
		}
		// A 0 with an EMPTY risk_assessed_by is NOT ASSESSED, and is neither
		// informational nor anything else (§5.2). The at-rest asset was seeded
		// with score 0 and no assessors.
		informational, _, err := svc.GetAssets(tenant, models.AssetFilters{Query: "risk:informational"})
		if err != nil {
			t.Fatalf("GetAssets: %v", err)
		}
		for _, a := range informational {
			if a.ID == atRest {
				t.Error("an unassessed asset must not band as informational; that is the 'not assessed rendered as passed' bug")
			}
		}
	})

	t.Run("legacy filter params still work and compose with a query", func(t *testing.T) {
		assets, _, err := svc.GetAssets(tenant, models.AssetFilters{
			Query:       "class:cloud_resource",
			Environment: []string{"production"},
		})
		if err != nil {
			t.Fatalf("GetAssets: %v", err)
		}
		if len(assets) != 1 || assets[0].ID != atRest {
			t.Fatalf("the two predicates must AND, got %d rows", len(assets))
		}
	})

	t.Run("an invalid query is a structured 400, not a 500", func(t *testing.T) {
		_, _, err := svc.GetAssets(tenant, models.AssetFilters{Query: "hostnaem:web-1"})
		if err == nil {
			t.Fatal("an unknown field must be refused")
		}
		qe, ok := AsQueryError(err)
		if !ok {
			t.Fatalf("expected a QueryError, got %T", err)
		}
		if len(qe.Errors) == 0 || qe.Errors[0].Code != "unknown_field" {
			t.Fatalf("expected unknown_field, got %v", qe.Errors)
		}
	})
}

// TestIntegration_AssetQuery_NoTenantPredicate is the isolation invariant from
// the other side.
//
// shared/query asserts that the TRANSLATOR emits no tenant predicate. This
// asserts the consequence: the read is scoped by RLS, so running the same
// compiled clause under a different tenant's session returns that tenant's
// rows and no others. If the translator ever started emitting one, a bug in it
// would look like an isolation control — and this is the test that would still
// be green while that happened, which is why it checks the ROWS rather than the
// SQL text.
func TestIntegration_AssetQuery_NoTenantPredicate(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)

	// Seeded as the OWNER (RLS is dormant for it, which is what lets a fixture
	// write both tenants' rows) and READ as the app role, which is the
	// connection production uses and the only one RLS applies to.
	//
	// This test used to read as the owner too — and RLS is inert for a table
	// owner, so the rows came back because `SetTenantContext` set a GUC that
	// nothing consulted. Deleting that call left the suite green: the read was
	// being narrowed by nothing at all, and the test that existed to prove
	// isolation proved only that two tenants had one asset each.
	ownerDB := &database.DB{DB: sqlx.NewDb(owner, "postgres")}
	seedAsset(t, ownerDB, tenantA, "a-web.example.test", "server", "hardware.computer.server", "production", 10, 1)
	seedAsset(t, ownerDB, tenantB, "b-web.example.test", "server", "hardware.computer.server", "production", 10, 1)

	app := testdb.ConnectAsAppRole(t, owner)
	// AFTER ConnectAsAppRole, and that ordering is the whole point.
	//
	// The shared lock and the EXCLUSIVE one the appliers take are the same
	// advisory key, and an advisory lock is SESSION-scoped: the share holder sits
	// on one connection of this pool while ConnectAsAppRole's EnsureRLSAppRole
	// asks for the exclusive key on another, so it waits on us and we never
	// release — a hang with no timeout, not a deadlock Postgres can break. Taking
	// the lock before this line wedged the whole package binary for its full ten
	// minutes, and every other binary's schema apply behind it.
	//
	// "After whatever applied the schema" is not the whole rule: it is after
	// anything that takes the key exclusively, and ConnectAsAppRole does.
	testdb.HoldSchemaShareLock(t, owner)
	svc := &AssetService{db: &database.DB{DB: sqlx.NewDb(app, "postgres")}}

	for name, tenant := range map[string]uuid.UUID{"A": tenantA, "B": tenantB} {
		assets, total, err := svc.GetAssets(tenant, models.AssetFilters{Query: "class:server"})
		if err != nil {
			t.Fatalf("tenant %s: %v", name, err)
		}
		if total != 1 || len(assets) != 1 {
			t.Fatalf("tenant %s: expected exactly its own asset, got %d", name, total)
		}
		if !strings.HasPrefix(*assets[0].Hostname, strings.ToLower(name)+"-") {
			t.Fatalf("tenant %s saw %q — RLS did not narrow the read", name, *assets[0].Hostname)
		}
		// And the OTHER tenant's asset is not merely absent from the page: it
		// is unreachable. A query that names it by hostname still returns
		// nothing, which is the assertion a page-size coincidence cannot fake.
		other := "b-web.example.test"
		if name == "B" {
			other = "a-web.example.test"
		}
		foreign, n, err := svc.GetAssets(tenant, models.AssetFilters{Query: `hostname="` + other + `"`})
		if err != nil {
			t.Fatalf("tenant %s: querying the other tenant's hostname: %v", name, err)
		}
		if n != 0 || len(foreign) != 0 {
			t.Errorf("tenant %s reached tenant %s's asset by name (%d rows) — RLS is not isolating this read",
				name, map[string]string{"A": "B", "B": "A"}[name], n)
		}
	}

	// And the clause itself: no tenant_id anywhere in it, which is what makes
	// the above a statement about RLS rather than about a WHERE clause.
	pred, err := buildAssetWhere("class:server", models.AssetFilters{}, 2, assetQueryAlias)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(pred.Where, "tenant_id") {
		t.Fatalf("the translator must emit no tenant predicate; got %s", pred.Where)
	}
}

// TestIntegration_AssetQuery_RoundTripsIsBounded is the N+1 guard.
//
// A page of any size is FOUR statements: count, page, one batched endpoint
// load, one batched identifier load. The obvious regression — loading each
// asset's endpoints in the scan loop — passes every other test in this file and
// only shows up as latency, so it is measured rather than reviewed for.
//
// Mutation-checked: replacing loadEndpointsForAssets with a per-asset query
// takes the count from 4 to 4+N and fails here.
func TestIntegration_AssetQuery_RoundTripsIsBounded(t *testing.T) {
	dsn := os.Getenv(testdb.URLEnv)
	if dsn == "" {
		t.Skipf("%s not set", testdb.URLEnv)
	}
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	// See newIdentityFixture: this test applies the schema, so it must hold the
	// shared schema lock while it writes or it can deadlock against another
	// package binary's apply and report as a failure of the logic under test.
	testdb.HoldSchemaShareLock(t, raw)
	tenant := testdb.NewTenant(t, raw)

	seedDB := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	const assets = 12
	for i := 0; i < assets; i++ {
		seedAsset(t, seedDB, tenant, fmt.Sprintf("host-%02d.example.test", i),
			"server", "hardware.computer.server", "production", 10, 3)
	}

	counted, statements, err := openCounting(dsn)
	if err != nil {
		t.Fatalf("open counting connection: %v", err)
	}
	defer func() { _ = counted.Close() }()

	svc := &AssetService{db: &database.DB{DB: sqlx.NewDb(counted, "postgres")}}
	statements.Store(0)
	got, total, err := svc.GetAssets(tenant, models.AssetFilters{Query: "class:server", PageSize: 50})
	if err != nil {
		t.Fatalf("GetAssets: %v", err)
	}
	if total != assets || len(got) != assets {
		t.Fatalf("expected %d assets, got total=%d rows=%d", assets, total, len(got))
	}
	for _, a := range got {
		if len(a.Endpoints) != 3 {
			t.Fatalf("%s carries %d endpoints, want 3 — the batched load is not attaching", *a.Hostname, len(a.Endpoints))
		}
	}

	// The tenant transaction costs a few statements of its own (BEGIN, the
	// SET LOCAL, COMMIT), so the bound is generous. What it cannot absorb is a
	// per-row query: twelve assets would add twelve.
	const bound = 12
	if n := statements.Load(); n > bound {
		t.Fatalf("a page of %d assets took %d statements; the bound is %d. "+
			"A per-asset child query is the usual cause.", assets, n, bound)
	}
}

// ------------------------------------------------- the counting connection --

// openCounting wraps lib/pq's connector and counts every statement that reaches
// the server.
//
// It measures round trips rather than expectations, which is the point: a mock
// would assert the queries this code writes TODAY, where this asserts the
// property that matters (the count does not grow with the page).
func openCounting(dsn string) (*sql.DB, *atomic.Int64, error) {
	inner, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, nil, err
	}
	n := &atomic.Int64{}
	return sql.OpenDB(&countingConnector{inner: inner, n: n}), n, nil
}

type countingConnector struct {
	inner driver.Connector
	n     *atomic.Int64
}

func (c *countingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, n: c.n}, nil
}

func (c *countingConnector) Driver() driver.Driver { return c.inner.Driver() }

type countingConn struct {
	driver.Conn
	n *atomic.Int64
}

func (c *countingConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.n.Add(1)
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

func (c *countingConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.n.Add(1)
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func (c *countingConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	c.n.Add(1)
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}

func (c *countingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
