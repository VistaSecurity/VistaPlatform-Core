package services

// View-isolation hardening tests (the "inverse risk" left open by the Phase 4
// RLS sweep): a plain view executes with its OWNER's privileges, and the owner
// both owns the base tables and is exempt from their RLS — so every
// non-security_invoker view over RLS tables was a cross-tenant read path for
// the NOBYPASSRLS crypto_app role, and the cross-tenant materialized views
// were SELECT-able in full.
//
// These tests prove, against a real schema-loaded Postgres AS THE APP ROLE
// (an owner connection is structurally incapable of catching this class):
//   1. every view over RLS base tables carries security_invoker=true;
//   2. v_ci_inventory actually enforces tenant isolation through that flag —
//      tenant A sees only A, and no tenant context means zero rows;
//   3. crypto_app cannot SELECT the cross-tenant matviews directly;
//   4. the *_tenant wrapper views scope matview reads by app.tenant_id and
//      fail closed without it;
//   5. refresh_operational_views() is callable as crypto_app (REFRESH needs
//      matview ownership, so the function must be SECURITY DEFINER — as a
//      plain-invoker function it failed "must be owner" on every call since
//      the role split, silently letting the operational views go stale).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// invokerViews is every view over RLS-policied base tables. Keep in sync with
// the VIEW ISOLATION HARDENING block at the bottom of scripts/database/schema.sql.
var invokerViews = []string{
	// partition wrappers (flipped with the partition conversion)
	"network_assets", "sensor_discoveries", "crypto_implementations",
	// flipped by the view-isolation hardening
	"active_resource_alerts",
	"aws_daily_cost_summary", "aws_daily_service_cost_summary", "aws_tenant_monthly_cost_summary",
	"current_resource_usage_summary", "health_metrics_aggregated_view",
	"platform_integrations_summary", "tenant_health_summary_view",
	"user_tenant_permissions", "v_ci_inventory",
}

func TestIntegration_RLSViews_AllSecurityInvoker(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	for _, v := range invokerViews {
		var ok bool
		err := db.QueryRow(`
			SELECT 'security_invoker=true' = ANY(COALESCE(c.reloptions, '{}'))
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1 AND c.relkind = 'v'`, v).Scan(&ok)
		if err != nil {
			t.Fatalf("view %s: %v", v, err)
		}
		if !ok {
			t.Errorf("view %s lacks security_invoker=true — it executes as the owner and bypasses RLS", v)
		}
	}
}

func TestIntegration_VCIInventory_EnforcesRLS(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)

	tenantA := testdb.NewTenant(t, db)
	tenantB := testdb.NewTenant(t, db)
	assetA, assetB := uuid.New(), uuid.New()
	for _, r := range []struct {
		asset, tenant uuid.UUID
		host          string
	}{{assetA, tenantA, "rls-view-a.example.test"}, {assetB, tenantB, "rls-view-b.example.test"}} {
		mustExec(t, db, `
			INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW())`, r.asset, r.tenant, r.host)
	}

	countVisible := func(tx *sql.Tx) (n int) {
		t.Helper()
		// No WHERE tenant_id clause on purpose: isolation must come from RLS
		// through the view, not from the query text.
		if err := tx.QueryRow(
			`SELECT count(*) FROM v_ci_inventory WHERE id IN ($1, $2)`, assetA, assetB,
		).Scan(&n); err != nil {
			t.Fatalf("v_ci_inventory as app role: %v", err)
		}
		return n
	}

	testdb.AsTenant(t, db, tenantA, func(tx *sql.Tx) {
		if n := countVisible(tx); n != 1 {
			t.Errorf("tenant A sees %d of the two assets through v_ci_inventory, want exactly its own 1", n)
		}
	})
	testdb.AsRoleNoTenant(t, db, func(tx *sql.Tx) {
		if n := countVisible(tx); n != 0 {
			t.Errorf("app role with no tenant context sees %d rows through v_ci_inventory, want 0 (fail closed)", n)
		}
	})
}

func TestIntegration_Matviews_AppRoleDeniedDirectSelect(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)

	for _, mv := range []string{"mv_remediation_queue", "mv_location_finding_summary", "tenant_cost_summary"} {
		testdb.AsRoleNoTenant(t, db, func(tx *sql.Tx) {
			var n int
			err := tx.QueryRow(`SELECT count(*) FROM ` + mv).Scan(&n)
			if err == nil {
				t.Errorf("crypto_app can SELECT %s directly (%d rows) — the cross-tenant matview must be reachable only through its _tenant wrapper", mv, n)
			}
		})
	}
}

func TestIntegration_MatviewWrapper_TenantScopedAndFailClosed(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)

	tenantA := testdb.NewTenant(t, db)
	tenantB := testdb.NewTenant(t, db)
	locA, locB := uuid.New(), uuid.New()
	mustExec(t, db, `
		INSERT INTO locations (id, tenant_id, name, location_type, full_path)
		VALUES ($1,$2,'rls-wrapper-a','site','rls-wrapper-a'), ($3,$4,'rls-wrapper-b','site','rls-wrapper-b')`,
		locA, tenantA, locB, tenantB)
	// Populate the matview with both tenants' locations (owner refresh).
	mustExec(t, db, `SELECT refresh_operational_views()`)

	testdb.AsTenant(t, db, tenantA, func(tx *sql.Tx) {
		var n int
		if err := tx.QueryRow(
			`SELECT count(*) FROM mv_location_finding_summary_tenant WHERE location_id IN ($1,$2)`, locA, locB,
		).Scan(&n); err != nil {
			t.Fatalf("wrapper as tenant A: %v", err)
		}
		if n != 1 {
			t.Errorf("tenant A sees %d of the two locations through mv_location_finding_summary_tenant, want exactly its own 1", n)
		}
	})
	testdb.AsRoleNoTenant(t, db, func(tx *sql.Tx) {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM mv_location_finding_summary_tenant`).Scan(&n); err != nil {
			t.Fatalf("wrapper with no tenant context: %v", err)
		}
		if n != 0 {
			t.Errorf("app role with no tenant context sees %d rows through the wrapper, want 0 (fail closed)", n)
		}
	})
}

func TestIntegration_RefreshOperationalViews_CallableAsAppRole(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	// Autocommit on the app-role connection (not inside a tx: REFRESH
	// CONCURRENTLY refuses transaction blocks). SECURITY DEFINER is what makes
	// this succeed — REFRESH requires matview ownership, which crypto_app
	// doesn't have.
	if _, err := app.Exec(`SELECT refresh_operational_views()`); err != nil {
		t.Fatalf("refresh_operational_views() as crypto_app: %v — as a plain-invoker function this fails 'must be owner' and the operational matviews silently go stale", err)
	}
}
