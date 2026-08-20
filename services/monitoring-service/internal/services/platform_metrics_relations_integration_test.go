package services

// Guard for B-41: GetTenantStatuses, GetPlatformMetrics and GetTenantMetrics
// all joined a relation named `assets`. No such relation has ever existed in
// any commit — the asset spine is `network_assets`, a view over
// `network_assets_partitioned`.
//
// The failure modes differed and both were bad. GetTenantStatuses propagated
// the error, so GET /admin-service/status/tenants and /tenants/:id answered 500
// on every call, forever. The two metrics handlers discarded it with
// `if err == nil { ... }`, so /admin/status and /admin-service/status/metrics
// reported total_tenants / active_tenants / total_users / total_assets as 0 on
// a populated platform, inside a 200, with nothing logged — a query that could
// not run reporting a healthy, empty platform.
//
// These tests assert the queries EXECUTE and return the real counts. A test
// that only asserted "no error" would have passed on a query returning zeros,
// so the counts are checked too.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedTenantWithAssets creates one tenant, one user and n non-deleted assets
// (plus one soft-deleted asset, which must NOT be counted), and returns the
// tenant id.
func seedTenantWithAssets(t *testing.T, db *sqlx.DB, liveAssets int) uuid.UUID {
	t.Helper()
	tenant := uuid.New()
	slug := "b41-" + uuid.NewString()[:8]
	if _, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, created_at, updated_at)
		VALUES ($1,$2,$3,NOW(),NOW())`, tenant, "B41 "+slug, slug); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name,
		                   is_active, last_login_at, created_at, updated_at)
		VALUES ($1,$2,$3,'x','B','41',true,NOW(),NOW(),NOW())`,
		uuid.New(), tenant, slug+"@example.test"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	for i := 0; i < liveAssets; i++ {
		if _, err := db.Exec(`
			INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status,
			                            last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW())`,
			uuid.New(), tenant, slug+"-live.example.test"); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
	}
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status,
		                            last_seen_at, first_discovered_at, created_at, updated_at, deleted_at)
		VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW(),NOW())`,
		uuid.New(), tenant, slug+"-gone.example.test"); err != nil {
		t.Fatalf("insert deleted asset: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM network_assets WHERE tenant_id = $1`, tenant)
		_, _ = db.Exec(`DELETE FROM users WHERE tenant_id = $1`, tenant)
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})
	return tenant
}

func TestIntegration_PlatformMetrics_QueriesARealRelation(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	// Same-package construction: NewMetricsService opens its own pools from
	// config/env, which this test has no need to reproduce.
	svc := &MetricsService{db: raw, bypassDB: raw}

	tenant := seedTenantWithAssets(t, db, 3)

	metrics, err := svc.GetPlatformMetrics()
	if err != nil {
		t.Fatalf("GetPlatformMetrics: %v — the query joined a relation named "+
			"\"assets\" that does not exist (B-41), and the HTTP handler discarded "+
			"exactly this error behind a 200 with all four counts zeroed", err)
	}
	if metrics.TotalTenants < 1 {
		t.Errorf("TotalTenants = %d, want >= 1", metrics.TotalTenants)
	}
	if metrics.TotalUsers < 1 {
		t.Errorf("TotalUsers = %d, want >= 1", metrics.TotalUsers)
	}
	if metrics.TotalAssets < 3 {
		t.Errorf("TotalAssets = %d, want >= 3 (the seeded live assets)", metrics.TotalAssets)
	}

	tenantMetrics, err := svc.GetTenantMetrics(tenant.String())
	if err != nil {
		t.Fatalf("GetTenantMetrics: %v (B-41)", err)
	}
	if tenantMetrics.TotalAssets != 3 {
		t.Errorf("GetTenantMetrics.TotalAssets = %d, want 3 — the soft-deleted asset "+
			"must be excluded", tenantMetrics.TotalAssets)
	}
	if tenantMetrics.TotalUsers != 1 {
		t.Errorf("GetTenantMetrics.TotalUsers = %d, want 1", tenantMetrics.TotalUsers)
	}
}

func TestIntegration_TenantStatuses_QueriesARealRelation(t *testing.T) {
	raw := testdb.Connect(t)
	db := sqlx.NewDb(raw, "postgres")
	svc := &HealthService{bypassDB: raw}

	tenant := seedTenantWithAssets(t, db, 2)

	statuses, err := svc.GetTenantStatuses()
	if err != nil {
		t.Fatalf("GetTenantStatuses: %v — this error reached the client as a "+
			"blanket 500 on GET /admin-service/status/tenants, every call (B-41)", err)
	}
	var found bool
	for _, s := range statuses {
		if s.TenantID == tenant.String() {
			found = true
			if s.AssetCount != 2 {
				t.Errorf("AssetCount = %d, want 2 — the soft-deleted asset must be excluded", s.AssetCount)
			}
			if s.UserCount != 1 {
				t.Errorf("UserCount = %d, want 1", s.UserCount)
			}
			if s.Status != "healthy" {
				t.Errorf("Status = %q, want healthy (users > 0 AND assets > 0)", s.Status)
			}
		}
	}
	if !found {
		t.Errorf("seeded tenant %s missing from GetTenantStatuses (%d rows)", tenant, len(statuses))
	}
}
