package services

// GetTenantActivitySummary's api_calls used to be polled from
// resource-tracker-service, with an inventory-size formula substituted when
// that peer was unreachable (B-12). The peer is retired: the count is
// now the tenant's own rows in tenant_resource_usage over the last 30 days,
// read in the same RLS-scoped transaction as the rest of the summary. This
// test asserts the figure is that sum — another tenant's rows and rows older
// than the window excluded — and that nothing is reported as unavailable.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ActivitySummary_APICallsAreTheTenantsMeteredSum(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	other := testdb.NewTenant(t, raw)

	for i := 0; i < 3; i++ {
		if _, err := db.Exec(`
			INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, $3, 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`,
			uuid.New(), tenant, "activity-summary-"+uuid.NewString()[:8]+".example.test"); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
	}
	// Metered samples: two in the window for this tenant (7 + 5), one just
	// outside it, and one for another tenant.
	for _, row := range []struct {
		tenant uuid.UUID
		calls  int
		age    string
	}{{tenant, 7, "1 day"}, {tenant, 5, "20 days"}, {tenant, 1000, "31 days"}, {other, 999, "1 day"}} {
		if _, err := raw.Exec(`
			INSERT INTO tenant_resource_usage (tenant_id, "timestamp", api_calls)
			VALUES ($1, NOW() - $3::interval, $2)`, row.tenant, row.calls, row.age); err != nil {
			t.Fatalf("insert usage: %v", err)
		}
	}

	svc := &AssetService{db: db}
	summary, err := svc.GetTenantActivitySummary(tenant)
	if err != nil {
		t.Fatalf("GetTenantActivitySummary: %v", err)
	}

	if summary.APICalls != 12 {
		t.Errorf("api_calls = %d, want 12 (7 + 5 within 30 days, this tenant only)", summary.APICalls)
	}
	if len(summary.UnavailableSources) != 0 {
		t.Errorf("unavailable_sources = %v, want none — no peer is polled any more", summary.UnavailableSources)
	}
	if summary.FeatureUsage["assets"] != 3 {
		t.Errorf("feature_usage[assets] = %d, want 3", summary.FeatureUsage["assets"])
	}
}
