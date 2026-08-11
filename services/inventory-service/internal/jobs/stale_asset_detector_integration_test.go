package jobs

// Integration proof that stale-asset detection reaches tenants who never
// configured a lifecycle policy — which is every tenant onboarded through
// signup.
//
// The detector used to enumerate `asset_lifecycle_policies WHERE
// auto_archive_enabled`, but a policy row is only created when someone opens
// Settings and saves one (and by the seed, only for tenants that existed at
// seed time). So signup tenants were skipped and their assets never aged, while
// the UI showed the in-memory default (30/60-day auto-archive) and looked
// enabled. These tests pin the fix and the opt-out that must still hold.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newDetector(t *testing.T) (*StaleAssetDetector, *database.DB, *sql.DB) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return NewStaleAssetDetector(db, services.NewAssetLifecycleService(db)), db, raw
}

// insertMonitoredAsset adds one monitored asset last seen `daysAgo` days back,
// for a tenant that has NO lifecycle-policy row.
func insertMonitoredAsset(t *testing.T, db *database.DB, tenant uuid.UUID, daysAgo int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, $3, 'server', 'monitoring', NOW() - ($4 || ' days')::interval, NOW() - ($4 || ' days')::interval, NOW(), NOW())`,
		id, tenant, "stale-"+id.String()[:8]+".example.test", daysAgo)
	if err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return id
}

func staleStatus(t *testing.T, db *database.DB, assetID uuid.UUID) *string {
	t.Helper()
	var s *string
	if err := db.QueryRow(`SELECT stale_status FROM network_assets WHERE id = $1`, assetID).Scan(&s); err != nil {
		t.Fatalf("read stale_status: %v", err)
	}
	return s
}

func TestIntegration_StaleDetector_ProcessesTenantWithoutAPolicyRow(t *testing.T) {
	det, db, raw := newDetector(t)
	tenant := testdb.NewTenant(t, raw) // fresh tenant, created after seed -> no policy row

	// Sanity: this tenant genuinely has no policy row (the bug precondition).
	var policyRows int
	if err := db.QueryRow(`SELECT count(*) FROM asset_lifecycle_policies WHERE tenant_id = $1`, tenant).Scan(&policyRows); err != nil {
		t.Fatal(err)
	}
	if policyRows != 0 {
		t.Fatalf("precondition: tenant unexpectedly has %d policy rows", policyRows)
	}

	asset := insertMonitoredAsset(t, db, tenant, 90) // 90 days > default 60-day archive

	// The enumerator must now include this tenant (the whole fix).
	tenants, err := det.tenantsToProcess()
	if err != nil {
		t.Fatalf("tenantsToProcess: %v", err)
	}
	found := false
	for _, id := range tenants {
		if id == tenant {
			found = true
		}
	}
	if !found {
		t.Fatal("tenant with assets but no policy row was NOT enumerated — the staleness bug is back")
	}

	// End to end: it must actually get archived under the default policy.
	if err := det.processTenant(context.Background(), tenant); err != nil {
		t.Fatalf("processTenant: %v", err)
	}
	got := staleStatus(t, db, asset)
	if got == nil || *got != "archived" {
		t.Fatalf("asset stale_status = %v, want \"archived\" (90 days stale, default 60-day policy)", got)
	}
}

// A tenant that explicitly disabled auto-archive must still be left alone — the
// enumerator now includes them, so the per-tenant guard is what protects them.
func TestIntegration_StaleDetector_RespectsExplicitOptOut(t *testing.T) {
	det, db, raw := newDetector(t)
	tenant := testdb.NewTenant(t, raw)

	if _, err := db.Exec(`
		INSERT INTO asset_lifecycle_policies (tenant_id, stale_warning_days, stale_archived_days, auto_archive_enabled, notifications_enabled)
		VALUES ($1, 30, 60, false, false)`, tenant); err != nil {
		t.Fatalf("insert opt-out policy: %v", err)
	}
	asset := insertMonitoredAsset(t, db, tenant, 90)

	if err := det.processTenant(context.Background(), tenant); err != nil {
		t.Fatalf("processTenant: %v", err)
	}
	if got := staleStatus(t, db, asset); got != nil {
		t.Errorf("asset was aged despite auto_archive_enabled=false (stale_status=%q)", *got)
	}
}
