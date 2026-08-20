package services

// B-12 (second site): GetTenantActivitySummary's api_calls came from
// resource-tracker-service, and when that peer was unreachable the code
// substituted an inventory-size formula:
//
//	assetCount*2 + cryptoCount + keyCount + libraryCount + integrationCount*5
//
// which has nothing to do with API traffic. That number reached
// tenant-health-service as a measurement. This test asserts the formula is
// gone: with the peer unreachable, api_calls is 0 and the source is NAMED.
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

func TestIntegration_ActivitySummary_UnreachableTrackerReportsUnknownNotAnEstimate(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	// Point the poll at a port nothing listens on, which is what a failed mTLS
	// handshake looks like to this caller.
	t.Setenv("RESOURCE_TRACKER_URL", "http://127.0.0.1:1")

	// Enough inventory that the old estimation formula would have produced a
	// clearly non-zero number (3 assets → at least 6).
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(`
			INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW())`,
			uuid.New(), tenant, "activity-summary-"+uuid.NewString()[:8]+".example.test"); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
	}

	svc := &AssetService{db: db}
	summary, err := svc.GetTenantActivitySummary(tenant)
	if err != nil {
		t.Fatalf("GetTenantActivitySummary: %v", err)
	}

	if summary.APICalls != 0 {
		t.Errorf("api_calls = %d, want 0 — an unreachable resource-tracker must not be "+
			"replaced by an inventory-derived estimate", summary.APICalls)
	}
	found := false
	for _, s := range summary.UnavailableSources {
		if s == "resource-tracker-service" {
			found = true
		}
	}
	if !found {
		t.Errorf("unavailable_sources = %v, want resource-tracker-service named so the "+
			"consumer can report api_calls as UNKNOWN", summary.UnavailableSources)
	}
	// The DB-derived parts of the summary must still be measured.
	if summary.FeatureUsage["assets"] != 3 {
		t.Errorf("feature_usage[assets] = %d, want 3", summary.FeatureUsage["assets"])
	}
}
