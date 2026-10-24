package services

// POST /infrastructure-assets/enrich-all is called by every seed and QA loader
// right after it declares a tenant's prefixes, before the tenant has a single
// asset. The backfill must answer that with 0 updates, not an error.
//
// Skips without TEST_DATABASE_URL.

import (
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_EnrichAllAssets_EmptyTenantIsNotAnError(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAssetService(db)

	updated, err := svc.EnrichAllAssets(tenant)
	if err != nil {
		t.Fatalf("EnrichAllAssets on a tenant with no assets: %v", err)
	}
	if updated != 0 {
		t.Fatalf("EnrichAllAssets on an empty tenant reported %d updates", updated)
	}
}
