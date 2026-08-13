package services

// M-1: crypto-configurations (GetCryptoImplementations) must exclude
// implementations on a pending-approval asset, matching the scope
// risk/summary's total_crypto and the PQC classifier now use — otherwise the
// Inventory Configuration lens total disagrees with the Dashboard "Configs"
// count and Remediation's PQC progress total for the same tenant.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CryptoConfigurations_ExcludesPendingApprovalAssets(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewCryptoImplementationService(db)

	monitoring := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'monitored.example.test','server','monitoring',NOW(),NOW(),NOW(),NOW())`, monitoring, tenant); err != nil {
		t.Fatalf("insert monitoring asset: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',NOW(),NOW())`, uuid.New(), tenant, monitoring); err != nil {
		t.Fatalf("insert implementation on monitoring asset: %v", err)
	}

	pending := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'pending.example.test','server','pending_approval',NOW(),NOW(),NOW(),NOW())`, pending, tenant); err != nil {
		t.Fatalf("insert pending asset: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',NOW(),NOW())`, uuid.New(), tenant, pending); err != nil {
		t.Fatalf("insert implementation on pending asset: %v", err)
	}

	_, total, err := svc.GetCryptoImplementations(tenant, models.CryptoImplementationFilters{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("GetCryptoImplementations: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1 (the pending-approval asset's config must be excluded)", total)
	}
}
