package services

// Guards for GetRiskSummary's asset-status scoping (M-3 / M-1).
//
// risk/summary used to count every non-deleted asset regardless of
// asset_status, so a still-pending-approval asset (and any crypto
// configuration on it) inflated total_assets/total_crypto/critical_findings
// relative to every Inventory lens, which already default to
// asset_status = 'monitoring' (buildAssetListWhereAndHaving). This pinned the
// fix: risk/summary now scopes to the same 'monitoring' population, so
// "N monitored assets" on the Dashboard/Posture agrees with the lenses.
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

func TestIntegration_GetRiskSummary_ExcludesPendingApprovalAssets(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	monitoring := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'monitored.example.test','server','monitoring',NOW(),NOW(),NOW(),NOW())`, monitoring, tenant); err != nil {
		t.Fatalf("insert monitoring asset: %v", err)
	}
	pending := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'pending.example.test','server','pending_approval',NOW(),NOW(),NOW(),NOW())`, pending, tenant); err != nil {
		t.Fatalf("insert pending asset: %v", err)
	}

	// A high-risk crypto implementation on the PENDING asset — must not count
	// toward total_crypto or critical_findings if it correctly excludes
	// pending assets.
	implID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, risk_score, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',95,NOW(),NOW())`, implID, tenant, pending); err != nil {
		t.Fatalf("insert implementation on pending asset: %v", err)
	}

	summary, err := svc.GetRiskSummary(tenant)
	if err != nil {
		t.Fatalf("GetRiskSummary: %v", err)
	}
	if summary.TotalAssets != 1 {
		t.Errorf("total_assets = %d, want 1 (pending-approval asset must be excluded)", summary.TotalAssets)
	}
	if summary.TotalCrypto != 0 {
		t.Errorf("total_crypto = %d, want 0 (the pending asset's crypto config must be excluded)", summary.TotalCrypto)
	}
	if summary.CriticalFindings != 0 {
		t.Errorf("critical_findings = %d, want 0 (the pending asset's Critical-scored config must be excluded)", summary.CriticalFindings)
	}
	if sum := summary.HighRisk + summary.MediumRisk + summary.LowRisk + summary.UnknownRisk; sum != summary.TotalAssets {
		t.Errorf("risk bands sum to %d, want total_assets %d", sum, summary.TotalAssets)
	}
}
