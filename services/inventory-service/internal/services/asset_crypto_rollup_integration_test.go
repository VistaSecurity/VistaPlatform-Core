package services

// Integration proof for the crypto rollup the asset LIST query returns:
// crypto_implementation_count and protocol_summary.
//
// Why these exist: the Inventory Infrastructure row needs a per-asset
// configuration count and protocol badges. Without them on the LIST payload the
// row can only get that data from the per-asset child query, which is
// lazy-loaded on expand — rendering badges from it would mean one request per
// visible row (a 50-request waterfall per page).
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

func newRollupSvc(t *testing.T) (*AssetService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	return &AssetService{db: db}, db, tenant
}

func insertRollupAsset(t *testing.T, db *database.DB, tenant uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, ip_address, asset_type, asset_status, created_at, updated_at)
		VALUES ($1, $2, $3, '192.0.2.10'::inet, 'server', 'monitoring', NOW(), NOW())`,
		id, tenant, hostname)
	if err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return id
}

func insertRollupImpl(t *testing.T, db *database.DB, tenant, asset uuid.UUID, protocol string, risk *int, deleted bool) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO crypto_implementations
			(id, tenant_id, asset_id, protocol, discovery_method, risk_score, deleted_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'passive', $5, CASE WHEN $6 THEN NOW() ELSE NULL END, NOW(), NOW())`,
		uuid.New(), tenant, asset, protocol, risk, deleted)
	if err != nil {
		t.Fatalf("insert crypto implementation: %v", err)
	}
}

func findAsset(t *testing.T, assets []models.Asset, id uuid.UUID) models.Asset {
	t.Helper()
	for _, a := range assets {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("asset %s not present in the list response", id)
	return models.Asset{}
}

func TestIntegration_GetAssets_CryptoRollup(t *testing.T) {
	svc, db, tenant := newRollupSvc(t)

	withCrypto := insertRollupAsset(t, db, tenant, "rollup-host")
	bare := insertRollupAsset(t, db, tenant, "bare-host")

	high, low, unassessed := 82, 12, 0
	insertRollupImpl(t, db, tenant, withCrypto, "TLS", &high, false)
	insertRollupImpl(t, db, tenant, withCrypto, "TLS", &low, false)
	insertRollupImpl(t, db, tenant, withCrypto, "SSH", &unassessed, false)
	// Soft-deleted rows must not be counted or badged.
	insertRollupImpl(t, db, tenant, withCrypto, "SMB", &high, true)

	assets, _, err := svc.GetAssets(tenant, models.AssetFilters{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("GetAssets: %v", err)
	}

	got := findAsset(t, assets, withCrypto)
	if got.CryptoImplementationCount == nil {
		t.Fatal("CryptoImplementationCount is nil — the LIST query no longer populates it")
	}
	if *got.CryptoImplementationCount != 3 {
		t.Errorf("CryptoImplementationCount = %d, want 3 (soft-deleted rows excluded)", *got.CryptoImplementationCount)
	}

	if len(got.ProtocolSummary) != 2 {
		t.Fatalf("ProtocolSummary = %+v, want 2 entries (TLS, SSH; the deleted SMB row excluded)", got.ProtocolSummary)
	}
	// Ordered by count descending, so TLS (2) precedes SSH (1).
	if got.ProtocolSummary[0].Protocol != "TLS" || got.ProtocolSummary[0].Count != 2 {
		t.Errorf("ProtocolSummary[0] = %+v, want TLS x2 first", got.ProtocolSummary[0])
	}
	// Worst-component-wins: the badge tone must follow the 82, not the 12.
	if got.ProtocolSummary[0].MaxRiskScore != 82 {
		t.Errorf("TLS MaxRiskScore = %d, want 82 (the worst of 82/12)", got.ProtocolSummary[0].MaxRiskScore)
	}
	// 0 here means NOT ASSESSED. It must survive as 0 so the UI can say so
	// rather than banding it as a low-risk result.
	if got.ProtocolSummary[1].Protocol != "SSH" || got.ProtocolSummary[1].MaxRiskScore != 0 {
		t.Errorf("ProtocolSummary[1] = %+v, want SSH with MaxRiskScore 0", got.ProtocolSummary[1])
	}

	// An asset with no crypto reports a real zero and an empty summary — the
	// row prints "no crypto seen", which is a fact, not a blank.
	none := findAsset(t, assets, bare)
	if none.CryptoImplementationCount == nil || *none.CryptoImplementationCount != 0 {
		t.Errorf("bare asset CryptoImplementationCount = %v, want 0", none.CryptoImplementationCount)
	}
	if len(none.ProtocolSummary) != 0 {
		t.Errorf("bare asset ProtocolSummary = %+v, want empty", none.ProtocolSummary)
	}
}
