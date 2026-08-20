package services

// Guard for B-42: the deny flow's suppression fingerprint.
//
// inventory-service has read and written `asset_suppressions` since the deny
// flow shipped, and the table existed in no DDL, seed or chart file — it had
// never been created in any commit. Neither call site could reveal that:
// isSuppressed folded EVERY error (including `relation "asset_suppressions"
// does not exist`) into `false, nil`, and addSuppression's error went to a bare
// stdout Printf while DenyAssets still returned nil. So deny reported success,
// the fingerprint was never recorded, and docsv4/core/features/asset-approval.md
// documented a mechanism that could not work.
//
// The primary deny guard — the `asset_status = 'denied'` check on the existing
// network_assets row — masks this for as long as that row survives. The
// fingerprint only carries the promise once the row is gone, which is the case
// the second test below reproduces.
//
// These are DB-integration tests because the entire bug was "the table is not
// there": a fake or mocked DB reproduces neither the failure nor the fix.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). Addresses are RFC 5737 documentation ranges.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newSuppressionFixture(t *testing.T) (*AssetService, *database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	return NewAssetService(db), db, tenant
}

// TestIntegration_DenyAssets_RecordsSuppression proves the deny path actually
// writes a fingerprint row. Before the fix this failed at the table itself; had
// the table merely lacked its (tenant_id, suppression_key) UNIQUE constraint it
// would have failed at the INSERT's `ON CONFLICT` arbiter with 42P10 instead,
// so this exercises both.
func TestIntegration_DenyAssets_RecordsSuppression(t *testing.T) {
	svc, db, tenant := newSuppressionFixture(t)

	assetID := uuid.New()
	host := "denied-host.example.test"
	ip := "192.0.2.44"
	port := 443
	mustExec(t, db.DB.DB, `
		INSERT INTO network_assets (id, tenant_id, hostname, ip_address, port, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,'server','pending_approval',NOW(),NOW(),NOW(),NOW())`,
		assetID, tenant, host, ip, port)

	if err := svc.DenyAssets(tenant, []uuid.UUID{assetID}, uuid.New()); err != nil {
		t.Fatalf("DenyAssets: %v", err)
	}

	// The row must exist, under the right tenant, keyed by the same fingerprint
	// the ingest path will later compute.
	wantKey := buildSuppressionKey(&host, &ip, &port)
	var n int
	if err := db.DB.DB.QueryRow(
		`SELECT COUNT(*) FROM asset_suppressions WHERE tenant_id = $1 AND suppression_key = $2`,
		tenant, wantKey,
	).Scan(&n); err != nil {
		t.Fatalf("count suppressions: %v", err)
	}
	if n != 1 {
		t.Fatalf("asset_suppressions rows for the denied fingerprint = %d, want 1 — "+
			"deny recorded no suppression, so a re-discovered denied host would come back", n)
	}

	// Denying twice must not error: addSuppression relies on ON CONFLICT DO
	// NOTHING, which needs the UNIQUE constraint to exist.
	if err := svc.DenyAssets(tenant, []uuid.UUID{assetID}, uuid.New()); err != nil {
		t.Fatalf("second DenyAssets (ON CONFLICT DO NOTHING path): %v", err)
	}
}

// TestIntegration_Suppression_PreventsRediscoveryAfterDelete is the case the
// fingerprint exists for: the denied asset row is gone, so the
// `asset_status == "denied"` guard cannot fire, and only the suppression key
// stands between the next discovery and a fresh pending_approval asset.
func TestIntegration_Suppression_PreventsRediscoveryAfterDelete(t *testing.T) {
	svc, db, tenant := newSuppressionFixture(t)

	assetID := uuid.New()
	host := "gone-host.example.test"
	ip := "192.0.2.45"
	port := 8443
	mustExec(t, db.DB.DB, `
		INSERT INTO network_assets (id, tenant_id, hostname, ip_address, port, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,'server','pending_approval',NOW(),NOW(),NOW(),NOW())`,
		assetID, tenant, host, ip, port)

	if err := svc.DenyAssets(tenant, []uuid.UUID{assetID}, uuid.New()); err != nil {
		t.Fatalf("DenyAssets: %v", err)
	}

	// Hard-delete the denied row, removing the primary guard entirely.
	mustExec(t, db.DB.DB, `DELETE FROM network_assets WHERE id = $1`, assetID)

	suppressed, err := svc.isSuppressed(tenant, &host, &ip, &port)
	if err != nil {
		t.Fatalf("isSuppressed returned an error: %v", err)
	}
	if !suppressed {
		t.Fatal("isSuppressed = false for a fingerprint that was just denied — " +
			"the denied host would reappear in Discovery → Approvals as a fresh pending asset")
	}

	// Negative polarity: an unrelated fingerprint must NOT be suppressed, or the
	// assertion above would pass for a function that returns true for everything.
	otherHost := "never-denied.example.test"
	otherIP := "192.0.2.46"
	suppressed, err = svc.isSuppressed(tenant, &otherHost, &otherIP, &port)
	if err != nil {
		t.Fatalf("isSuppressed (unrelated fingerprint): %v", err)
	}
	if suppressed {
		t.Fatal("isSuppressed = true for a fingerprint that was never denied")
	}

	// And the suppression must not leak across tenants: the same fingerprint
	// under a different tenant is a different host.
	otherTenant := testdb.NewTenant(t, db.DB.DB)
	suppressed, err = svc.isSuppressed(otherTenant, &host, &ip, &port)
	if err != nil {
		t.Fatalf("isSuppressed (other tenant): %v", err)
	}
	if suppressed {
		t.Fatal("a suppression recorded for one tenant matched another tenant's discovery")
	}
}
