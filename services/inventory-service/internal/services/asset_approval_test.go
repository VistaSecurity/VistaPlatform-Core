package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestAssetIngestionPendingApproval tests that new assets are created with pending_approval status
func TestIntegration_AssetIngestionPendingApproval(t *testing.T) {
	// Skip if no test database configured
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)

	// Everything below runs under the SHARED schema advisory lock.
	//
	// `make test-integration-db` and the nightly job run package binaries in
	// parallel against ONE Postgres, so a neighbouring binary can be applying
	// scripts/database/schema.sql while these ordinary writes are in flight.
	// The apply takes ACCESS EXCLUSIVE across the file and this test holds row
	// locks on the partitioned asset tables in a different order, so Postgres
	// breaks the cycle by killing one of them — and which one it kills is
	// whichever happened to be mid-statement. The server log is unambiguous:
	//
	//   DETAIL: Process A waits for AccessShareLock on <assets partition>;
	//           blocked by process B (schema.sql).
	//           Process B waits for AccessExclusiveLock ...; blocked by A.
	//
	// testdb.WithSchemaShareLock makes the overlap impossible instead of
	// retrying after it happens: the appliers take the same key EXCLUSIVELY,
	// and the shared mode means any number of these tests still run at once.
	// It goes AFTER getTestDBAndTenant, never around it — that helper applies
	// the schema itself and would block for ever waiting on the shared holder.
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		service := NewAssetService(db)

		// Create a new asset via ingestion
		findings := []IngestFinding{
			{
				Hostname:  stringPtr("test-server.example.com"),
				IPAddress: stringPtr("192.168.1.100"),
				Port:      intPtr(443),
				AssetType: "server",
				Protocol:  "TLS",
			},
		}

		inserted, err := service.IngestFindings(tenantID, findings)
		if err != nil {
			t.Fatalf("Failed to ingest findings: %v", err)
		}
		if inserted != 1 {
			t.Errorf("Expected 1 asset inserted, got %d", inserted)
		}

		// Verify asset was created with pending_approval status
		assets, _, err := service.GetAssets(tenantID, models.AssetFilters{
			AssetStatus: []string{"pending_approval"},
			Page:        1,
			PageSize:    10,
		})
		if err != nil {
			t.Fatalf("Failed to get assets: %v", err)
		}
		if len(assets) != 1 {
			t.Fatalf("Expected 1 asset, got %d", len(assets))
		}
		if assets[0].AssetStatus != "pending_approval" {
			t.Errorf("Expected status 'pending_approval', got '%s'", assets[0].AssetStatus)
		}
		if assets[0].Hostname == nil || *assets[0].Hostname != "test-server.example.com" {
			t.Errorf("Expected hostname 'test-server.example.com', got '%v'", assets[0].Hostname)
		}
	})
}

// TestSuppressionPreventsReDiscovery tests that denied assets are suppressed and not re-discovered
func TestIntegration_SuppressionPreventsReDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)

	// Under the shared schema lock — see the note on the first test in this
	// file for why every one of them needs it.
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		service := NewAssetService(db)
		userID := uuid.New()

		// Create an asset
		hostname := "denied-server.example.com"
		ipAddress := "10.0.0.50"
		port := 443

		input := models.AssetInput{
			Hostname:    &hostname,
			IPAddress:   &ipAddress,
			ClassKey:    assetclass.KeyServer,
			Tags:        models.JSONB{},
			Metadata:    models.JSONB{},
			AssetStatus: stringPtr("pending_approval"),
		}

		asset, err := service.CreateAsset(tenantID, input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Deny the asset
		err = service.DenyAssets(tenantID, []uuid.UUID{asset.ID}, userID)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify asset is denied
		deniedAssets, _, err := service.GetAssets(tenantID, models.AssetFilters{
			AssetStatus: []string{"denied"},
			Page:        1,
			PageSize:    10,
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		require.Len(t, deniedAssets, 1)
		assert.Equal(t, "denied", deniedAssets[0].AssetStatus)

		// Try to ingest the same asset again
		findings := []IngestFinding{
			{
				Hostname:  &hostname,
				IPAddress: &ipAddress,
				Port:      &port,
				AssetType: "server",
				Protocol:  "TLS",
			},
		}

		inserted, err := service.IngestFindings(tenantID, findings)
		if err != nil {
			t.Fatalf("Failed to ingest findings: %v", err)
		}
		// Should not create a new asset
		if inserted != 0 {
			t.Errorf("Expected 0 assets inserted (suppressed), got %d", inserted)
		}

		// Verify no new pending assets were created.
		//
		// Retried past the cross-binary races the shared integration database
		// produces: `make test-integration-db` and the nightly job run package
		// binaries in parallel against ONE Postgres, and a neighbouring package's
		// schema apply takes ACCESS EXCLUSIVE locks across it — which is enough to
		// deadlock this read-only list over the partitioned tables. It did, on a
		// full parallel run, and reported as "the suppression did not hold". Only
		// [testdb.IsTransientRace] errors are retried; a real failure is
		// deterministic and still fails on the first attempt.
		var pendingAssets []models.Asset
		testdb.RetryTransient(t, func() error {
			var listErr error
			pendingAssets, _, listErr = service.GetAssets(tenantID, models.AssetFilters{
				AssetStatus: []string{"pending_approval"},
				Page:        1,
				PageSize:    10,
			})
			return listErr
		})
		if len(pendingAssets) != 0 {
			t.Errorf("Expected 0 pending assets, got %d", len(pendingAssets))
		}
	})
}

// TestApproveAssets tests that assets can be approved and transition to monitoring
func TestIntegration_ApproveAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)

	// Under the shared schema lock — see the note on the first test in this
	// file for why every one of them needs it.
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		service := NewAssetService(db)

		// Create pending assets
		hostname1 := "server1.example.com"
		hostname2 := "server2.example.com"
		ip1 := "192.168.1.1"
		ip2 := "192.168.1.2"

		asset1, err := service.CreateAsset(tenantID, models.AssetInput{
			Hostname:  &hostname1,
			IPAddress: &ip1,
			ClassKey:  assetclass.KeyServer,
			Tags:      models.JSONB{},
			Metadata:  models.JSONB{},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		asset2, err := service.CreateAsset(tenantID, models.AssetInput{
			Hostname:  &hostname2,
			IPAddress: &ip2,
			ClassKey:  assetclass.KeyServer,
			Tags:      models.JSONB{},
			Metadata:  models.JSONB{},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Approve both assets
		err = service.ApproveAssets(tenantID, []uuid.UUID{asset1.ID, asset2.ID}, uuid.Nil)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify assets are now monitoring
		monitoringAssets, _, err := service.GetAssets(tenantID, models.AssetFilters{
			AssetStatus: []string{"monitoring"},
			Page:        1,
			PageSize:    10,
		})
		if err != nil {
			t.Fatalf("Failed to get assets: %v", err)
		}
		if len(monitoringAssets) != 2 {
			t.Errorf("Expected 2 monitoring assets, got %d", len(monitoringAssets))
		}

		// Verify pending assets count is zero
		pendingAssets, _, err := service.GetAssets(tenantID, models.AssetFilters{
			AssetStatus: []string{"pending_approval"},
			Page:        1,
			PageSize:    10,
		})
		if err != nil {
			t.Fatalf("Failed to get assets: %v", err)
		}
		if len(pendingAssets) != 0 {
			t.Errorf("Expected 0 pending assets, got %d", len(pendingAssets))
		}
	})
}

// TestDenyAssets tests that assets can be denied and suppressed
func TestIntegration_DenyAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)

	// Under the shared schema lock — see the note on the first test in this
	// file for why every one of them needs it.
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		service := NewAssetService(db)
		userID := uuid.New()

		// Create pending asset
		hostname := "deny-me.example.com"
		ipAddress := "10.0.0.100"
		port := 443

		asset, err := service.CreateAsset(tenantID, models.AssetInput{
			Hostname:  &hostname,
			IPAddress: &ipAddress,
			ClassKey:  assetclass.KeyServer,
			Tags:      models.JSONB{},
			Metadata:  models.JSONB{},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Deny the asset
		err = service.DenyAssets(tenantID, []uuid.UUID{asset.ID}, userID)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Verify asset is denied
		deniedAssets, _, err := service.GetAssets(tenantID, models.AssetFilters{
			AssetStatus: []string{"denied"},
			Page:        1,
			PageSize:    10,
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		require.Len(t, deniedAssets, 1)
		assert.Equal(t, "denied", deniedAssets[0].AssetStatus)

		// Verify suppression was added (by trying to ingest again)
		findings := []IngestFinding{
			{
				Hostname:  &hostname,
				IPAddress: &ipAddress,
				Port:      &port,
				AssetType: "server",
				Protocol:  "TLS",
			},
		}

		inserted, err := service.IngestFindings(tenantID, findings)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		assert.Equal(t, 0, inserted, "Suppressed asset should not be re-ingested")
	})
}

// TestGetAssetsDefaultStatusFilter tests that GetAssets defaults to monitoring status
func TestIntegration_GetAssetsDefaultStatusFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)

	// Under the shared schema lock — see the note on the first test in this
	// file for why every one of them needs it.
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		service := NewAssetService(db)

		// Create assets with different statuses
		hostname1 := "monitoring.example.com"
		hostname2 := "pending.example.com"
		hostname3 := "denied.example.com"
		ip1 := "192.168.1.10"
		ip2 := "192.168.1.11"
		ip3 := "192.168.1.12"

		// Create the monitoring asset, then APPROVE it.
		//
		// `AssetStatus` on the input is ignored on create, deliberately: the
		// approval status is evaluated server-side from the tenant's network
		// segments, so no request body can promote an asset past the approval
		// queue. These tests predate that rule and asserted the old behaviour;
		// approving is what a person actually does.
		monitoringAsset, err := service.CreateAsset(tenantID, models.AssetInput{
			Hostname:  &hostname1,
			IPAddress: &ip1,
			ClassKey:  assetclass.KeyServer,
			Tags:      models.JSONB{},
			Metadata:  models.JSONB{},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if err := service.ApproveAssets(tenantID, []uuid.UUID{monitoringAsset.ID}, uuid.Nil); err != nil {
			t.Fatalf("approve: %v", err)
		}

		// Create pending asset
		_, err = service.CreateAsset(tenantID, models.AssetInput{
			Hostname:  &hostname2,
			IPAddress: &ip2,
			ClassKey:  assetclass.KeyServer,
			Tags:      models.JSONB{},
			Metadata:  models.JSONB{},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Create denied asset
		deniedAsset, err := service.CreateAsset(tenantID, models.AssetInput{
			Hostname:  &hostname3,
			IPAddress: &ip3,
			ClassKey:  assetclass.KeyServer,
			Tags:      models.JSONB{},
			Metadata:  models.JSONB{},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		userID := seedTestUser(t, db, tenantID)
		err = service.DenyAssets(tenantID, []uuid.UUID{deniedAsset.ID}, userID)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Get assets without status filter (should default to monitoring)
		assets, count, err := service.GetAssets(tenantID, models.AssetFilters{
			Page:     1,
			PageSize: 10,
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected count 1 (monitoring only by default), got %d", count)
		}
		if len(assets) != 1 {
			t.Fatalf("Expected 1 asset, got %d", len(assets))
		}
		if assets[0].AssetStatus != "monitoring" {
			t.Errorf("Expected status 'monitoring', got '%s'", assets[0].AssetStatus)
		}
		if assets[0].Hostname == nil || *assets[0].Hostname != hostname1 {
			t.Errorf("Expected hostname '%s', got '%v'", hostname1, assets[0].Hostname)
		}
	})
}

// TestGetAssetsWithStatusFilter tests explicit status filtering
func TestIntegration_GetAssetsWithStatusFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)

	// Under the shared schema lock — see the note on the first test in this
	// file for why every one of them needs it.
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		service := NewAssetService(db)

		// Create assets with different statuses
		hostname1 := "monitoring.example.com"
		hostname2 := "pending.example.com"
		ip1 := "192.168.1.20"
		ip2 := "192.168.1.21"

		// Approved explicitly — CreateAsset ignores AssetStatus by design.
		approved, err := service.CreateAsset(tenantID, models.AssetInput{
			Hostname:  &hostname1,
			IPAddress: &ip1,
			ClassKey:  assetclass.KeyServer,
			Tags:      models.JSONB{},
			Metadata:  models.JSONB{},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if err := service.ApproveAssets(tenantID, []uuid.UUID{approved.ID}, uuid.Nil); err != nil {
			t.Fatalf("approve: %v", err)
		}

		_, err = service.CreateAsset(tenantID, models.AssetInput{
			Hostname:  &hostname2,
			IPAddress: &ip2,
			ClassKey:  assetclass.KeyServer,
			Tags:      models.JSONB{},
			Metadata:  models.JSONB{},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Get pending assets explicitly
		pendingAssets, count, err := service.GetAssets(tenantID, models.AssetFilters{
			AssetStatus: []string{"pending_approval"},
			Page:        1,
			PageSize:    10,
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		assert.Equal(t, 1, count)
		assert.Len(t, pendingAssets, 1)
		assert.Equal(t, "pending_approval", pendingAssets[0].AssetStatus)

		// Get multiple statuses
		allAssets, count, err := service.GetAssets(tenantID, models.AssetFilters{
			AssetStatus: []string{"monitoring", "pending_approval"},
			Page:        1,
			PageSize:    10,
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		assert.Equal(t, 2, count)
		assert.Len(t, allAssets, 2)
	})
}

// getTestDB opens the shared integration database with the schema and seed
// applied.
//
// It used to be `t.Skip("Test database connection not configured")` —
// UNCONDITIONALLY. Eleven of the twelve tests in this file and network_space_test.go
// therefore never ran, and they cover pending_approval, the deny suppression
// and network classification: the behaviour this workstream changed most. A
// test that always skips is not a test, and it reports as a pass.
// getTestDBAndTenant also creates a REAL tenant row.
//
// These tests used `uuid.New()` as a tenant id, which was fine while they never
// ran: `assets.tenant_id` has a foreign key to `tenants`, so the first insert
// fails outright once they do. A tenant id that names no tenant is not a
// lightweight fixture, it is a row the database refuses.
//
// It APPLIES the schema, so it takes the schema advisory lock EXCLUSIVELY for
// the duration of that apply. A caller that then writes ordinary rows must hold
// the same key in SHARED mode for the rest of its test (testdb.WithSchemaShareLock)
// — call it after this, never around it. See the note on the first test in this
// file. TestIntegration_ApprovalTests_HoldTheSchemaShareLock holds every test in
// the file to that.
func getTestDBAndTenant(t *testing.T) (*database.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	// No db.Close(): testdb.Connect registers its own t.Cleanup, and closing a
	// handle other tests in this binary share would break them.
	return &database.DB{DB: sqlx.NewDb(raw, "postgres")}, testdb.NewTenant(t, raw)
}

func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

// seedTestUser writes a real user row. `asset_history.actor_user_id` and
// `asset_suppressions.created_by` both have foreign keys to `users`, so a
// decision attributed to a random uuid is rejected by the database — which is
// correct, and is why these fixtures create a person.
func seedTestUser(t *testing.T, db *database.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO users (id, tenant_id, email, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, true, NOW(), NOW())`,
		id, tenantID, "fixture-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}
