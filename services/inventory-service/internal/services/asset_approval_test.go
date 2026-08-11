package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// TestAssetIngestionPendingApproval tests that new assets are created with pending_approval status
func TestAssetIngestionPendingApproval(t *testing.T) {
	// Skip if no test database configured
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	service := NewAssetService(db)
	tenantID := uuid.New()

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
}

// TestSuppressionPreventsReDiscovery tests that denied assets are suppressed and not re-discovered
func TestSuppressionPreventsReDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	service := NewAssetService(db)
	tenantID := uuid.New()
	userID := uuid.New()

	// Create an asset
	hostname := "denied-server.example.com"
	ipAddress := "10.0.0.50"
	port := 443

	input := models.AssetInput{
		Hostname:    &hostname,
		IPAddress:   &ipAddress,
		Port:        &port,
		AssetType:   "server",
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

	// Verify no new pending assets were created
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
}

// TestApproveAssets tests that assets can be approved and transition to monitoring
func TestApproveAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	service := NewAssetService(db)
	tenantID := uuid.New()

	// Create pending assets
	hostname1 := "server1.example.com"
	hostname2 := "server2.example.com"
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"
	port := 443

	asset1, err := service.CreateAsset(tenantID, models.AssetInput{
		Hostname:    &hostname1,
		IPAddress:   &ip1,
		Port:        &port,
		AssetType:   "server",
		Tags:        models.JSONB{},
		Metadata:    models.JSONB{},
		AssetStatus: stringPtr("pending_approval"),
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	asset2, err := service.CreateAsset(tenantID, models.AssetInput{
		Hostname:    &hostname2,
		IPAddress:   &ip2,
		Port:        &port,
		AssetType:   "server",
		Tags:        models.JSONB{},
		Metadata:    models.JSONB{},
		AssetStatus: stringPtr("pending_approval"),
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Approve both assets
	err = service.ApproveAssets(tenantID, []uuid.UUID{asset1.ID, asset2.ID})
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
}

// TestDenyAssets tests that assets can be denied and suppressed
func TestDenyAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	service := NewAssetService(db)
	tenantID := uuid.New()
	userID := uuid.New()

	// Create pending asset
	hostname := "deny-me.example.com"
	ipAddress := "10.0.0.100"
	port := 443

	asset, err := service.CreateAsset(tenantID, models.AssetInput{
		Hostname:    &hostname,
		IPAddress:   &ipAddress,
		Port:        &port,
		AssetType:   "server",
		Tags:        models.JSONB{},
		Metadata:    models.JSONB{},
		AssetStatus: stringPtr("pending_approval"),
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
}

// TestGetAssetsDefaultStatusFilter tests that GetAssets defaults to monitoring status
func TestGetAssetsDefaultStatusFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	service := NewAssetService(db)
	tenantID := uuid.New()

	// Create assets with different statuses
	hostname1 := "monitoring.example.com"
	hostname2 := "pending.example.com"
	hostname3 := "denied.example.com"
	ip1 := "192.168.1.10"
	ip2 := "192.168.1.11"
	ip3 := "192.168.1.12"
	port := 443

	// Create monitoring asset
	_, err := service.CreateAsset(tenantID, models.AssetInput{
		Hostname:    &hostname1,
		IPAddress:   &ip1,
		Port:        &port,
		AssetType:   "server",
		Tags:        models.JSONB{},
		Metadata:    models.JSONB{},
		AssetStatus: stringPtr("monitoring"),
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Create pending asset
	_, err = service.CreateAsset(tenantID, models.AssetInput{
		Hostname:    &hostname2,
		IPAddress:   &ip2,
		Port:        &port,
		AssetType:   "server",
		Tags:        models.JSONB{},
		Metadata:    models.JSONB{},
		AssetStatus: stringPtr("pending_approval"),
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Create denied asset
	deniedAsset, err := service.CreateAsset(tenantID, models.AssetInput{
		Hostname:    &hostname3,
		IPAddress:   &ip3,
		Port:        &port,
		AssetType:   "server",
		Tags:        models.JSONB{},
		Metadata:    models.JSONB{},
		AssetStatus: stringPtr("pending_approval"),
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	userID := uuid.New()
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
}

// TestGetAssetsWithStatusFilter tests explicit status filtering
func TestGetAssetsWithStatusFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDB(t)
	defer func() { _ = db.Close() }()

	service := NewAssetService(db)
	tenantID := uuid.New()

	// Create assets with different statuses
	hostname1 := "monitoring.example.com"
	hostname2 := "pending.example.com"
	ip1 := "192.168.1.20"
	ip2 := "192.168.1.21"
	port := 443

	_, err := service.CreateAsset(tenantID, models.AssetInput{
		Hostname:    &hostname1,
		IPAddress:   &ip1,
		Port:        &port,
		AssetType:   "server",
		Tags:        models.JSONB{},
		Metadata:    models.JSONB{},
		AssetStatus: stringPtr("monitoring"),
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	_, err = service.CreateAsset(tenantID, models.AssetInput{
		Hostname:    &hostname2,
		IPAddress:   &ip2,
		Port:        &port,
		AssetType:   "server",
		Tags:        models.JSONB{},
		Metadata:    models.JSONB{},
		AssetStatus: stringPtr("pending_approval"),
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
}

// Helper functions
func getTestDB(t *testing.T) *database.DB {
	// This would need to be configured based on your test setup
	// For now, this is a placeholder that would need actual DB connection
	t.Skip("Test database connection not configured")
	return nil
}

func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}
