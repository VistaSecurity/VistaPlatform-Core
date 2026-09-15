package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The DB-backed tests in this file share getTestDBAndTenant with
// asset_approval_test.go, and with it the same exposure: `make
// test-integration-db` and the nightly job run package binaries in PARALLEL
// against one Postgres, so a neighbouring binary can be applying
// scripts/database/schema.sql while these ordinary writes are in flight. The
// apply takes ACCESS EXCLUSIVE across the partitioned asset tables; these tests
// hold row locks on them in a different order; Postgres breaks the cycle by
// killing whichever session was mid-statement. The failure names this test and
// has nothing to do with network spaces:
//
//	DETAIL: Process A waits for AccessShareLock on <partition>; blocked by B.
//	        Process B waits for AccessExclusiveLock on <partition>; blocked by A.
//	        Process B: -- Vista Platform - Consolidated Database Schema ...
//
// testdb.HoldSchemaShareLock makes the overlap impossible rather than retrying
// after it: the appliers take the same advisory key EXCLUSIVELY, and the shared
// mode means any number of these tests still run at once. It goes AFTER
// getTestDBAndTenant, never before — that helper applies the schema itself and
// takes the same key exclusively to do it.
//
// asset_approval_sharelock_test.go is the source-level guard that every test
// using the shared fixture takes the lock, in this file and in that one.

// TestClassifyAssetInternal tests that assets in defined CIDR ranges are classified as 'internal'
func TestIntegration_ClassifyAssetInternal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)
	testdb.HoldSchemaShareLock(t, db.DB.DB) // see the file comment above

	service := NewNetworkSpaceService(db)
	userID := seedTestUser(t, db, tenantID)

	// Create a network space for internal network
	spaces := []models.NetworkSpace{
		{
			ID:          uuid.New().String(),
			Type:        "cidr",
			Value:       "192.168.100.0/24",
			NetworkType: "private",
			Description: "Development network",
			IsActive:    true,
		},
	}

	err := service.SaveNetworkSpaces(tenantID, userID, spaces)
	require.NoError(t, err, "Failed to save network spaces")

	// Test IP in the CIDR range
	ip := "192.168.100.50"
	hostname := stringPtr("dev-server.example.com")
	ownership, err := service.ClassifyAsset(tenantID, &ip, hostname, []string{})
	require.NoError(t, err)
	assert.Equal(t, "internal", ownership, "Asset in CIDR range should be classified as 'internal'")

	// Test IP not in any CIDR range
	externalIP := "203.0.113.10"
	ownership2, err := service.ClassifyAsset(tenantID, &externalIP, nil, []string{})
	require.NoError(t, err)
	assert.Equal(t, "third_party", ownership2, "Asset not in any CIDR range should be classified as 'third_party'")
}

// TestClassifyAssetThirdParty tests that assets not matching any network space are classified as 'third_party'
func TestIntegration_ClassifyAssetThirdParty(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)
	testdb.HoldSchemaShareLock(t, db.DB.DB) // see the file comment above

	service := NewNetworkSpaceService(db)

	// No network spaces defined
	ip := "203.0.113.10"
	ownership, err := service.ClassifyAsset(tenantID, &ip, nil, []string{})
	require.NoError(t, err)
	assert.Equal(t, "unknown", ownership, "Asset with no network spaces defined should be 'unknown'")

	// Create a network space
	userID := seedTestUser(t, db, tenantID)
	spaces := []models.NetworkSpace{
		{
			ID:          uuid.New().String(),
			Type:        "cidr",
			Value:       "192.168.100.0/24",
			NetworkType: "private",
			IsActive:    true,
		},
	}
	err = service.SaveNetworkSpaces(tenantID, userID, spaces)
	require.NoError(t, err)

	// Test IP not in the CIDR range
	externalIP := "203.0.113.10"
	ownership2, err := service.ClassifyAsset(tenantID, &externalIP, nil, []string{})
	require.NoError(t, err)
	assert.Equal(t, "third_party", ownership2, "Asset not matching any network space should be 'third_party'")
}

// TestGetTagsForAssetSingleMatch tests that tags are applied when asset matches one network space
func TestIntegration_GetTagsForAssetSingleMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)
	testdb.HoldSchemaShareLock(t, db.DB.DB) // see the file comment above

	service := NewNetworkSpaceService(db)
	userID := seedTestUser(t, db, tenantID)

	// Create a network space with tags
	spaces := []models.NetworkSpace{
		{
			ID:          uuid.New().String(),
			Type:        "cidr",
			Value:       "192.168.100.0/24",
			NetworkType: "private",
			Description: "Development network",
			IsActive:    true,
			Tags: map[string]interface{}{
				"environment": "dev",
				"team":        "backend",
			},
		},
	}

	err := service.SaveNetworkSpaces(tenantID, userID, spaces)
	require.NoError(t, err)

	// Test IP in the CIDR range
	ip := "192.168.100.50"
	tags, err := service.GetTagsForAsset(tenantID, &ip, nil, []string{})
	require.NoError(t, err)

	assert.Equal(t, "dev", tags["environment"], "Tag 'environment' should be 'dev'")
	assert.Equal(t, "backend", tags["team"], "Tag 'team' should be 'backend'")
	assert.Len(t, tags, 2, "Should have 2 tags")
}

// TestGetTagsForAssetMultipleMatches tests that tags are merged when asset matches multiple network spaces
func TestIntegration_GetTagsForAssetMultipleMatches(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)
	testdb.HoldSchemaShareLock(t, db.DB.DB) // see the file comment above

	service := NewNetworkSpaceService(db)
	userID := seedTestUser(t, db, tenantID)

	// Create multiple network spaces with overlapping ranges and different tags
	spaces := []models.NetworkSpace{
		{
			ID:          uuid.New().String(),
			Type:        "cidr",
			Value:       "192.168.0.0/16", // Larger range
			NetworkType: "private",
			Description: "Private network",
			IsActive:    true,
			Tags: map[string]interface{}{
				"environment": "production",
				"region":      "us-east-1",
			},
		},
		{
			ID:          uuid.New().String(),
			Type:        "cidr",
			Value:       "192.168.100.0/24", // Smaller, more specific range
			NetworkType: "private",
			Description: "Development network",
			IsActive:    true,
			Tags: map[string]interface{}{
				"environment": "dev",     // Overrides the previous environment tag
				"team":        "backend", // New tag
			},
		},
	}

	err := service.SaveNetworkSpaces(tenantID, userID, spaces)
	require.NoError(t, err)

	// Test IP that matches both ranges (192.168.100.50 is in both 192.168.0.0/16 and 192.168.100.0/24)
	ip := "192.168.100.50"
	tags, err := service.GetTagsForAsset(tenantID, &ip, nil, []string{})
	require.NoError(t, err)

	// Last match wins for duplicate keys
	assert.Equal(t, "dev", tags["environment"], "Tag 'environment' should be 'dev' (last match wins)")
	assert.Equal(t, "us-east-1", tags["region"], "Tag 'region' should be preserved from first match")
	assert.Equal(t, "backend", tags["team"], "Tag 'team' should be from second match")
	assert.Len(t, tags, 3, "Should have 3 tags merged")
}

// TestGetTagsForAssetNoMatch tests that no tags are returned when asset doesn't match any network space
func TestIntegration_GetTagsForAssetNoMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)
	testdb.HoldSchemaShareLock(t, db.DB.DB) // see the file comment above

	service := NewNetworkSpaceService(db)
	userID := seedTestUser(t, db, tenantID)

	// Create a network space
	spaces := []models.NetworkSpace{
		{
			ID:          uuid.New().String(),
			Type:        "cidr",
			Value:       "192.168.100.0/24",
			NetworkType: "private",
			IsActive:    true,
			Tags: map[string]interface{}{
				"environment": "dev",
			},
		},
	}

	err := service.SaveNetworkSpaces(tenantID, userID, spaces)
	require.NoError(t, err)

	// Test IP not in any CIDR range
	externalIP := "203.0.113.10"
	tags, err := service.GetTagsForAsset(tenantID, &externalIP, nil, []string{})
	require.NoError(t, err)
	assert.Empty(t, tags, "No tags should be returned for non-matching asset")
}

// TestMergeTags tests the mergeTags helper function
func TestMergeTags(t *testing.T) {
	existingTags := map[string]interface{}{
		"existing": "value1",
		"shared":   "old",
	}

	newTags := map[string]interface{}{
		"shared": "new",
		"new":    "value2",
	}

	merged := mergeTags(existingTags, newTags)

	assert.Equal(t, "value1", merged["existing"], "Existing tags should be preserved")
	assert.Equal(t, "new", merged["shared"], "New tags should override existing tags with same key")
	assert.Equal(t, "value2", merged["new"], "New tags should be added")
	assert.Len(t, merged, 3, "Should have 3 tags total")
}

// TestReclassifyAllAssetsWithTags tests that reclassification updates both ownership and tags
func TestIntegration_ReclassifyAllAssetsWithTags(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db, tenantID := getTestDBAndTenant(t)
	testdb.HoldSchemaShareLock(t, db.DB.DB) // see the file comment above

	networkSpaceService := NewNetworkSpaceService(db)
	assetService := NewAssetService(db)
	userID := seedTestUser(t, db, tenantID)

	// Create a network space with tags
	spaces := []models.NetworkSpace{
		{
			ID:          uuid.New().String(),
			Type:        "cidr",
			Value:       "192.168.100.0/24",
			NetworkType: "private",
			Description: "Development network",
			IsActive:    true,
			Tags: map[string]interface{}{
				"environment": "dev",
			},
		},
	}

	err := networkSpaceService.SaveNetworkSpaces(tenantID, userID, spaces)
	require.NoError(t, err)

	// Create an asset in the CIDR range
	ip := "192.168.100.50"
	hostname := "test-server.example.com"
	asset, err := assetService.CreateAsset(tenantID, models.AssetInput{
		Hostname:  &hostname,
		IPAddress: &ip,
		ClassKey:  assetclass.KeyServer,
		Tags:      models.JSONB{"existing": "tag"},
		Metadata:  models.JSONB{},
	})
	require.NoError(t, err)

	// Reclassify all assets
	updatedCount, err := networkSpaceService.ReclassifyAllAssets(tenantID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, updatedCount, 1, "At least one asset should be updated")

	// Verify asset ownership and tags were updated.
	//
	// The status filter is EXPLICIT: a newly created asset is
	// `pending_approval`, and the list defaults to `monitoring` only. This test
	// is about classification, not approval, so it asks for the asset where the
	// asset actually is rather than approving it to make a default match.
	assets, _, err := assetService.GetAssets(tenantID, models.AssetFilters{
		AssetStatus: []string{"pending_approval", "monitoring"},
		Page:        1,
		PageSize:    10,
	})
	require.NoError(t, err)

	var foundAsset *models.Asset
	for _, a := range assets {
		if a.ID == asset.ID {
			foundAsset = &a
			break
		}
	}
	require.NotNil(t, foundAsset, "Asset should be found")

	// Verify ownership
	assert.Equal(t, "internal", foundAsset.AssetOwnership, "Asset should be classified as 'internal'")

	// Verify tags were merged
	tags := foundAsset.Tags
	assert.Equal(t, "dev", tags["environment"], "Tag 'environment' should be 'dev'")
	assert.Equal(t, "tag", tags["existing"], "Existing tag should be preserved")
}
