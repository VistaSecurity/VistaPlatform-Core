package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// getTestDBForNetworkSpace returns a test database connection
// Uses the same pattern as asset_approval_test.go
func getTestDBForNetworkSpace(t *testing.T) *database.DB {
	// Use the same getTestDB function from asset_approval_test.go
	// This will be available since it's in the same package
	return getTestDB(t)
}

// TestClassifyAssetInternal tests that assets in defined CIDR ranges are classified as 'internal'
func TestClassifyAssetInternal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDBForNetworkSpace(t)
	if db == nil {
		return
	}
	defer func() { _ = db.Close() }()

	service := NewNetworkSpaceService(db)
	tenantID := uuid.New()
	userID := uuid.New()

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
func TestClassifyAssetThirdParty(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDBForNetworkSpace(t)
	if db == nil {
		return
	}
	defer func() { _ = db.Close() }()

	service := NewNetworkSpaceService(db)
	tenantID := uuid.New()

	// No network spaces defined
	ip := "203.0.113.10"
	ownership, err := service.ClassifyAsset(tenantID, &ip, nil, []string{})
	require.NoError(t, err)
	assert.Equal(t, "unknown", ownership, "Asset with no network spaces defined should be 'unknown'")

	// Create a network space
	userID := uuid.New()
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
func TestGetTagsForAssetSingleMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDBForNetworkSpace(t)
	if db == nil {
		return
	}
	defer func() { _ = db.Close() }()

	service := NewNetworkSpaceService(db)
	tenantID := uuid.New()
	userID := uuid.New()

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
func TestGetTagsForAssetMultipleMatches(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDBForNetworkSpace(t)
	if db == nil {
		return
	}
	defer func() { _ = db.Close() }()

	service := NewNetworkSpaceService(db)
	tenantID := uuid.New()
	userID := uuid.New()

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
func TestGetTagsForAssetNoMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDBForNetworkSpace(t)
	if db == nil {
		return
	}
	defer func() { _ = db.Close() }()

	service := NewNetworkSpaceService(db)
	tenantID := uuid.New()
	userID := uuid.New()

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
func TestReclassifyAllAssetsWithTags(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	db := getTestDBForNetworkSpace(t)
	if db == nil {
		return
	}
	defer func() { _ = db.Close() }()

	networkSpaceService := NewNetworkSpaceService(db)
	assetService := NewAssetService(db)
	tenantID := uuid.New()
	userID := uuid.New()

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
		AssetType: "server",
		Tags:      models.JSONB{"existing": "tag"},
		Metadata:  models.JSONB{},
	})
	require.NoError(t, err)

	// Reclassify all assets
	updatedCount, err := networkSpaceService.ReclassifyAllAssets(tenantID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, updatedCount, 1, "At least one asset should be updated")

	// Verify asset ownership and tags were updated
	assets, _, err := assetService.GetAssets(tenantID, models.AssetFilters{
		Page:     1,
		PageSize: 10,
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
