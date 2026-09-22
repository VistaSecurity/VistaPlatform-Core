package services

// The WIRING for cloud scope on a non-enumerated resource ( slice D).
//
// `cloud_scope_test.go` pins what `cloudScopeValues` decides. That is the easy
// half and it is worth nothing on its own: the decision is only reachable
// because `upsertDeviceAsset` passes `s.cloudScopeExtra(ctx, device)` as the
// transaction hook, and that is ONE argument in ONE line. Replace it with the
// `nil` it used to be and every unit assertion next door stays green while a
// bucket goes back to carrying no account and no region at all.
//
// So this drives the real funnel against a real database and reads the rows.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CloudScope_BucketGetsAccountAndRegion(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)
	if _, err := owner.Exec(
		`UPDATE platform_integrations SET account_id = '123456789012' WHERE id = $1`, integrationID); err != nil {
		t.Fatalf("set integration account_id: %v", err)
	}

	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	scope := svc.resolveCloudScope(ctx, tenantID, integrationID, "aws")
	if scope.AccountID != "123456789012" {
		t.Fatalf("resolveCloudScope account = %q, want the integration's 123456789012", scope.AccountID)
	}
	ctx = context.WithValue(ctx, cloudScopeKey{}, scope)

	// An S3 bucket: the at-rest collector's shape, and the one whose ARN names
	// no account, so the integration's is the only answer available.
	arn := "arn:aws:s3:::assets-bucket-" + uuid.New().String()[:8]
	device := models.Device{
		ID:               uuid.New(),
		TenantID:         tenantID,
		DeviceType:       "aws_s3_bucket",
		Vendor:           stringPtr("AWS"),
		Hostname:         stringPtr("assets-bucket"),
		DiscoveryMethod:  "cloud_api",
		ConnectionStatus: "discovered",
		Metadata:         models.JSONB{"arn": arn, "region": "us-east-1", "resource_type": "s3_bucket"},
	}
	if err := svc.upsertDeviceAsset(ctx, &device, arn); err != nil {
		t.Fatalf("upsertDeviceAsset: %v", err)
	}

	assetID := assetIDForCloudResource(t, owner, tenantID, arn)
	got := factMap(t, owner, tenantID, assetID)
	for key, want := range map[string]string{
		facts.KeyCloudProvider:  `"aws"`,
		facts.KeyCloudAccountID: `"123456789012"`,
		facts.KeyCloudRegion:    `"us-east-1"`,
	} {
		if got[key] != want {
			t.Errorf("fact %s = %s, want %s", key, got[key], want)
		}
	}

	// And the class attributes, which are what the Inventory facets read.
	// `object_storage` inherits provider/account_id/region from
	// `cloud_resource`, so no assetclass change was needed for any of this.
	attrs := attributeMap(t, owner, tenantID, assetID)
	if attrs["region"] != "us-east-1" || attrs["account_id"] != "123456789012" {
		t.Errorf("attributes = %v", attrs)
	}

	// Re-running the same discovery must not double the rows — the facts are
	// upserted on (tenant, asset, key, source_ref) like every other collector's.
	second := device
	second.ID = uuid.New()
	if err := svc.upsertDeviceAsset(ctx, &second, arn); err != nil {
		t.Fatalf("second upsertDeviceAsset: %v", err)
	}
	var count int
	if err := owner.QueryRow(
		`SELECT count(*) FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
		tenantID, assetID, facts.KeyCloudRegion).Scan(&count); err != nil {
		t.Fatalf("count region facts: %v", err)
	}
	if count != 1 {
		t.Errorf("cloud.region rows after two runs = %d, want 1", count)
	}
}

func TestIntegration_CloudScope_RegionlessResourceIsStillRecorded(t *testing.T) {
	// The empty state, and the one it would be easy to get wrong in either
	// direction: a resource whose region nothing stated must not acquire a
	// fabricated one, and must not lose the asset either.
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	// No account_id on the integration either, so NOTHING about this resource's
	// placement is known beyond the provider.
	ctx = context.WithValue(ctx, cloudScopeKey{}, svc.resolveCloudScope(ctx, tenantID, integrationID, "aws"))

	arn := "arn:aws:s3:::nowhere-bucket-" + uuid.New().String()[:8]
	device := models.Device{
		ID:               uuid.New(),
		TenantID:         tenantID,
		DeviceType:       "aws_s3_bucket",
		Vendor:           stringPtr("AWS"),
		Hostname:         stringPtr("nowhere-bucket"),
		DiscoveryMethod:  "cloud_api",
		ConnectionStatus: "discovered",
		Metadata:         models.JSONB{"arn": arn, "resource_type": "s3_bucket"},
	}
	if err := svc.upsertDeviceAsset(ctx, &device, arn); err != nil {
		t.Fatalf("upsertDeviceAsset: %v", err)
	}

	// The asset exists.
	assetID := assetIDForCloudResource(t, owner, tenantID, arn)
	got := factMap(t, owner, tenantID, assetID)
	if _, present := got[facts.KeyCloudRegion]; present {
		t.Errorf("a region was invented: %s", got[facts.KeyCloudRegion])
	}
	if _, present := got[facts.KeyCloudAccountID]; present {
		t.Errorf("an account was invented: %s", got[facts.KeyCloudAccountID])
	}
	if got[facts.KeyCloudProvider] != `"aws"` {
		t.Errorf("cloud.provider = %s, want \"aws\" — the one thing that IS known", got[facts.KeyCloudProvider])
	}
}
