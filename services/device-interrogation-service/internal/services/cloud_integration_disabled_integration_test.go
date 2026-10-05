package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// A disabled integration is not a configured source: its identity refresh is
// blocked, not dispatched (a run of it would be refused by
// authorizeCloudIntegration anyway — TestAuthorizeCloudIntegration_Disabled…).
//
// MUTATION-VERIFIED: drop `COALESCE(is_enabled, true)` from planCloud's
// configured-integration check and the refresh is queued.
//
// Skips unless TEST_DATABASE_URL is set.
func TestIntegration_SourceRefresh_DisabledCloudIntegrationIsNotDispatched(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	ctx := context.Background()
	tenant := testdb.NewTenant(t, owner)
	integration := uuid.New()
	if _, err := owner.Exec(`INSERT INTO platform_integrations(id,tenant_id,integration_name,integration_type,provider,config,is_active,is_enabled)
		VALUES($1,$2,'Disabled AWS','aws','cloud','{"region":"us-east-1"}',true,false)`, integration, tenant); err != nil {
		t.Fatal(err)
	}
	devices := NewDeviceServiceWithKey(owner, testMasterKey)
	// The retained (asset-less) shape: a linked cloud observation completes
	// without consulting any source (TestIntegration_SourceRefresh_
	// CloudDiscoveredAssetCompletes), so the integration check lives here.
	bucket := s3Bucket("example-disabled-bucket")
	bucket.TenantID = tenant
	bucket.CredentialID = &integration
	enableSourceRefresh(t, owner, tenant)
	refresh := NewConfiguredSourceRefresh(owner, NewJobQueueService(owner, owner, nil), devices, nil)
	status, err := refresh.Refresh(ctx, retainedCloudRefresh(t, owner, devices, tenant, bucket))
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "blocked" || status.Reason != "configured_credentials_unavailable" {
		t.Fatalf("a disabled integration's refresh reads %+v, want blocked / configured_credentials_unavailable", status)
	}
}
