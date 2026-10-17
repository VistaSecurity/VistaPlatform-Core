package services

// ADR-0009 D6's evidence, written by the REAL run funnel: every resource a
// listing returns carries `cloud.listing` + `cloud.last_enumerated_at`, and
// the account asset carries `cloud.enumeration_coverage` for exactly the
// listings that completed — never for one that was refused. inventory-service's
// stale sweep (jobs/cloud_lifecycle_integration_test.go) reads these three.
//
// MUTATION-VERIFIED: dropping cloudListingFacts from recordCloudResource, or
// the recordEnumerationCoverage call, turns this red.
//
// Skips unless TEST_DATABASE_URL is set.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CloudLifecycle_RunRecordsListingAndCoverage(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	plan := awsEnumerationPlanForTest(t)
	account := plan.Instances[0].Facts["cloud.account_id"].(string)
	integ := seedAccountIntegration(t, owner, tenantID, account, true)
	svc := NewCloudDiscoveryService(app, owner, testMasterKey)

	rec := NewCloudOutcomeRecorder([]string{CloudTypeComputeInstances})
	ctx := WithCloudOutcomes(svc.beginCloudRun(context.Background(), tenantID, integ, "aws"), rec)
	rec.Attempt(CloudTypeComputeInstances, "us-east-1", len(plan.Instances), nil)
	rec.Attempt(CloudTypeComputeInstances, "eu-west-1", 0, errAccessDeniedForTest{})
	for i := range plan.Instances {
		plan.Instances[i].annotateListing(CloudListingKey(CloudTypeComputeInstances, "us-east-1"))
	}
	if _, _, err := svc.recordEnumeration(ctx, tenantID, integ, "production", plan); err != nil {
		t.Fatalf("recordEnumeration: %v", err)
	}
	svc.recordEnumerationCoverage(ctx, tenantID, "AWS")

	instance := assetIDForCloudResource(t, owner, tenantID, plan.Instances[0].ResourceID)
	fact := func(asset any, key string) []byte {
		var raw []byte
		if err := owner.QueryRow(`SELECT value FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
			tenantID, asset, key).Scan(&raw); err != nil {
			t.Fatalf("fact %s: %v", key, err)
		}
		return raw
	}
	var listing, last string
	_ = json.Unmarshal(fact(instance, "cloud.listing"), &listing)
	_ = json.Unmarshal(fact(instance, "cloud.last_enumerated_at"), &last)
	if listing != "compute_instances@us-east-1" || last == "" {
		t.Errorf("instance listing = %q, last_enumerated_at = %q", listing, last)
	}

	var coverage map[string]string
	_ = json.Unmarshal(fact(accountAssetID(t, owner, tenantID, account), "cloud.enumeration_coverage"), &coverage)
	if coverage["compute_instances@us-east-1"] != last {
		t.Errorf("coverage[us-east-1] = %q, want the run's clock %q", coverage["compute_instances@us-east-1"], last)
	}
	if _, refused := coverage["compute_instances@eu-west-1"]; refused {
		t.Error("a refused listing recorded coverage — absence there would be read from nothing")
	}
}

type errAccessDeniedForTest struct{}

func (errAccessDeniedForTest) Error() string { return "AccessDenied: not authorized" }
