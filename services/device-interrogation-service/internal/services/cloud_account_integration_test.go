package services

// The account half of the cloud intake (asset-inventory ADR-0009 D1, D5),
// through the REAL funnel every collector records through
// (upsertDeviceAssetWith, reached via recordEnumeration and upsertDeviceAsset),
// the real identity engine and the real schema:
//
//   - a resource in an account whose integration auto-approves is approved by
//     the account's rule — the rule matches only on cloud.account_id, so an
//     approval proves the account reached shared/approval;
//   - with the switch off, it waits in Approvals;
//   - every recorded resource hangs off the account asset with `hosted_on`,
//     active exactly when the resource is approved;
//   - a contested resource still produces a merge proposal and nothing is
//     approved: auto-approval never auto-merges.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cloudaccount"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedAccountIntegration is an AWS integration that names its account, with
// the account-level auto-approval switch as given.
func seedAccountIntegration(t *testing.T, db *sql.DB, tenantID uuid.UUID, account string, autoApprove bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO platform_integrations
		(id, tenant_id, integration_name, integration_type, provider, status, account_id, auto_approve_resources)
		VALUES ($1, $2, $3, 'aws', 'cloud', 'connected', $4, $5)`,
		id, tenantID, "aws-"+id.String()[:8], account, autoApprove); err != nil {
		t.Fatalf("seed integration: %v", err)
	}
	return id
}

func assetStatus(t *testing.T, db *sql.DB, tenantID, assetID uuid.UUID) string {
	t.Helper()
	var s string
	if err := db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2`, tenantID, assetID).Scan(&s); err != nil {
		t.Fatalf("asset %s: %v", assetID, err)
	}
	return s
}

// hostedOnEdge returns the (to, status) of the asset's hosted_on edge.
func hostedOnEdge(t *testing.T, db *sql.DB, tenantID, from uuid.UUID) (string, string) {
	t.Helper()
	var to, status string
	err := db.QueryRow(`SELECT to_asset_id::text, status FROM asset_relationships
		WHERE tenant_id = $1 AND from_asset_id = $2 AND type = 'hosted_on'`, tenantID, from).Scan(&to, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return to, status
}

// accountRun records an enumeration plan the way a cloud run does: the run is
// begun (account sync, scope, rule cache) and then recorded through the funnel.
func accountRun(t *testing.T, svc *CloudDiscoveryService, tenantID, integrationID uuid.UUID, plan cloudEnumerationPlan) {
	t.Helper()
	ctx := svc.beginCloudRun(context.Background(), tenantID, integrationID, "aws")
	if _, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan); err != nil {
		t.Fatalf("recordEnumeration: %v", err)
	}
}

// accountAssetID is the tenant's cloud_account asset for the AWS account.
func accountAssetID(t *testing.T, db *sql.DB, tenantID uuid.UUID, account string) uuid.UUID {
	t.Helper()
	return assetIDForCloudResource(t, db, tenantID, cloudaccount.ResourceID("aws", account))
}

// TestIntegration_CloudIntake_CallsApprovalWithAccountScope: the account rule
// is `source:cloud and cloud.account_id=<account>` — it can only match if the
// funnel put the resource's account on the observation it handed
// shared/approval. Every enumerated resource lands approved, and the history
// row names the rule. Mutation: remove the cloudResourceRecorded call (or the
// CloudAccountID on its approval input) and they land pending.
func TestIntegration_CloudIntake_CallsApprovalWithAccountScope(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	plan := awsEnumerationPlanForTest(t)
	account := plan.Instances[0].Facts["cloud.account_id"].(string)
	integ := seedAccountIntegration(t, owner, tenantID, account, true)
	svc := NewCloudDiscoveryService(app, owner, testMasterKey)

	accountRun(t, svc, tenantID, integ, plan)

	for _, res := range []cloudEnumResource{plan.Instances[0]} {
		id := assetIDForCloudResource(t, owner, tenantID, res.ResourceID)
		if s := assetStatus(t, owner, tenantID, id); s != identity.StatusMonitoring {
			t.Errorf("%s landed %q, want monitoring by the account rule", res.DeviceType, s)
		}
		var rule string
		if err := owner.QueryRow(`SELECT coalesce(changes_json->>'auto_approval_rule_id', '') FROM asset_history
			WHERE tenant_id = $1 AND asset_id = $2 AND action = 'approved'`, tenantID, id).Scan(&rule); err != nil || rule == "" {
			t.Errorf("%s: no approval history naming the rule (rule %q, err %v)", res.DeviceType, rule, err)
		}
	}
}

// TestIntegration_CloudIntake_AutoApproveOff_LeavesPending: the same run with
// the account's switch off. Mutation: invert the auto_approve_resources read
// in the account sync and these approve.
func TestIntegration_CloudIntake_AutoApproveOff_LeavesPending(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	plan := awsEnumerationPlanForTest(t)
	account := plan.Instances[0].Facts["cloud.account_id"].(string)
	integ := seedAccountIntegration(t, owner, tenantID, account, false)
	svc := NewCloudDiscoveryService(app, owner, testMasterKey)

	accountRun(t, svc, tenantID, integ, plan)

	inst := assetIDForCloudResource(t, owner, tenantID, plan.Instances[0].ResourceID)
	if s := assetStatus(t, owner, tenantID, inst); s != identity.StatusPendingApproval {
		t.Fatalf("instance landed %q with auto-approve off, want pending_approval", s)
	}
	// The account itself is still declared and approved: the person added it.
	acct := accountAssetID(t, owner, tenantID, account)
	if s := assetStatus(t, owner, tenantID, acct); s != identity.StatusMonitoring {
		t.Fatalf("account asset is %q, want monitoring (approved by adding the integration)", s)
	}
	if to, st := hostedOnEdge(t, owner, tenantID, inst); to != acct.String() || st != "pending" {
		t.Fatalf("pending instance's hosted_on = (%q, %q), want (%s, pending)", to, st, acct)
	}
}

// TestIntegration_CloudIntake_EmitsHostedOnToAccount (instance and CDN halves;
// the bucket half is inventory-service's, where buckets arrive): an enumerated
// instance and a crypto collector's CloudFront distribution both hang off the
// account asset — the edge is written in the funnel, so a collector cannot
// skip it. Mutation: remove the LinkHostedOn call and both go red.
func TestIntegration_CloudIntake_EmitsHostedOnToAccount(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	plan := awsEnumerationPlanForTest(t)
	account := plan.Instances[0].Facts["cloud.account_id"].(string)
	integ := seedAccountIntegration(t, owner, tenantID, account, true)
	svc := NewCloudDiscoveryService(app, owner, testMasterKey)

	accountRun(t, svc, tenantID, integ, plan)
	acct := accountAssetID(t, owner, tenantID, account)

	inst := assetIDForCloudResource(t, owner, tenantID, plan.Instances[0].ResourceID)
	if to, st := hostedOnEdge(t, owner, tenantID, inst); to != acct.String() || st != "active" {
		t.Fatalf("instance hosted_on = (%q, %q), want (%s, active)", to, st, acct)
	}

	// A CDN distribution from the crypto collectors' path (upsertDeviceAsset),
	// no address of its own.
	ctx := svc.beginCloudRun(context.Background(), tenantID, integ, "aws")
	distARN := "arn:aws:cloudfront::" + account + ":distribution/E" + uuid.NewString()[:8]
	name := "d" + uuid.NewString()[:8] + ".cloudfront.net"
	vendor := "aws"
	dist := models.Device{
		ID: uuid.New(), TenantID: tenantID, DeviceType: "aws_cloudfront", Vendor: &vendor,
		Hostname: &name, DiscoveryMethod: "cloud_api", CredentialID: &integ,
		Metadata: models.JSONB{"arn": distARN}, CreatedAt: time.Now(),
	}
	if err := svc.upsertDeviceAsset(ctx, &dist, distARN); err != nil {
		t.Fatalf("record distribution: %v", err)
	}
	if s := assetStatus(t, owner, tenantID, dist.ID); s != identity.StatusMonitoring {
		t.Fatalf("distribution landed %q, want monitoring", s)
	}
	if to, st := hostedOnEdge(t, owner, tenantID, dist.ID); to != acct.String() || st != "active" {
		t.Fatalf("distribution hosted_on = (%q, %q), want (%s, active)", to, st, acct)
	}
}

// A contested resource with auto-approve ON: the merge proposal is written,
// no asset is created, and neither of the two assets the identifiers belong
// to is approved or linked. Auto-approval never auto-merges (ADR-0002 D5).
func TestIntegration_CloudIntake_ContestedStillProposes_WithAutoApproveOn(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	const account = "100000000001"
	integ := seedAccountIntegration(t, db, tenant, account, true)
	cloud := NewCloudDiscoveryService(db, db, testMasterKey)
	devices := cloud.devices

	arn := "arn:aws:elasticloadbalancing:us-east-1:" + account + ":loadbalancer/app/contested/" + uuid.NewString()[:6]
	arnOwnerName := "lb-first-" + uuid.NewString()[:6] + ".example.test"
	arnOwner, err := devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "aws_alb", Hostname: &arnOwnerName, Metadata: map[string]interface{}{"arn": arn},
	})
	if err != nil {
		t.Fatalf("asset owning the ARN: %v", err)
	}
	nameOwnerName := "lb-second-" + uuid.NewString()[:6] + ".example.test"
	nameOwner, err := devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "aws_alb", Hostname: &nameOwnerName})
	if err != nil {
		t.Fatalf("asset owning the name: %v", err)
	}

	run := cloud.beginCloudRun(ctx, tenant, integ, "aws")
	vendor := "aws"
	device := models.Device{TenantID: tenant, DeviceType: "aws_alb", Vendor: &vendor, Hostname: &nameOwnerName, CredentialID: &integ}
	err = cloud.upsertDeviceAsset(run, &device, arn)
	var contested *DeviceIdentityContestedError
	if !errors.As(err, &contested) || contested.ProposalID == "" {
		t.Fatalf("err = %v, want a contested resolution naming its merge proposal", err)
	}
	for _, id := range []uuid.UUID{arnOwner.ID, nameOwner.ID} {
		if s := assetStatus(t, db, tenant, id); s != identity.StatusPendingApproval {
			t.Errorf("contested candidate %s is %q; auto-approval reached an asset whose identity is in dispute", id, s)
		}
		if to, _ := hostedOnEdge(t, db, tenant, id); to != "" {
			t.Errorf("contested candidate %s got a hosted_on edge", id)
		}
	}
}
