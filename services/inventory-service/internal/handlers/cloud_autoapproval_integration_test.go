package handlers

// Account-level auto-approval and the `hosted_on` edge for the cloud
// resources that reach inventory only as FINDINGS (buckets, databases, key
// stores), end to end over a real Postgres through the real discovery import
// route (asset-inventory ADR-0009 D1, D5).
//
// What changed, and what these pin:
//
//  1. The segment editor's "Cloud discoveries" source is gone. It never fired
//     (the cloud intake never evaluated rules), and a segment is the wrong
//     boundary for a resource with no address. A segment configured with it —
//     or with no source term at all — no longer approves a cloud resource.
//  2. Cloud resources are approved by the ACCOUNT's rule,
//     `source:cloud and cloud.account_id="<id>"`, which device-interrogation-
//     service derives from the integration's auto_approve_resources setting.
//     The import puts the finding's account on the observation; shared/approval
//     decides.
//  3. Every resolved cloud resource hangs off its account asset with a
//     measured `hosted_on` edge, including an addressless bucket whose ARN
//     names no account (the integration's account is used).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/cloudaccount"
)

const testCloudAccount = "111122223333"

// importCloudKey imports one placeholder-addressed KMS key through the real
// import route, the way discovery-processor forwards a cloud-API row, and
// returns the status its asset landed as and the rule credited.
func (f *routePipelineFixture) importCloudKey(t *testing.T, account, name string) (string, string) {
	t.Helper()
	resp := f.importFindings(t, map[string]interface{}{
		"hostname":   name,
		"ip_address": "0.0.0.0",
		"asset_type": "key_store",
		"protocol":   "",
		"raw_data": map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"cloud_provider":   "aws",
			"cloud_region":     "us-east-1",
			"environment":      "production",
			"arn":              "arn:aws:kms:us-east-1:" + account + ":key/" + name,
			"confidence":       0.95,
			"at_rest":          true,
		},
	})
	return resp.AssetStatuses[0], resp.Results[0].AutoApprovalRuleID
}

// importBucket imports an S3 bucket: an ARN with NO account in it, read
// through an integration that names the account.
func (f *routePipelineFixture) importBucket(t *testing.T, integrationID uuid.UUID, name string) (string, string) {
	t.Helper()
	resp := f.importFindings(t, map[string]interface{}{
		"hostname":   name,
		"ip_address": "0.0.0.0",
		"asset_type": "object_storage",
		"protocol":   "",
		"raw_data": map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"cloud_provider":   "aws",
			"cloud_region":     "us-east-1",
			"device_type":      "aws_s3_bucket",
			"arn":              "arn:aws:s3:::" + name,
			"integration_id":   integrationID.String(),
			"confidence":       0.8,
			"at_rest":          true,
		},
	})
	return resp.AssetStatuses[0], resp.Results[0].AssetID
}

// accountRule writes the rule device-interrogation-service derives from an
// integration's auto_approve_resources setting.
func (f *routePipelineFixture) accountRule(t *testing.T, account string, active bool) {
	t.Helper()
	q, err := approval.ValidateRuleQuery(approval.CloudAccountApprovalQuery(account))
	if err != nil {
		t.Fatalf("account rule: %v", err)
	}
	if _, err := f.raw.Exec(`INSERT INTO discovery_auto_approval_rules (tenant_id, name, query, is_active)
		VALUES ($1, 'Auto-approve cloud resources', $2, $3)`, f.tenant, q, active); err != nil {
		t.Fatalf("insert account rule: %v", err)
	}
}

// cloudIntegration seeds the tenant's AWS integration for the account.
func (f *routePipelineFixture) cloudIntegration(t *testing.T, account string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO platform_integrations
		(id, tenant_id, integration_name, integration_type, provider, status, account_id)
		VALUES ($1, $2, $3, 'aws', 'cloud', 'connected', $4)`, id, f.tenant, "aws-"+id.String()[:8], account); err != nil {
		t.Fatalf("seed integration: %v", err)
	}
	return id
}

// accountAsset declares the account asset the way the integration create path
// does — a declared `cloud_account` keyed aws:<account> — and approves it.
func (f *routePipelineFixture) accountAsset(t *testing.T, account string) uuid.UUID {
	t.Helper()
	assets := services.NewAssetService(&database.DB{DB: sqlx.NewDb(f.raw, "postgres")})
	name := cloudaccount.DisplayName("aws", account)
	a, err := assets.CreateAsset(f.tenant, models.AssetInput{
		ClassKey:    cloudaccount.ClassKey,
		DisplayName: &name,
		Identifiers: []models.AssetIdentifierInput{{Kind: "cloud_resource_id", Value: cloudaccount.ResourceID("aws", account)}},
	})
	if err != nil {
		t.Fatalf("declare account asset: %v", err)
	}
	if err := assets.ApproveAssets(f.tenant, []uuid.UUID{a.ID}, uuid.Nil); err != nil {
		t.Fatalf("approve account asset: %v", err)
	}
	return a.ID
}

// hostedOn reads the hosted_on edge from a resource, if any.
func (f *routePipelineFixture) hostedOn(t *testing.T, from string) (to, status string) {
	t.Helper()
	err := f.raw.QueryRow(`SELECT to_asset_id::text, status FROM asset_relationships
		WHERE tenant_id = $1 AND from_asset_id = $2 AND type = 'hosted_on'`, f.tenant, from).Scan(&to, &status)
	if err != nil {
		return "", ""
	}
	return to, status
}

// TestIntegration_CloudIntake_CallsApprovalWithAccountScope: the import puts
// the finding's account on the observation, so the account's rule approves a
// resource in it — and only in it. Mutation: drop the line that sets
// CloudAccountID in pipelineApproval and the in-account key lands pending.
func TestIntegration_CloudIntake_CallsApprovalWithAccountScope(t *testing.T) {
	f := newRoutePipelineFixture(t)
	f.accountRule(t, testCloudAccount, true)

	status, ruleID := f.importCloudKey(t, testCloudAccount, "key-in-account")
	if status != "monitoring" || ruleID == "" {
		t.Fatalf("a key in the auto-approving account landed %q (rule %q), want monitoring credited to the account rule — "+
			"the import did not put cloud.account_id on the observation", status, ruleID)
	}
	if status, ruleID := f.importCloudKey(t, "999988887777", "key-elsewhere"); status != "pending_approval" || ruleID != "" {
		t.Fatalf("a key in ANOTHER account landed %q (rule %q); an account rule must not reach past its account", status, ruleID)
	}
}

// An inactive account rule (the integration's switch is off) approves nothing.
func TestIntegration_CloudIntake_InactiveAccountRule_LeavesPending(t *testing.T) {
	f := newRoutePipelineFixture(t)
	f.accountRule(t, testCloudAccount, false)
	if status, ruleID := f.importCloudKey(t, testCloudAccount, "key-switch-off"); status != "pending_approval" || ruleID != "" {
		t.Fatalf("landed %q (rule %q) with the account's auto-approve off", status, ruleID)
	}
}

// TestIntegration_CloudIntake_EmitsHostedOnToAccount (bucket half; the
// instance half is device-interrogation-service's): an addressless bucket
// whose ARN names no account hangs off the account of the integration that
// read it. Pending while the bucket is pending; active once approved by the
// account rule. Mutation: remove linkCloudAccount's call and both go red.
func TestIntegration_CloudIntake_EmitsHostedOnToAccount(t *testing.T) {
	f := newRoutePipelineFixture(t)
	integ := f.cloudIntegration(t, testCloudAccount)
	account := f.accountAsset(t, testCloudAccount)

	status, bucket := f.importBucket(t, integ, "bucket-pending-"+uuid.NewString()[:6])
	if status != "pending_approval" {
		t.Fatalf("bucket landed %q with no account rule, want pending_approval", status)
	}
	if to, st := f.hostedOn(t, bucket); to != account.String() || st != "pending" {
		t.Fatalf("pending bucket's hosted_on = (%q, %q), want (%s, pending)", to, st, account)
	}

	f.accountRule(t, testCloudAccount, true)
	status, bucket = f.importBucket(t, integ, "bucket-approved-"+uuid.NewString()[:6])
	if status != "monitoring" {
		t.Fatalf("bucket in the auto-approving account landed %q, want monitoring (account from the integration)", status)
	}
	if to, st := f.hostedOn(t, bucket); to != account.String() || st != "active" {
		t.Fatalf("approved bucket's hosted_on = (%q, %q), want (%s, active)", to, st, account)
	}
}

// A prefix rule never approves a cloud resource (ADR-0009 D5, DCIM row 1.6):
// an auto-approving `cloud` prefix generates a `source:sensor` rule, and only
// the account decides a cloud listing.
func TestIntegration_PrefixAutoApproval_DoesNotCoverCloud(t *testing.T) {
	f := newRoutePipelineFixture(t)
	body := []byte(`{"prefix":"10.0.0.0/8","network_type":"cloud","auto_approve_discoveries":true,"auto_approve_sources":["sensor","cloud"]}`)
	if _, err := services.NewIPAMService(f.raw).Create(handlerIPAMCtx(), f.tenant, "prefixes", body); err != nil {
		t.Fatalf("declare cloud prefix: %v", err)
	}
	if status, ruleID := f.importCloudKey(t, testCloudAccount, "key-in-prefix"); status != "pending_approval" || ruleID != "" {
		t.Fatalf("a prefix rule approved a cloud resource (landed %q, rule %q)", status, ruleID)
	}
}
