package services

// One CloudFront distribution, one asset — through the REAL collector shape.
//
// pinned that two findings sharing a `distribution_id` collapse into one
// asset. It passed, and the defect survived it, because its fixture wrote
// `resource_type: cloudfront` into the finding's raw data and the CloudFront
// collector does not write that key at all. With `resource_type` present the
// class hint is `cdn_distribution`, whose identifier precedence begins with
// `cloud_resource_id`; without it the hint falls through the legacy
// `asset_type` ("service") to `application`, whose precedence is
// `[cmdb_sys_id, name]` — no `cloud_resource_id`. The identifier was recorded
// and never allowed to vote.
//
// Measured on demo, running core-v1.0.1-rc.1: one distribution produced three
// assets — the collector's `cdn_distribution` plus two `application` rows, one
// per hostname, both `pending_approval`, so the ACM certificate was deferred
// and reached `certificates` never.
//
// These tests drive the finding shape `WriteSensorDiscoveries` actually
// produces: `device_type` and no `resource_type`. Deleting the `device_type`
// read from findingClassHint turns them red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// liveCloudFrontFinding is the finding a CloudFront discovery really produces.
//
// Compare cloudFrontFinding in cloud_resource_id_identity_integration_test.go,
// which carries `resource_type`. discoverCloudFrontDistributions writes
// `distribution_id`, `status` and `enabled` into the device metadata and
// WriteSensorDiscoveries adds `device_type`, `discovery_method`,
// `integration_id`, `cloud_provider` and `cloud_region`. There is no
// `resource_type` anywhere on this path, and there never was.
func liveCloudFrontFinding(hostname, ip, distributionID, integrationID string, certs []interface{}) IngestFinding {
	port := 443
	version := "TLS 1.2"
	suite := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	raw := map[string]interface{}{
		"source":           "cloud_discovery",
		"discovery_method": "cloud_api",
		"integration_id":   integrationID,
		"cloud_provider":   "aws",
		"cloud_region":     "global",
		// What the collector writes. NOT `resource_type`.
		"device_type":     "aws_cloudfront",
		"distribution_id": distributionID,
	}
	if certs != nil {
		raw["certificates"] = certs
	}
	return IngestFinding{
		Hostname:  &hostname,
		IPAddress: &ip,
		Port:      &port,
		// mapCloudDeviceTypeToAssetType("aws_cloudfront") — the legacy
		// asset_type the converter stamps, and the thing `application` came
		// from.
		AssetType:       "service",
		Protocol:        "TLS",
		ProtocolVersion: &version,
		CipherSuite:     &suite,
		RawData:         raw,
	}
}

// seedCollectorCloudAsset creates the asset the cloud COLLECTOR creates before
// any finding is ingested: upsertDeviceAsset resolves an observation whose
// class comes from assetclass.FromDeviceType and whose strongest identifier is
// the provider's own resource id. It is `monitoring` because nothing about a
// resource read through the tenant's own credentials is awaiting approval.
func seedCollectorCloudAsset(t *testing.T, svc *AssetService, raw *sql.DB, tenant uuid.UUID, classKey, hostname, resourceID string) uuid.UUID {
	t.Helper()
	obs := identity.Observation{
		TenantID:    tenant.String(),
		ClassHint:   classKey,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "cloud:aws"},
		ObservedAt:  time.Now().UTC(),
		Confidence:  1,
		DisplayName: hostname,
		Hostname:    hostname,
		Admission:   identity.AdmissionEvidence{Authoritative: true, ReceiptID: uuid.NewString()},
		Network:     identity.Network{Ownership: identity.OwnershipInternal},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindCloudResourceID, Value: resourceID, Confidence: 1},
			{Kind: identity.KindFQDN, Value: hostname, Confidence: 1},
		},
	}
	res, err := svc.resolveObservationWithRepo(context.Background(), obs, nil)
	if err != nil {
		t.Fatalf("seed collector asset: %v", err)
	}
	if res.Asset.Zero() {
		t.Fatalf("seed collector asset: the engine created nothing")
	}
	id := uuid.MustParse(res.Asset.ID)
	if _, err := raw.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
		t.Fatalf("seed collector asset status: %v", err)
	}
	return id
}

func TestIntegration_CloudFrontFinding_ResolvesToTheCollectorsAsset(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)
	integrationID := uuid.NewString()

	const distributionID = "EXAMPLEDIST123"
	const domain = "df0pxeck85ppe.cloudfront.net"
	const alias = "shop.example.com"
	const ip = "203.0.113.55"

	collector := seedCollectorCloudAsset(t, svc, raw, tenant, "cdn_distribution", domain, distributionID)

	// The batch status production had: no auto-approval rule matches a cloud
	// row, so discovery-processor asks for pending_approval. It is exactly
	// this that made the certificate invisible — a NEW asset lands pending and
	// its crypto is deferred, while the collector's asset is already
	// monitoring and materializes at once.
	findings := []IngestFinding{
		liveCloudFrontFinding(domain, ip, distributionID, integrationID, []interface{}{acmCertificateEntry()}),
		liveCloudFrontFinding(alias, ip, distributionID, integrationID, []interface{}{acmCertificateEntry()}),
	}
	if _, err := svc.IngestFindings(tenant, findings, "pending_approval"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var assets int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if assets != 1 {
		rows, _ := raw.Query(`SELECT display_name, class_key, asset_status FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY display_name`, tenant)
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var name, class, status string
			_ = rows.Scan(&name, &class, &status)
			t.Logf("asset: %-40s %-20s %s", name, class, status)
		}
		t.Fatalf("one CloudFront distribution produced %d assets, want 1 — the findings must resolve to "+
			"the asset the collector created, not spawn `application` duplicates beside it", assets)
	}

	// …and it is the collector's asset, not a new one that happens to be alone.
	var survivor uuid.UUID
	if err := raw.QueryRow(`SELECT id FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&survivor); err != nil {
		t.Fatalf("read the surviving asset: %v", err)
	}
	if survivor != collector {
		t.Fatalf("the findings landed on asset %s, want the collector's %s", survivor, collector)
	}

	// The user-visible outcome slice C promised: the ACM certificate in
	// Inventory → Certificates. It materialized because the finding resolved
	// onto an asset that is already `monitoring`; on a new pending_approval
	// asset it would have been deferred into metadata and shown nowhere.
	var commonName string
	if err := raw.QueryRow(
		`SELECT common_name FROM certificates WHERE tenant_id=$1 AND common_name=$2`,
		tenant, "shop.example.com").Scan(&commonName); err != nil {
		t.Fatalf("the ACM certificate did not reach `certificates`: %v", err)
	}
}

// The KMS shape. Four AWS-managed keys arrived as four `application` assets on
// demo, for the same reason: `aws_kms` names a class in the one device_type
// table and the ingest side did not read it.
//
// There is no collector-created asset to resolve to here — the KMS collector
// does not call upsertDeviceAsset — so the assertion is about the CLASS, not
// about duplication. An `application` is what the legacy asset_type guessed; a
// `key_store` is what the provider said.
func TestIntegration_KMSKeyFinding_IsAKeyStoreNotAnApplication(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)

	arn := "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000002"
	hostname := "alias/aws/acm"
	f := IngestFinding{
		Hostname:  &hostname,
		AssetType: "service",
		Protocol:  atRestProtocolSentinel,
		RawData: map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"integration_id":   uuid.NewString(),
			"cloud_provider":   "aws",
			"cloud_region":     "us-east-1",
			"device_type":      "aws_kms",
			"at_rest":          true,
			"arn":              arn,
		},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var classKey string
	if err := raw.QueryRow(
		`SELECT class_key FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&classKey); err != nil {
		t.Fatalf("read the KMS asset: %v", err)
	}
	if classKey != "key_store" {
		t.Errorf("a KMS key was inventoried as %q, want \"key_store\" — `aws_kms` names a class in the "+
			"one device_type table and ingest must read it rather than guessing from the legacy asset_type",
			classKey)
	}
}
