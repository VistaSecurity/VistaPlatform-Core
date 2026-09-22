package services

// One CloudFront distribution, two discovery rows, one asset.
//
// A CloudFront distribution is discovered twice in the same run: once under the
// distribution domain AWS assigns it, and once under each alias configured on
// it. Both rows describe the SAME resource and both carry the distribution's
// own identifier — `distribution_id` — and nothing else that names it.
//
// `cloudResourceID()` did not read `distribution_id`, so neither row produced a
// `cloud_resource_id` identifier. The identity engine then had only the two
// hostnames to work with, they differ, and the distribution became two assets:
// the duplicate-identity class ADR-0002 D3 exists to prevent.
//
// Before this was invisible — a public dest_ip routed both rows to
// `external_connections` and no asset was created at all. Ownership now decides
// the route, so these rows take the managed-asset path and the missing
// identifier became load-bearing.
//
// Both polarities are asserted:
//
//	one resource    two rows sharing a provider id → ONE asset
//	two resources   two rows with DIFFERENT provider ids → TWO assets
//
// Deleting `distribution_id` from cloudResourceID()'s key list turns the first
// red. Collapsing on hostname or IP instead of the provider id turns the second
// red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// cloudFrontFinding builds the finding shape WriteSensorDiscoveries produces for
// a CloudFront distribution: the collector's device metadata is flattened into
// raw_data, so `distribution_id` sits at the top level beside the cloud
// provenance keys.
func cloudFrontFinding(hostname, ip, distributionID, integrationID string) IngestFinding {
	port := 443
	version := "TLS 1.2"
	suite := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	return IngestFinding{
		Hostname:        &hostname,
		IPAddress:       &ip,
		Port:            &port,
		AssetType:       "cdn",
		Protocol:        "TLS",
		ProtocolVersion: &version,
		CipherSuite:     &suite,
		RawData: map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"integration_id":   integrationID,
			"cloud_provider":   "aws",
			"cloud_region":     "global",
			"device_type":      "aws_cloudfront",
			"resource_type":    "cloudfront",
			// The ONLY thing in a CloudFront distribution's metadata that
			// names the distribution. There is no `arn` here — the collector
			// never had one to write.
			"distribution_id": distributionID,
		},
	}
}

func TestIntegration_CloudFrontAliasAndDomain_ResolveToOneAsset(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)
	integrationID := uuid.NewString()

	// The live shape from the demo discovery: the distribution domain and one
	// alias, different hostnames, ONE shared address, one distribution id.
	const distributionID = "EXAMPLEDIST123"
	const ip = "203.0.113.55"

	findings := []IngestFinding{
		cloudFrontFinding("df0pxeck85ppe.cloudfront.net", ip, distributionID, integrationID),
		cloudFrontFinding("shop.example.com", ip, distributionID, integrationID),
	}

	if _, err := svc.IngestFindings(tenant, findings, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var assets int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if assets != 1 {
		t.Fatalf("one CloudFront distribution produced %d assets, want 1 — the distribution domain and "+
			"its alias are one resource, and `distribution_id` is the identifier that says so", assets)
	}

	// …and it carries the provider's id, not just a hostname. An asset that
	// happened to collapse for some other reason would pass the count above.
	var ids int
	if err := raw.QueryRow(`
		SELECT COUNT(*) FROM asset_identifiers
		 WHERE tenant_id = $1 AND kind = 'cloud_resource_id' AND value = $2`,
		tenant, distributionID).Scan(&ids); err != nil {
		t.Fatalf("count cloud_resource_id identifiers: %v", err)
	}
	if ids != 1 {
		t.Errorf("the distribution carries %d `cloud_resource_id` identifier(s) with value %q, want 1 — "+
			"the provider's own id is the strongest identifier a cloud resource ever has and must be recorded",
			ids, distributionID)
	}
}

// The other polarity: two DIFFERENT distributions must stay two assets. Without
// it, a "fix" that collapsed every cloud finding onto one asset would pass the
// test above.
func TestIntegration_TwoCloudFrontDistributions_StayTwoAssets(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)
	integrationID := uuid.NewString()

	// Same shared CloudFront edge address, two distributions. The address is
	// genuinely shared — that is what a CDN edge is — so anything keying on it
	// would merge them.
	const ip = "203.0.113.55"
	findings := []IngestFinding{
		cloudFrontFinding("d111111abcdef8.cloudfront.net", ip, "EXAMPLEDISTAAA", integrationID),
		cloudFrontFinding("d222222abcdef8.cloudfront.net", ip, "EXAMPLEDISTBBB", integrationID),
	}

	if _, err := svc.IngestFindings(tenant, findings, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var assets int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&assets); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if assets != 2 {
		t.Fatalf("two distinct CloudFront distributions produced %d assets, want 2 — a shared CDN edge "+
			"address is not evidence that two resources are one", assets)
	}
}

// Existing data: two assets a PRE-FIX run already created for one distribution.
//
// This is the reason there is no backfill. Merging two assets is not something
// a POST-MIGRATIONS statement may do — auto-merge is what ADR-0002 D5 forbids,
// and a SQL job has no way to ask. What the fix does instead is let the next
// discovery run SEE the collision: the alias finding now carries the
// distribution id, which belongs to one asset, and its FQDN, which belongs to
// another. Two assets matched by different identifiers is the contested case,
// and the engine holds the observation rather than creating a third asset or
// silently picking one.
func TestIntegration_PreExistingCloudFrontDuplicate_IsHeldNotCompounded(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)
	integrationID := uuid.NewString()

	const distributionID = "EXAMPLEDIST123"
	const ip = "203.0.113.55"
	const domain = "df0pxeck85ppe.cloudfront.net"
	const alias = "shop.example.com"

	// A pre-fix run: the collectors wrote `distribution_id`, nothing read it,
	// and the distribution became two assets.
	preFix := func(hostname string) IngestFinding {
		f := cloudFrontFinding(hostname, ip, distributionID, integrationID)
		delete(f.RawData, "distribution_id")
		return f
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{preFix(domain), preFix(alias)}, "monitoring"); err != nil {
		t.Fatalf("pre-fix IngestFindings: %v", err)
	}
	var before int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&before); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if before != 2 {
		t.Fatalf("the pre-fix state is %d assets, want 2 — this test is not reproducing the state it "+
			"claims to be about", before)
	}

	// The next run, with the fix.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{
		cloudFrontFinding(domain, ip, distributionID, integrationID),
		cloudFrontFinding(alias, ip, distributionID, integrationID),
	}, "monitoring"); err != nil {
		t.Fatalf("post-fix IngestFindings: %v", err)
	}

	var after int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&after); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if after != before {
		t.Errorf("a re-run over a pre-existing duplicate produced %d assets, want the %d that were "+
			"already there — the fix must not compound the duplicate it cannot merge", after, before)
	}

	// …and the collision was RAISED, not swallowed. A merge proposal is an
	// `asset_history` row with action 'merge_proposed'; it is what puts the
	// question in front of a human, and it is the whole reason a SQL backfill
	// is the wrong instrument here.
	var proposals int
	if err := raw.QueryRow(`
		SELECT COUNT(*) FROM asset_history
		 WHERE tenant_id = $1 AND action = 'merge_proposed'`, tenant).Scan(&proposals); err != nil {
		t.Fatalf("count merge proposals: %v", err)
	}
	if proposals == 0 {
		t.Error("no merge proposal was opened for the pre-existing duplicate — the collision is now " +
			"visible to the engine and must reach Approvals, not be silently tolerated")
	}
}
