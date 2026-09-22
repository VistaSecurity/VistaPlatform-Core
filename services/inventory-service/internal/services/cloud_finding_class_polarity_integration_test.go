package services

// The two polarities of the class-hint fix, both of which a careless version
// of it would break. Helpers live in
// cloud_finding_class_identity_integration_test.go.
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

// Two DIFFERENT distributions, in the same live shape, must stay two assets.
// Without this, a "fix" that made every cloud finding resolve to whatever
// cloud asset already existed would pass the one-asset test.
func TestIntegration_TwoCloudFrontDistributions_LiveShape_StayTwoAssets(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)
	integrationID := uuid.NewString()

	// One shared CloudFront edge address — that is what a CDN edge IS — so
	// anything keying on the address would merge them.
	const ip = "203.0.113.55"
	findings := []IngestFinding{
		liveCloudFrontFinding("d111111abcdef8.cloudfront.net", ip, "EXAMPLEDISTAAA", integrationID, nil),
		liveCloudFrontFinding("d222222abcdef8.cloudfront.net", ip, "EXAMPLEDISTBBB", integrationID, nil),
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

// Existing data: the split demo is in right now — the collector's
// `cdn_distribution` and an `application` duplicate a PRE-FIX run created for
// the alias.
//
// ADR-0002 D5 forbids auto-merge and there is no backfill, so the fix's job is
// to make the collision VISIBLE: the alias finding now carries the
// distribution id (owned by the collector's asset) and its FQDN (owned by the
// duplicate). Two assets matched by different kinds is the contested case; the
// engine holds the observation and opens a merge proposal rather than creating
// a third asset or silently picking one.
func TestIntegration_PreFixCloudFrontDuplicate_IsProposedNotCompounded(t *testing.T) {
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

	seedCollectorCloudAsset(t, svc, raw, tenant, "cdn_distribution", domain, distributionID)

	// A PRE-FIX run, reproduced by removing the one key the fix reads. Without
	// `device_type` the hint falls through to `application`, whose precedence
	// holds no `cloud_resource_id`, so each hostname became its own asset
	// beside the collector's — the exact three-asset state measured on demo.
	preFix := func(hostname string) IngestFinding {
		f := liveCloudFrontFinding(hostname, ip, distributionID, integrationID, nil)
		delete(f.RawData, "device_type")
		return f
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{preFix(domain), preFix(alias)}, "pending_approval"); err != nil {
		t.Fatalf("pre-fix IngestFindings: %v", err)
	}

	var before int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&before); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if before != 3 {
		t.Fatalf("the pre-fix state is %d assets, want 3 (the collector's plus one per hostname) — this "+
			"test is not reproducing the state it claims to be about", before)
	}

	// The next run, with the fix.
	if _, err := svc.IngestFindings(tenant, []IngestFinding{
		liveCloudFrontFinding(domain, ip, distributionID, integrationID, []interface{}{acmCertificateEntry()}),
		liveCloudFrontFinding(alias, ip, distributionID, integrationID, []interface{}{acmCertificateEntry()}),
	}, "pending_approval"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	var after int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&after); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if after != before {
		t.Errorf("a re-run over a pre-existing duplicate produced %d assets, want the %d already there — "+
			"the fix must not compound a duplicate it is not allowed to merge", after, before)
	}

	var proposals int
	if err := raw.QueryRow(`
		SELECT COUNT(*) FROM asset_history
		 WHERE tenant_id = $1 AND action = 'merge_proposed'`, tenant).Scan(&proposals); err != nil {
		t.Fatalf("count merge proposals: %v", err)
	}
	if proposals == 0 {
		t.Error("no merge proposal was opened for the pre-existing duplicate — auto-merge is forbidden, " +
			"so raising the question is the only honest outcome and it must reach Approvals")
	}
}
