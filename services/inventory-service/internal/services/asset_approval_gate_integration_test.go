package services

// Pins the ONE rule: an asset is auto-approved if and only if it is on a
// user-defined network segment with auto-approve enabled. Both polarities, on
// every path that creates an asset from a caller's request — manual create,
// spreadsheet/CMDB bulk import — plus the negative security case: a request that
// asks for `monitoring` must not get it.
//
// Before this, CreateAsset took input.AssetStatus verbatim, so the tenant's own
// approval policy was advisory: bypassable by any caller that supplied a status,
// and inapplicable to anyone who did not (an asset on an auto-approve segment
// still queued).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newApprovalGateFixture wires an AssetService the way main.go does (with the
// network-segment service attached) and gives the tenant one auto-approving
// segment. Rules are generated from segments by ManageAutoApprovalRules, exactly
// as the Settings → Infrastructure toggle does.
//
// Addresses are RFC 5737 documentation ranges throughout.
func newApprovalGateFixture(t *testing.T) (*AssetService, *NetworkSegmentService, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	segSvc := NewNetworkSegmentService(db, NewLocationService(db))
	assetSvc := NewAssetService(db)
	assetSvc.SetEnrichmentServices(segSvc, nil)

	// 192.0.2.0/24 auto-approves; 198.51.100.0/24 is a known segment that does not.
	if _, err := segSvc.Create(tenant, models.NetworkSegmentInput{
		Name: "auto-approve lab", SegmentType: "cidr", Value: "192.0.2.0/24",
		NetworkType: "private", Environment: "production",
		AutoApproveDiscoveries: boolPtr(true),
	}); err != nil {
		t.Fatalf("create auto-approve segment: %v", err)
	}
	if _, err := segSvc.Create(tenant, models.NetworkSegmentInput{
		Name: "manual review", SegmentType: "cidr", Value: "198.51.100.0/24",
		NetworkType: "private", Environment: "production",
		AutoApproveDiscoveries: boolPtr(false),
	}); err != nil {
		t.Fatalf("create manual segment: %v", err)
	}
	if err := segSvc.ManageAutoApprovalRules(tenant, uuid.Nil); err != nil {
		t.Fatalf("generate auto-approval rules from segments: %v", err)
	}
	return assetSvc, segSvc, tenant
}

func TestIntegration_CreateAsset_SegmentToggleIsTheOnlyGate(t *testing.T) {
	assetSvc, _, tenant := newApprovalGateFixture(t)

	onSegment, err := assetSvc.CreateAsset(tenant, models.AssetInput{
		AssetType: "server", IPAddress: strPtr("192.0.2.10"), Hostname: strPtr("app-1.example.com"),
	})
	if err != nil {
		t.Fatalf("create on auto-approve segment: %v", err)
	}
	if onSegment.AssetStatus != "monitoring" {
		t.Fatalf("asset on an auto-approve segment landed %q, want monitoring — the segment toggle must apply to every path, not only sensor discoveries", onSegment.AssetStatus)
	}

	offSegment, err := assetSvc.CreateAsset(tenant, models.AssetInput{
		AssetType: "server", IPAddress: strPtr("198.51.100.10"), Hostname: strPtr("app-2.example.com"),
	})
	if err != nil {
		t.Fatalf("create off auto-approve segment: %v", err)
	}
	if offSegment.AssetStatus != "pending_approval" {
		t.Fatalf("asset on a non-auto-approving segment landed %q, want pending_approval", offSegment.AssetStatus)
	}

	// An address in no segment at all is the default-deny case.
	unknown, err := assetSvc.CreateAsset(tenant, models.AssetInput{
		AssetType: "server", IPAddress: strPtr("203.0.113.10"), Hostname: strPtr("app-3.example.com"),
	})
	if err != nil {
		t.Fatalf("create outside every segment: %v", err)
	}
	if unknown.AssetStatus != "pending_approval" {
		t.Fatalf("asset outside every segment landed %q, want pending_approval", unknown.AssetStatus)
	}
}

// The security regression test. A caller asking to be approved must not be.
func TestIntegration_CreateAsset_IgnoresCallerSuppliedApprovalStatus(t *testing.T) {
	assetSvc, _, tenant := newApprovalGateFixture(t)

	for _, status := range []string{"monitoring", "active", "approved"} {
		asset, err := assetSvc.CreateAsset(tenant, models.AssetInput{
			AssetType:   "server",
			IPAddress:   strPtr("198.51.100.20"),
			Hostname:    strPtr("claimed-" + status + ".example.com"),
			AssetStatus: strPtr(status),
		})
		if err != nil {
			t.Fatalf("create with asset_status=%q: %v", status, err)
		}
		if asset.AssetStatus != "pending_approval" {
			t.Fatalf("a request asking for asset_status=%q produced %q — approval must be evaluated server-side, never supplied by the caller", status, asset.AssetStatus)
		}
	}
}

// CMDB pull and spreadsheet import both reach CreateAsset through
// BulkCreateAssets, so the same hole existed there. Fixing CreateAsset fixes
// both — this asserts it rather than assuming it.
func TestIntegration_BulkCreateAssets_IgnoresCallerSuppliedApprovalStatus(t *testing.T) {
	assetSvc, _, tenant := newApprovalGateFixture(t)

	res := assetSvc.BulkCreateAssets(tenant, []models.AssetInput{
		{AssetType: "server", IPAddress: strPtr("198.51.100.30"), Hostname: strPtr("pulled-1.example.com"), AssetStatus: strPtr("monitoring")},
		{AssetType: "server", IPAddress: strPtr("192.0.2.30"), Hostname: strPtr("pulled-2.example.com")},
	})
	if res.Created != 2 {
		t.Fatalf("bulk import created %d rows, want 2 (rows: %+v)", res.Created, res.Results)
	}

	claimed := loadAssetStatusByHostname(t, assetSvc, tenant, "pulled-1.example.com")
	if claimed != "pending_approval" {
		t.Fatalf("a bulk row asking for monitoring off-segment landed %q — CMDB pull must not be able to promote assets", claimed)
	}
	onSegment := loadAssetStatusByHostname(t, assetSvc, tenant, "pulled-2.example.com")
	if onSegment != "monitoring" {
		t.Fatalf("a bulk row on an auto-approve segment landed %q, want monitoring", onSegment)
	}
}

// The discovery pipeline reaches the same decision through shared/approval over
// the same rule rows. This pins the rows ManageAutoApprovalRules writes against
// the evaluator both consumers use, so the two paths cannot drift into two
// different definitions of "approved".
func TestIntegration_SegmentRules_EvaluateTheSameForTheDiscoveryPipeline(t *testing.T) {
	_, segSvc, tenant := newApprovalGateFixture(t)

	raw := testdb.Connect(t)
	svc := approval.NewService(raw)

	classificationFor := func(ip string) *approval.Classification {
		seg, err := segSvc.GetSegmentForIP(tenant, &ip, nil)
		if err != nil {
			t.Fatalf("segment lookup for %s: %v", ip, err)
		}
		c := &approval.Classification{Ownership: "unknown", Type: "private"}
		if seg != nil {
			id, name := seg.ID, seg.Name
			c.Ownership, c.Type, c.SegmentID, c.SegmentName = "internal", seg.NetworkType, &id, &name
		}
		return c
	}

	auto, ruleID, err := svc.EvaluateAutoApproval(approval.Discovery{TenantID: tenant, Confidence: 1.0}, classificationFor("192.0.2.40"))
	if err != nil {
		t.Fatalf("evaluate on-segment: %v", err)
	}
	if !auto || ruleID == nil {
		t.Fatal("a discovery on an auto-approve segment was not auto-approved by the shared evaluator")
	}

	auto, _, err = svc.EvaluateAutoApproval(approval.Discovery{TenantID: tenant, Confidence: 1.0}, classificationFor("198.51.100.40"))
	if err != nil {
		t.Fatalf("evaluate off-segment: %v", err)
	}
	if auto {
		t.Fatal("a discovery on a segment with auto-approve OFF was auto-approved — the toggle is the only gate")
	}
}

func loadAssetStatusByHostname(t *testing.T, svc *AssetService, tenant uuid.UUID, hostname string) string {
	t.Helper()
	var status string
	if err := svc.db.Get(&status,
		`SELECT asset_status FROM network_assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
		tenant, hostname); err != nil {
		t.Fatalf("load asset %s: %v", hostname, err)
	}
	return status
}
