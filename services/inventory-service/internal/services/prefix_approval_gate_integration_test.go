package services

// Pins the ONE rule: an asset is auto-approved if and only if its address is
// in a prefix with auto-approve enabled — the LONGEST-matching prefix (DCIM row
// 1.6, ADR-0010 D3). Both polarities, on every path that creates an asset from a
// caller's request — manual create, spreadsheet/CMDB bulk import — plus the
// negative security case: a request that asks for `monitoring` must not get it.
//
// The rules are written by the prefix's own write (prefix_approval_rules.go,
// hooked into the IPAM engine's AfterWrite), so the fixture declares prefixes
// through the real IPAM service, exactly as Inventory → Networks does.
//
// Mutations:
//   - restore `AfterWrite: refreshAfterPrefixWrite` on the prefix spec (no
//     generator) and every "monitoring" expectation goes red;
//   - make approval.PrefixSet.Match return the FIRST containing prefix rather
//     than the longest and 192.0.2.200 — inside the /25 carved out of the
//     auto-approving /24, with no rule of its own — is approved.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/testdb"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

type approvalGateFixture struct {
	assets *AssetService
	ipam   *IPAMService
	tenant uuid.UUID
	// auto is the auto-approving /24; nested the /25 inside it without
	// auto-approve; manual the /24 that never auto-approves.
	auto, nested, manual uuid.UUID
}

func (f *approvalGateFixture) createPrefix(t *testing.T, body map[string]any) uuid.UUID {
	t.Helper()
	raw, _ := json.Marshal(body)
	out, err := f.ipam.Create(ipamTestCtx(), f.tenant, "prefixes", raw)
	if err != nil {
		t.Fatalf("create prefix %v: %v", body["prefix"], err)
	}
	var row struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(out, &row); err != nil {
		t.Fatal(err)
	}
	return row.ID
}

// newApprovalGateFixture wires an AssetService the way main.go does and
// declares the prefixes through the IPAM service.
//
// Addresses are RFC 5737 documentation ranges throughout.
func newApprovalGateFixture(t *testing.T) *approvalGateFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	f := &approvalGateFixture{assets: NewAssetService(db), ipam: NewIPAMService(raw), tenant: testdb.NewTenant(t, raw)}
	f.auto = f.createPrefix(t, map[string]any{"prefix": "192.0.2.0/24", "network_type": "private", "auto_approve_discoveries": true})
	f.nested = f.createPrefix(t, map[string]any{"prefix": "192.0.2.128/25", "network_type": "private"})
	f.manual = f.createPrefix(t, map[string]any{"prefix": "198.51.100.0/24", "network_type": "private"})
	return f
}

func TestIntegration_CreateAsset_PrefixToggleIsTheOnlyGate(t *testing.T) {
	f := newApprovalGateFixture(t)
	for _, tc := range []struct {
		ip, want, why string
	}{
		{"192.0.2.10", "monitoring", "in the auto-approving prefix"},
		{"192.0.2.200", "pending_approval", "in a /25 carved out of it with no rule: the longest match decides"},
		{"198.51.100.10", "pending_approval", "in a prefix with auto-approve off"},
		{"203.0.113.10", "pending_approval", "in no prefix at all: default deny"},
	} {
		a, err := f.assets.CreateAsset(f.tenant, models.AssetInput{
			ClassKey: assetclass.KeyServer, IPAddress: strPtr(tc.ip), Hostname: strPtr("app-" + tc.ip + ".example.com"),
		})
		if err != nil {
			t.Fatalf("create at %s: %v", tc.ip, err)
		}
		if a.AssetStatus != tc.want {
			t.Errorf("asset at %s landed %q, want %q (%s)", tc.ip, a.AssetStatus, tc.want, tc.why)
		}
	}
}

// The rule follows the prefix: turning the switch off disables it, deleting the
// prefix deletes it. Driven through the IPAM service's own writes.
func TestIntegration_PrefixApprovalRule_FollowsThePrefix(t *testing.T) {
	f := newApprovalGateFixture(t)
	rules := func() (total, active int) {
		t.Helper()
		if err := f.assets.db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE is_active)
			FROM discovery_auto_approval_rules WHERE tenant_id = $1 AND query LIKE '%' || $2 || '%'`,
			f.tenant, f.auto.String()).Scan(&total, &active); err != nil {
			t.Fatal(err)
		}
		return total, active
	}
	if total, active := rules(); total != 1 || active != 1 {
		t.Fatalf("after create: %d rule(s), %d active; want exactly one active rule for the prefix", total, active)
	}
	if _, err := f.ipam.Update(ipamTestCtx(), f.tenant, "prefixes", f.auto, []byte(`{"auto_approve_discoveries": false}`)); err != nil {
		t.Fatalf("turn auto-approve off: %v", err)
	}
	if total, active := rules(); total != 1 || active != 0 {
		t.Fatalf("after switching off: %d rule(s), %d active; want the rule kept and disabled", total, active)
	}
	a, err := f.assets.CreateAsset(f.tenant, models.AssetInput{ClassKey: assetclass.KeyServer, IPAddress: strPtr("192.0.2.11"), Hostname: strPtr("after-off.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if a.AssetStatus != "pending_approval" {
		t.Errorf("asset after the switch went off landed %q, want pending_approval", a.AssetStatus)
	}
	if _, err := f.ipam.Update(ipamTestCtx(), f.tenant, "prefixes", f.auto, []byte(`{"auto_approve_discoveries": true}`)); err != nil {
		t.Fatalf("turn auto-approve back on: %v", err)
	}
	if total, active := rules(); total != 1 || active != 1 {
		t.Fatalf("after switching back on: %d rule(s), %d active; want the same rule re-enabled", total, active)
	}
	if err := f.ipam.Delete(ipamTestCtx(), f.tenant, "prefixes", f.nested); err != nil {
		t.Fatalf("delete the nested prefix: %v", err)
	}
	if err := f.ipam.Delete(ipamTestCtx(), f.tenant, "prefixes", f.auto); err != nil {
		t.Fatalf("delete the prefix: %v", err)
	}
	if total, _ := rules(); total != 0 {
		t.Fatalf("after deleting the prefix: %d rule(s) remain for it", total)
	}
}

// The security regression test. A caller asking to be approved must not be.
func TestIntegration_CreateAsset_IgnoresCallerSuppliedApprovalStatus(t *testing.T) {
	f := newApprovalGateFixture(t)
	assetSvc, tenant := f.assets, f.tenant

	for _, status := range []string{"monitoring", "active", "approved"} {
		asset, err := assetSvc.CreateAsset(tenant, models.AssetInput{
			ClassKey:    assetclass.KeyServer,
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
	f := newApprovalGateFixture(t)
	assetSvc, tenant := f.assets, f.tenant

	res := assetSvc.BulkCreateAssets(tenant, []models.AssetInput{
		{ClassKey: assetclass.KeyServer, IPAddress: strPtr("198.51.100.30"), Hostname: strPtr("pulled-1.example.com"), AssetStatus: strPtr("monitoring")},
		{ClassKey: assetclass.KeyServer, IPAddress: strPtr("192.0.2.30"), Hostname: strPtr("pulled-2.example.com")},
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
// the same rule rows. This pins the rows the prefix generator writes against
// the evaluator both consumers use, classified by the ingest classifier
// (classifyFindingIn), so the two paths cannot drift into two definitions of
// "approved".
func TestIntegration_PrefixRules_EvaluateTheSameForTheDiscoveryPipeline(t *testing.T) {
	f := newApprovalGateFixture(t)
	raw := testdb.Connect(t)
	svc := approval.NewService(raw)
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"192.0.2.40", true},
		{"192.0.2.240", false},
		{"198.51.100.40", false},
	} {
		ip := tc.ip
		cls := f.assets.classifyFindingIn(nil, f.tenant, IngestFinding{IPAddress: &ip}, &ip)
		auto, ruleID, err := svc.EvaluateAutoApproval(
			approval.Discovery{TenantID: f.tenant, Address: ip, Metadata: []byte(`{"source":"sensor"}`)}.WithConfidence(1.0), &cls)
		if err != nil {
			t.Fatalf("evaluate %s: %v", ip, err)
		}
		if auto != tc.want || (auto && ruleID == nil) {
			t.Errorf("discovery at %s auto-approved = %v (rule %v), want %v", ip, auto, ruleID, tc.want)
		}
	}
}

func loadAssetStatusByHostname(t *testing.T, svc *AssetService, tenant uuid.UUID, hostname string) string {
	t.Helper()
	var status string
	if err := svc.db.Get(&status,
		`SELECT asset_status FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
		tenant, hostname); err != nil {
		t.Fatalf("load asset %s: %v", hostname, err)
	}
	return status
}
