package services

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// TestIntegration_AssetReads_ShowEveryInterfaceAddress: since DCIM row 1.4 an
// asset's addresses live on its interfaces, not in asset_identifiers. The two
// read paths the Inventory list and the asset page use — loadIdentifiersForAssets
// (GetAssets) and getAssetIdentifiers (GetAssetByID) — must still show EVERY
// address, one per interface, where the identifier rows used to.
//
// Mutation: read `FROM asset_identifiers` instead of identifiersql.All in
// asset_sql.go (either reader) and the matching half goes red.
func TestIntegration_AssetReads_ShowEveryInterfaceAddress(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)
	ctx := context.Background()
	created, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("two-nics.example.test")})
	if err != nil {
		t.Fatal(err)
	}
	ref := identity.AssetRef{TenantID: tenant.String(), ID: created.ID.String()}
	var ids []identity.Identifier
	for _, a := range []struct{ addr, iface string }{{"192.0.2.81", "eth0"}, {"198.51.100.81", "eth1"}} {
		ids = append(ids, identity.Identifier{
			Kind: identity.KindIPAddress, Value: a.addr, Scope: identity.ScopeTenantDefault, Confidence: 1,
			Interface: a.iface, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "agent:two-nics"},
		})
	}
	if _, err := svc.identityRepo.AttachIdentifiers(ctx, ref, ids); err != nil {
		t.Fatal(err)
	}
	var onInterfaces int
	if err := svc.db.QueryRow(`SELECT count(DISTINCT ip.assigned_id) FROM ip_addresses ip
		  JOIN interfaces ifc ON ifc.id = ip.assigned_id
		 WHERE ip.tenant_id = $1 AND ifc.asset_id = $2`, tenant, created.ID).Scan(&onInterfaces); err != nil {
		t.Fatal(err)
	}
	if onInterfaces != 2 {
		t.Fatalf("addresses on %d interfaces, want 2 (eth0, eth1)", onInterfaces)
	}
	want := map[string]bool{"192.0.2.81": true, "198.51.100.81": true}
	check := func(path string, got []models.Identifier) {
		t.Helper()
		seen := map[string]bool{}
		for _, id := range got {
			if id.Kind == string(identity.KindIPAddress) {
				seen[id.Value] = true
			}
		}
		for a := range want {
			if !seen[a] {
				t.Errorf("%s: address %s missing from the asset's identifiers %+v", path, a, got)
			}
		}
	}

	page, err := svc.GetAssetByID(tenant, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	check("asset page (GetAssetByID)", page.Identifiers)

	list, _, err := svc.GetAssets(tenant, models.AssetFilters{Page: 1, PageSize: 50, AssetStatus: []string{page.AssetStatus}})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list returned %d assets, want the one", len(list))
	}
	check("asset list (GetAssets)", list[0].Identifiers)
}
