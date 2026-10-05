package services

// The two engine-less writes that moved onto the engine — the identifier
// edit and a connector's source link — now resolve a declaration FOR their
// asset (identity.Engine.ResolveDeclaredFor). What proves it is the engine's
// own footprint: the `updated` history entry it records, decided by the
// declaration and naming what was attached. A direct AttachIdentifiers writes
// the identifier and nothing else, so reverting either call site to it turns
// these red. Skips without TEST_DATABASE_URL.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// declaredHistory counts the asset's history entries the engine wrote for a
// declaration that attached an identifier with this value.
func declaredHistory(t *testing.T, svc *AssetService, tenant, asset uuid.UUID, value string) int {
	t.Helper()
	var n int
	if err := svc.db.QueryRow(`SELECT count(*) FROM asset_history
		WHERE tenant_id=$1 AND asset_id=$2 AND action='updated'
		  AND changes_json->>'decided_by'='declaration_id'
		  AND changes_json->>'identifiers' LIKE '%' || $3 || '%'`, tenant, asset, value).Scan(&n); err != nil {
		t.Fatalf("read history: %v", err)
	}
	return n
}

func TestIntegration_IdentifierEdit_ResolvesThroughTheEngine(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)
	created, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("declared-for.example.test")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.UpdateAsset(tenant, created.ID, models.AssetInput{
		Identifiers: []models.AssetIdentifierInput{{Kind: "serial_number", Value: "SN-DECLARED-FOR"}},
	}, uuid.New()); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, ok := identifierRows(t, svc, tenant, created.ID)["serial_number|SN-DECLARED-FOR|"]; !ok {
		t.Fatalf("the edit did not attach the serial: %v", identifierRows(t, svc, tenant, created.ID))
	}
	if n := declaredHistory(t, svc, tenant, created.ID, "SN-DECLARED-FOR"); n != 1 {
		t.Fatalf("%d engine history entries for the edit, want 1 — the edit did not resolve through the engine", n)
	}
}

func TestIntegration_SourceLink_ResolvesThroughTheEngine(t *testing.T) {
	f := newCIFixture(t)
	ctx := context.Background()
	tenant := f.tenant(t)
	mine := f.asset(t, tenant, "link-mine.example.test", "monitoring", "")
	other := f.asset(t, tenant, "link-other.example.test", "monitoring", "")
	src := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:profile-9"}

	res, err := f.svc.AttachLinks(ctx, tenant, src, []SourceLink{{AssetID: mine, Kind: "cmdb_sys_id", Value: "SRV-DECLARED", Scope: "profile-9"}})
	if err != nil || res[0].Outcome != SourceItemRecorded {
		t.Fatalf("link = %+v, %v; want recorded", res, err)
	}
	assets := NewAssetService(f.db)
	if n := declaredHistory(t, assets, tenant, mine, "SRV-DECLARED"); n != 1 {
		t.Fatalf("%d engine history entries for the link, want 1 — the link did not resolve through the engine", n)
	}

	// The same record linked to a DIFFERENT asset: refused, reported, and
	// nothing moves — the source's link already belongs to `mine`.
	res, err = f.svc.AttachLinks(ctx, tenant, src, []SourceLink{{AssetID: other, Kind: "cmdb_sys_id", Value: "SRV-DECLARED", Scope: "profile-9"}})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Outcome != SourceOutcomeError || !strings.Contains(res[0].Error, "already belongs to") {
		t.Fatalf("relink to another asset = %+v; want an error naming the owner", res[0])
	}
	var owner uuid.UUID
	if err := f.db.QueryRow(`SELECT asset_id FROM asset_identifiers WHERE tenant_id=$1 AND kind='cmdb_sys_id' AND value='SRV-DECLARED'`, tenant).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != mine {
		t.Fatalf("the link moved to %s; it must stay on %s", owner, mine)
	}
}
