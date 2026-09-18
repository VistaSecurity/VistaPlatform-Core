package services

import (
	"context"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"testing"
)

func TestIntegration_NameProvenanceCombinedAndMetadataOnly(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)
	asset, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: "server", Hostname: ptr("before.example.test")})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.UpdateAsset(tenant, asset.ID, models.AssetInput{Hostname: ptr("operator.example.test"), DisplayName: ptr("My server"), Metadata: models.JSONB{"custom": "kept", "name_source_kind": "measured-passive"}}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.UpdateAsset(tenant, asset.ID, models.AssetInput{Metadata: models.JSONB{"custom": "replaced", "name_source_kind": "measured-passive"}}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	var source, custom string
	if err := db.QueryRow(`SELECT metadata->>'name_source_kind',metadata->>'custom' FROM assets WHERE id=$1`, asset.ID).Scan(&source, &custom); err != nil {
		t.Fatal(err)
	}
	if source != "declared" || custom != "replaced" {
		t.Fatalf("source=%s custom=%s", source, custom)
	}
	repo := pgidentity.New(db.DB.DB)
	if err := repo.PromoteNames(context.Background(), identity.AssetRef{TenantID: tenant.String(), ID: asset.ID.String()}, "probe.example.test", "probe.example.test", "measured-active"); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := db.QueryRow(`SELECT hostname FROM assets WHERE id=$1`, asset.ID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "operator.example.test" {
		t.Fatal(name)
	}
}
