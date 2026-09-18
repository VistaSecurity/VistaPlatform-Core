package services

import (
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"testing"
)

func TestIntegration_FacetUnsetAndSegmentCountsMatchClicks(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	other := testdb.NewTenant(t, raw)
	svc := &AssetService{db: &database.DB{DB: sqlx.NewDb(raw, "postgres")}}
	segments := []uuid.UUID{uuid.New(), uuid.New()}
	for i, id := range segments {
		cidr := []string{"192.0.2.0/24", "198.51.100.0/24"}[i]
		if _, err := raw.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'Same label','cidr',$3,'production')`, id, tenant, cidr); err != nil {
			t.Fatal(err)
		}
	}
	for i, owner := range []any{nil, "", "ops@example.test"} {
		var segment any
		if i < 2 {
			segment = segments[i]
		}
		if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,class_key,class_path,asset_status,owner_email,business_unit,site,network_segment_id) VALUES($1,$2,'server','hardware.computer.server','monitoring',$3,$3,$3,$4)`, uuid.New(), tenant, owner, segment); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,class_key,class_path,asset_status) VALUES($1,$2,'server','hardware.computer.server','monitoring')`, uuid.New(), other); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"owner_email", "business_unit", "site"} {
		buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{}, field, 50)
		if err != nil {
			t.Fatal(err)
		}
		unknown := 0
		for _, b := range buckets {
			if b.Key == "Unknown" {
				unknown = b.Count
			}
		}
		if unknown != 2 {
			t.Fatalf("%s unknown=%d want 2", field, unknown)
		}
		query := `(not exists(` + field + `) or ` + field + ` = "")`
		selected, err := svc.GetAssetFacets(tenant, models.AssetFilters{Query: query}, field, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(selected) != 1 || selected[0].Count != unknown {
			t.Fatalf("%s click diverged: %+v", field, selected)
		}
	}
	buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{}, "segment", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 3 {
		t.Fatalf("segment groups=%+v", buckets)
	}
	for _, b := range buckets {
		query := "segment_id:" + b.Key
		if b.Key == "Unsegmented" {
			query = "not exists(segment_id)"
		}
		selected, err := svc.GetAssetFacets(tenant, models.AssetFilters{Query: query}, "segment", 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(selected) != 1 || selected[0].Key != b.Key || selected[0].Count != b.Count {
			t.Fatalf("segment click diverged: %+v", selected)
		}
	}
}
