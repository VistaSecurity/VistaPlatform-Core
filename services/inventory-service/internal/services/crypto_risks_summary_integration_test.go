package services

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CryptoRisksSummary_CanonicalJudgments(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewCryptoRisksService(db)
	asset := uuid.New()
	if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,created_at,updated_at) VALUES($1,$2,'bands.test','server','hardware.computer.server','monitoring',NOW(),NOW())`, asset, tenant); err != nil {
		t.Fatal(err)
	}
	for _, score := range []int{90, 70, 40, 1, 0} {
		alg, ci := uuid.New(), uuid.New()
		if _, err := db.Exec(`INSERT INTO algorithms(id,code,name,category,strength,risk_score) VALUES($1,$2,'test','symmetric','weak',$3)`, alg, "READ-"+alg.String(), score); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM algorithms WHERE id=$1`, alg) })
		if _, err := db.Exec(`INSERT INTO crypto_implementations(id,tenant_id,asset_id,protocol,discovery_method,risk_score,created_at,updated_at) VALUES($1,$2,$3,'TLS','passive',0,NOW(),NOW())`, ci, tenant, asset); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type) VALUES($1,$2,'symmetric')`, ci, alg); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := svc.GetSummary(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Critical != 1 || summary.TotalAffected != 1 || summary.High+summary.Medium+summary.Low+summary.Informational+summary.Unscored != 0 {
		t.Fatalf("not worst-per-asset: %+v", summary)
	}
	for _, band := range []string{"critical", "high", "medium", "low", "info", "informational"} {
		page, err := svc.ListRisks(tenant, CryptoRiskFilters{Severity: []string{band}})
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 1 {
			t.Fatalf("%s total=%d", band, page.Total)
		}
	}
}

func TestIntegration_CryptoRisks_StreamedPageSelection(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	asset, algorithm := uuid.New(), uuid.New()
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status) VALUES($1,$2,'stream.test','server','hardware.computer.server','monitoring')`, asset, tenant)
	must(`INSERT INTO algorithms(id,code,name,category,strength,risk_score) VALUES($1,$2,'stream','symmetric','weak',0)`, algorithm, "STREAM-"+algorithm.String())
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE id=$1`, algorithm) })
	must(`WITH inserted AS (
 INSERT INTO crypto_implementations(id,tenant_id,asset_id,protocol,discovery_method,risk_score)
 SELECT gen_random_uuid(),$1,$2,'TLS','passive',0 FROM generate_series(1,2000) RETURNING id)
 INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type)
 SELECT id,$3,'symmetric' FROM inserted`, tenant, asset, algorithm)
	svc := NewCryptoRisksService(db)
	started := time.Now()
	page, err := svc.ListRisks(tenant, CryptoRiskFilters{Page: 3, PageSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("2000 candidates, keep <=300 rows: page selection %s", time.Since(started))
	if len(page.Risks) != 100 || page.Total != 2000 {
		t.Fatalf("page count %+v", page)
	}
	started = time.Now()
	exported, err := svc.ExportRisks(tenant, CryptoRiskFilters{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("2000 candidates, single-pass export: %s", time.Since(started))
	if len(exported) != 2000 {
		t.Fatalf("exported %d", len(exported))
	}
	for i, r := range page.Risks {
		if r.ID != exported[i+200].ID {
			t.Fatalf("page/export order drift at %d", i)
		}
	}
}
