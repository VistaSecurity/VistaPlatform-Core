package jobs

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Exercise the production scheduler's tenant pass, including its post-producer
// rollup. A producer-only test cannot catch a missing call here.
func TestIntegration_FindingProducerJob_ReassessesExistingCrypto(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	asset, cfg, alg, finding := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO assets(id,tenant_id,hostname,display_name,class_key,class_path,asset_status) VALUES($1,$2,'reassessment','reassessment','server','hardware.computer.server','monitoring')`, []any{asset, tenant}},
		{`INSERT INTO crypto_implementations(id,tenant_id,asset_id,protocol,protocol_version,discovery_method,risk_score) VALUES($1,$2,$3,'TLS','TLS 1.3','active',10)`, []any{cfg, tenant, asset}},
		{`INSERT INTO algorithms(id,name,code,category,strength,risk_score,primitive) VALUES($1,$2,$2,'protocol_version','recommended',10,'other')`, []any{alg, "SCHEDULER-" + alg.String()}},
		{`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type) VALUES($1,$2,'protocol_version')`, []any{cfg, alg}},
		{`INSERT INTO findings(id,tenant_id,producer,kind,subject_type,subject_id,severity,score,summary,detection_state,workflow_status) VALUES($1,$2,'crypto','weak_configuration','crypto_configuration',$3,'low',10,'Old false weak title','ACTIVE','NEW')`, []any{finding, tenant, cfg}},
	} {
		if _, err := owner.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM algorithms WHERE id=$1`, alg) })
	job, err := NewFindingProducerJob(app, owner)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		testdb.WithSchemaShareLock(t, owner, func() {
			if !job.runTenant(context.Background(), tenant) {
				t.Fatal("tenant producer pass failed")
			}
		})
		var state string
		var score int
		var covered bool
		if err := owner.QueryRow(`SELECT detection_state FROM findings WHERE id=$1`, finding).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(`SELECT risk_score,'crypto'=ANY(risk_assessed_by) FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&score, &covered); err != nil {
			t.Fatal(err)
		}
		if state != "INACTIVE" || score != 0 || !covered {
			t.Fatalf("pass %d state=%s risk=%d covered=%v", i, state, score, covered)
		}
	}
}
