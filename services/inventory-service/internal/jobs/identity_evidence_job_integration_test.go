package jobs

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type mergeOnlyTenantSweep struct {
	tenant    uuid.UUID
	cancel    context.CancelFunc
	published bool
}

func (s *mergeOnlyTenantSweep) PublishPendingMergeEvents(_ context.Context, tenant uuid.UUID) (int, error) {
	if tenant == s.tenant {
		s.published = true
	}
	return 0, nil
}
func (s *mergeOnlyTenantSweep) SweepIdentityEvidence(_ context.Context, tenant uuid.UUID) (int, error) {
	if tenant == s.tenant {
		s.cancel()
	}
	return 0, nil
}

func TestIntegration_IdentityMaintenanceIncludesMergeOnlyTenants(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO asset_merge_audits(tenant_id,id,revision,reason,survivor_asset_id,source_asset_ids,audit,result,pending_events) VALUES($1,$2,$3,'test',$4,ARRAY[$5::uuid],'{}','{}','[{"pending":true}]')`, tenant, uuid.New(), uuid.NewString(), uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	sweeper := &mergeOnlyTenantSweep{tenant: tenant, cancel: cancel}
	StartIdentityEvidenceWorker(ctx, db, sweeper, sweeper)
	if !sweeper.published {
		t.Fatal("merge-only tenant never reached publication maintenance")
	}
}

func TestIdentityMaintenanceMainWiresMergePublisher(t *testing.T) {
	main, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "jobs.StartIdentityEvidenceWorker(ctx, bypassDB, assetService, mergeProposalService)") {
		t.Fatal("merge outbox missing from running maintenance worker")
	}
}
