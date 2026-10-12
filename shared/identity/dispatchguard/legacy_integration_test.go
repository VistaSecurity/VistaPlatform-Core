package dispatchguard

// AuthorizeLegacyManualTargets against real rows: literals are judged on the
// scope as it is now; a hostname is judged on the addresses it was authorized
// on (the job's pinned_addresses), and refused when none were recorded.

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AuthorizeLegacyManualTargets(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	job := uuid.New()
	if _, err := db.Exec(`INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,metadata) VALUES($1,$2,'sensors','queued',$3::jsonb)`,
		job, tenant, `{"pinned_addresses":{"ok.internal.test":["10.55.0.9"],"bad.internal.test":["10.56.0.9"]}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,$2::jsonb) ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`,
		tenant, `{"identity_enrichment":{"excluded_cidrs":["10.56.0.0/24","10.57.0.0/24"]}}`); err != nil {
		t.Fatal(err)
	}
	payload := sensordispatch.Payload{JobID: job.String(), TenantID: tenant.String(),
		Targets: []string{"10.55.0.1", "10.57.0.1", "ok.internal.test", "bad.internal.test", "unpinned.internal.test", "127.0.0.1"}}

	kept, refused, err := AuthorizeLegacyManualTargets(db, payload, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(kept, ",") != "10.55.0.1,ok.internal.test" {
		t.Fatalf("kept = %v", kept)
	}
	got := map[string]string{}
	for _, r := range refused {
		got[r.Target] = r.Reason
	}
	for _, target := range []string{"10.57.0.1", "bad.internal.test", "unpinned.internal.test", "127.0.0.1"} {
		if got[target] == "" {
			t.Errorf("%s was not refused (refused: %v)", target, got)
		}
	}
	if !strings.Contains(got["unpinned.internal.test"], "not recorded") {
		t.Errorf("unpinned name reason = %q", got["unpinned.internal.test"])
	}

	// A job that no longer exists authorizes nothing.
	payload.JobID = uuid.NewString()
	kept, refused, err = AuthorizeLegacyManualTargets(db, payload, uuid.New())
	if err != nil || len(kept) != 0 || len(refused) != len(payload.Targets) {
		t.Fatalf("missing job: kept=%v refused=%d err=%v", kept, len(refused), err)
	}
	// A payload that does not name a valid job authorizes nothing and does not error.
	payload.JobID = "not-a-uuid"
	kept, refused, err = AuthorizeLegacyManualTargets(db, payload, uuid.New())
	if err != nil || len(kept) != 0 || len(refused) != len(payload.Targets) {
		t.Fatalf("bad job id: kept=%v refused=%d err=%v", kept, len(refused), err)
	}
}
