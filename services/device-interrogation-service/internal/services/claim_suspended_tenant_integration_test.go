package services

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// A job queued before its tenant was suspended used to run anyway: the
// scheduler stopped creating jobs for a suspended tenant, but the claim took
// whatever was pending. The claim now applies the same tenantstate predicate.
// Driven through the agent lane, which is tenant-scoped and so cannot claim
// another test's job from the shared database; the platform lane uses the same
// candidate query.
//
// MUTATION-VERIFIED: drop the usableTenant clause from claimAuthorizedJob's
// candidate query and the suspended tenant's job is claimed.
//
// Skips unless TEST_DATABASE_URL is set.
func TestIntegration_Claim_SkipsJobsOfSuspendedTenants(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	queue, tenant, agent, job := sourceClaimFixture(t, db, true)
	// An ordinary job: nothing about identity-refresh policy decides it.
	ordinary, err := queue.CreateJob(context.Background(), models.CreateDeviceJobRequest{TenantID: tenant, JobType: job.JobType, AssetID: job.AssetID, AgentID: agent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE device_jobs SET parameters=NULL WHERE id=$1`, ordinary.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE device_jobs SET status='cancelled' WHERE tenant_id=$1 AND id<>$2`, tenant, ordinary.ID); err != nil {
		t.Fatal(err)
	}

	for _, status := range []string{"suspended", "canceled"} {
		if _, err := db.Exec(`UPDATE tenants SET payment_status=$2 WHERE id=$1`, tenant, status); err != nil {
			t.Fatal(err)
		}
		got, err := queue.claimAuthorizedJob(context.Background(), agent, &tenant)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("a %s tenant's queued job was claimed", status)
		}
	}

	// Reactivated, the same job runs.
	if _, err := db.Exec(`UPDATE tenants SET payment_status='active' WHERE id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	got, err := queue.claimAuthorizedJob(context.Background(), agent, &tenant)
	if err != nil || got == nil || got.ID != ordinary.ID {
		t.Fatalf("the reactivated tenant's job was not claimed: %v %v", got, err)
	}
}
