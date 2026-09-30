package services

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_ScheduledCloudJob_NoParametersRunsCollectors drives the whole
// scheduled path against a real database: a schedule created the way the
// Scheduled Scans modal creates one (no parameters), fired by TriggerSchedule,
// read back from device_jobs, and executed by the REAL executeCloudDiscovery.
// Every collector a manual run would dispatch must run.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
//
// MUTATION-VERIFIED alongside the unit test: without the default in
// executeCloudDiscovery, no collector runs.
func TestIntegration_ScheduledCloudJob_NoParametersRunsCollectors(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()
	integrationID := seedCloudIntegration(t, owner, tenantID)

	jobQueue := NewJobQueueService(owner, owner, nil)
	scheduler := NewSchedulerService(owner, owner, jobQueue)

	// Exactly the body schedule-modals.tsx sends: no `parameters` key.
	schedule, err := scheduler.CreateSchedule(ctx, tenantID, CreateScheduleRequest{
		Name:           "nightly cloud",
		CronExpression: "0 3 * * *",
		TargetType:     "cloud_integration",
		TargetID:       integrationID,
	})
	if err != nil {
		t.Fatalf("CreateSchedule: %v", err)
	}
	fired, err := scheduler.TriggerSchedule(ctx, tenantID, schedule.ID)
	if err != nil {
		t.Fatalf("TriggerSchedule: %v", err)
	}

	// The worker executes the job as it reads back from device_jobs.
	job, err := jobQueue.GetJobByID(ctx, fired.ID)
	if err != nil || job == nil {
		t.Fatalf("GetJobByID: %v (job %v)", err, job)
	}

	t.Setenv("ENCRYPTION_MASTER_KEY", "unit-test-master-key-0123456789abcdef")
	d := &recordingDiscoverer{provider: "aws"}
	w := &PlatformAgentWorker{cloudService: d, cloudSink: &recordingCloudSink{}}
	if _, err := w.executeCloudDiscovery(ctx, job); err != nil {
		t.Fatalf("executeCloudDiscovery: %v", err)
	}

	got := append([]string(nil), d.ran...)
	want := DefaultCloudResourceTypes("aws")
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scheduled run dispatched collectors %v, want %v", got, want)
	}
}
