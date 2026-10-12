package services

// A person's protocols x ports scan on a tenant sensor (the legacy shape):
//   - a Cancel reaches its sensor command, collected or not;
//   - the scan is re-authorized when it is dispatched and when it is retried,
//     against the tenant's scope as it is then, not as it was at creation;
//   - a job that asked for no active scanning says so.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func (f *dispatchFixture) commandStatuses(t *testing.T, commandType, jobID string) []string {
	t.Helper()
	rows, err := f.raw.Query(`SELECT status FROM sensor_commands WHERE command_type = $1 AND payload ->> 'job_id' = $2 ORDER BY created_at`, commandType, jobID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (f *dispatchFixture) dispatchLegacyJob(t *testing.T, jobID string) {
	t.Helper()
	full, err := f.svc.GetJob(jobID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.dispatchToSensor(full); err != nil {
		t.Fatal(err)
	}
}

func (f *dispatchFixture) excludeRange(t *testing.T, cidr string) {
	t.Helper()
	if _, err := f.raw.Exec(`INSERT INTO tenant_admin_settings (tenant_id, config) VALUES ($1, $2::jsonb) ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config`,
		f.tenant, `{"identity_enrichment":{"excluded_cidrs":["`+cidr+`"]}}`); err != nil {
		t.Fatal(err)
	}
}

// Mutation: restore the early return for a job without a scan plan in
// revokeSensorDispatch and the command stays pending, turning this red.
func TestIntegration_CancelLegacyJob_WithdrawsOrCancelsItsSensorCommand(t *testing.T) {
	f := newDispatchFixture(t)
	sensor := f.liveSensor(t, "legacy-cancel-sensor")

	// Not yet collected: the command is failed, so the pickup query (which
	// reads only pending commands) never hands it to the sensor.
	job := f.createSensorsJob(t, sensor)
	f.dispatchLegacyJob(t, job.ID)
	if got := f.commandStatuses(t, sensordispatch.CommandType, job.ID); len(got) != 1 || got[0] != "pending" {
		t.Fatalf("command before cancel = %v, want one pending", got)
	}
	if err := f.svc.CancelJob(job.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.commandStatuses(t, sensordispatch.CommandType, job.ID); len(got) != 1 || got[0] != "failed" {
		t.Fatalf("command after cancel = %v, want it failed (withdrawn)", got)
	}
	if got := f.commandStatuses(t, sensordispatch.CancelCommandType, job.ID); len(got) != 0 {
		t.Fatalf("a cancel command was queued for a scan the sensor never collected: %v", got)
	}

	// Already collected: the sensor is told to stop.
	running := f.createSensorsJob(t, sensor)
	f.dispatchLegacyJob(t, running.ID)
	if _, err := f.raw.Exec(`UPDATE sensor_commands SET status = 'delivered', delivered_at = NOW() WHERE payload ->> 'job_id' = $1`, running.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CancelJob(running.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.commandStatuses(t, sensordispatch.CancelCommandType, running.ID); len(got) != 1 || got[0] != "pending" {
		t.Fatalf("cancel commands for a collected legacy scan = %v, want one pending", got)
	}
	var to string
	if err := f.raw.QueryRow(`SELECT sensor_id::text FROM sensor_commands WHERE command_type = $1 AND payload ->> 'job_id' = $2`,
		sensordispatch.CancelCommandType, running.ID).Scan(&to); err != nil || to != sensor.String() {
		t.Fatalf("cancel addressed to %q (%v), want the sensor that collected the scan, %s", to, err, sensor)
	}
}

// Mutation: remove the IsLegacyManualPayload block in dispatchToSensor and the
// excluded target is still handed to the sensor.
func TestIntegration_LegacyDispatch_ReauthorizesAgainstTheScopeAsItIsNow(t *testing.T) {
	f := newDispatchFixture(t)
	sensor := f.liveSensor(t, "legacy-reauth-sensor")

	// One of two targets is excluded after the job was created: it is dropped
	// and named; the other is dispatched.
	job := f.createSensorsJob(t, sensor) // 10.183.0.10 and 10.183.0.11
	f.excludeRange(t, "10.183.0.11/32")
	f.dispatchLegacyJob(t, job.ID)
	var targets string
	if err := f.raw.QueryRow(`SELECT payload ->> 'targets' FROM sensor_commands WHERE payload ->> 'job_id' = $1`, job.ID).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(targets, "10.183.0.10") || strings.Contains(targets, "10.183.0.11") {
		t.Fatalf("dispatched targets = %s, want only the one still authorized", targets)
	}
	got, err := f.svc.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Note, "10.183.0.11") || got.Status != sensordispatch.StatusAwaitingSensor {
		t.Fatalf("job = %s, note %q, want awaiting_sensor with a note naming the dropped target", got.Status, got.Note)
	}
	var dropped string
	if err := f.raw.QueryRow(`SELECT status FROM discovery_targets WHERE job_id = $1 AND input = '10.183.0.11'`, job.ID).Scan(&dropped); err != nil || dropped != "failed" {
		t.Fatalf("dropped target row = %q (%v), want failed", dropped, err)
	}

	// Nothing left authorized: the job fails with the reason and no command exists.
	f.excludeRange(t, "10.99.0.0/24")
	none := f.createSensorsJob(t, sensor)
	f.excludeRange(t, "10.183.0.0/24")
	f.dispatchLegacyJob(t, none.ID)
	status, _, _, errMsg := f.jobRow(t, none.ID)
	if status != "failed" || !strings.Contains(errMsg.String, "10.183.0.10") {
		t.Fatalf("job with no authorized target = %s / %q, want failed naming the targets", status, errMsg.String)
	}
	if n := len(f.commandStatuses(t, sensordispatch.CommandType, none.ID)); n != 0 {
		t.Fatalf("%d command(s) written for a job with no authorized target", n)
	}
}

// Mutation: remove the reauthorizeLegacyRetry call in RequeueJobForRetry and
// the retry of a job whose targets were since excluded is accepted.
func TestIntegration_RetryLegacyJob_IsRefusedWhenItsTargetsAreNoLongerAuthorized(t *testing.T) {
	f := newDispatchFixture(t)
	sensor := f.liveSensor(t, "legacy-retry-sensor")
	job := f.createSensorsJob(t, sensor)
	f.dispatchLegacyJob(t, job.ID)
	reason := "sensor went quiet"
	if err := f.svc.UpdateJobStatus(job.ID, "failed", &reason); err != nil {
		t.Fatal(err)
	}

	f.excludeRange(t, "10.183.0.0/24")
	err := f.svc.RequeueJobForRetry(job.ID)
	var refused *dispatchguard.RefusedTargetsError
	if !errors.As(err, &refused) || !errors.Is(err, dispatchguard.ErrDenied) {
		t.Fatalf("retry err = %v, want a refusal naming the targets", err)
	}
	if status, _, _, _ := f.jobRow(t, job.ID); status != "failed" {
		t.Fatalf("a refused retry left the job %s, want it still failed", status)
	}

	// With the exclusion lifted the same retry is accepted.
	f.excludeRange(t, "10.99.0.0/24")
	if err := f.svc.RequeueJobForRetry(job.ID); err != nil {
		t.Fatalf("retry of an authorized job: %v", err)
	}
	if status, _, _, _ := f.jobRow(t, job.ID); status != "queued" {
		t.Fatalf("job after an accepted retry = %s, want queued", status)
	}
}

// Mutation: delete the note write in the active_scanning branch of
// processDiscoveryJob and the job completes with no explanation.
func TestIntegration_NoActiveScanning_CompletesWithAnHonestNote(t *testing.T) {
	f := newDispatchFixture(t)
	job, err := f.svc.CreateJob(f.tenant.String(), "system", legacyNoScanRequest())
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := f.svc.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Note != "" {
		t.Fatalf("note before the job ran = %q", loaded.Note)
	}
	if err := f.jp.processDiscoveryJob(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	after, err := f.svc.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Note != noActiveScanningNote {
		t.Fatalf("note = %q, want %q", after.Note, noActiveScanningNote)
	}
	jobs, _, err := f.svc.GetJobs(f.tenant.String(), 1, 10, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) == 0 || jobs[0].Note != noActiveScanningNote {
		t.Fatalf("the listing does not carry the note: %+v", jobs)
	}
}

func legacyNoScanRequest() models.CreateDiscoveryJobRequest {
	return models.CreateDiscoveryJobRequest{
		Targets:       []string{"10.184.0.10"},
		ExecutionMode: "cloud",
		Protocols:     []string{"TLS"},
		Ports:         []int{443},
		Options:       map[string]interface{}{"active_scanning": false},
	}
}
