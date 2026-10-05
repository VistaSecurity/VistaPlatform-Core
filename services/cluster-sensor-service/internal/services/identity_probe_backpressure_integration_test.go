package services

// The identity-enrichment probe flood seen on a lab deployment, the cluster-sensor
// half: a sensor whose queue is full refuses an identity probe, and that must
// read as back-pressure — failed with a machine-readable code the producer
// retries on, and no tenant-facing job_failed alert — while every other job's
// busy refusal stays exactly as loud as before. And a duplicate delivery of a
// job that is already with its sensor is a no-op that says so, not a "failed"
// dispatch.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// captureLog collects the standard logger's output for the rest of the test.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		out := buf.String()
		buf.Reset()
		return out
	}
}

type writerFunc func([]byte) (int, error)

func (w writerFunc) Write(p []byte) (int, error) { return w(p) }

func TestIntegration_SensorDispatch_BusyRefusalOfAnIdentityProbeIsBackPressure(t *testing.T) {
	f, _ := lifecycleFixture(t)
	sensorID := f.liveSensor(t, "branch-sensor")

	refuseBusy := func(origin string) string {
		t.Helper()
		job := f.createSensorsJob(t, sensorID)
		// origin is server authority (the handler strips it from any request a
		// person makes), so it is written the way the server writes it.
		if _, err := f.raw.Exec(`UPDATE discovery_jobs SET metadata = jsonb_set(metadata, '{options,origin}', to_jsonb($2::text)) WHERE id = $1`, job.ID, origin); err != nil {
			t.Fatal(err)
		}
		full, err := f.svc.GetJob(job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.jp.dispatchToSensor(full); err != nil {
			t.Fatal(err)
		}
		// The ack a 4.3.1 sensor sends when its queue is full, verbatim.
		if _, err := f.raw.Exec(`UPDATE sensor_commands SET status = 'failed', error_message = 'sensor busy: 8 discovery jobs already queued', delivered_at = NOW(), acknowledged_at = NOW()
			WHERE payload ->> 'job_id' = $1`, job.ID); err != nil {
			t.Fatal(err)
		}
		return job.ID
	}
	probe := refuseBusy("identity_enrichment")
	manual := refuseBusy("manual")

	// Through the sweep's own entry point, so the wiring is what is tested.
	f.jp.sweepStaleDispatches(context.Background())

	read := func(jobID string) (status, code string, msg sql.NullString, alerts int) {
		t.Helper()
		if err := f.raw.QueryRow(`SELECT status, COALESCE(metadata->>$2, ''), error_message FROM discovery_jobs WHERE id = $1`, jobID, sensordispatch.FailureCodeKey).Scan(&status, &code, &msg); err != nil {
			t.Fatal(err)
		}
		if err := f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_alert_history WHERE job_id = $1 AND alert_type = 'job_failed'`, jobID).Scan(&alerts); err != nil {
			t.Fatal(err)
		}
		return
	}

	status, code, msg, alerts := read(probe)
	if status != "failed" || code != sensordispatch.FailureCodeSensorBusy {
		t.Fatalf("identity probe = %s / failure_code %q, want failed / %s — the producer needs the code to send it again instead of blocking the observation", status, code, sensordispatch.FailureCodeSensorBusy)
	}
	if alerts != 0 {
		t.Errorf("identity probe refused for want of room raised %d job_failed alert(s), want 0 — it is retried, nobody has anything to do", alerts)
	}
	if !msg.Valid || !strings.Contains(msg.String, "sensor busy") || !strings.Contains(msg.String, "will send it again") {
		t.Errorf("identity probe error_message = %v, want the sensor's reason and that it will be sent again", msg)
	}

	// The other polarity: a person's scan keeps the loud failure it had. The
	// code is recorded for it too (it is a fact about the refusal), but the
	// alert is the person's. (Any origin but identity_enrichment takes this
	// branch; an auto_scan job cannot be dispatched in this fixture, which has
	// no eligible tenant assets.)
	status, code, _, alerts = read(manual)
	if status != "failed" || code != sensordispatch.FailureCodeSensorBusy {
		t.Errorf("manual job = %s / %q, want failed / %s", status, code, sensordispatch.FailureCodeSensorBusy)
	}
	if alerts != 1 {
		t.Errorf("a person's scan refused busy raised %d job_failed alert(s), want 1 — only identity enrichment's own retries are quiet", alerts)
	}
}

// A refusal that says the JOB is wrong is a real failure even for an identity
// probe: no failure code (so the producer does not resend it) and the alert.
func TestIntegration_SensorDispatch_NonBusyRefusalOfAnIdentityProbeStaysLoud(t *testing.T) {
	f, _ := lifecycleFixture(t)
	sensorID := f.liveSensor(t, "branch-sensor")
	job := f.createSensorsJob(t, sensorID)
	if _, err := f.raw.Exec(`UPDATE discovery_jobs SET metadata = jsonb_set(metadata, '{options,origin}', '"identity_enrichment"') WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	full, _ := f.svc.GetJob(job.ID)
	if err := f.jp.dispatchToSensor(full); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`UPDATE sensor_commands SET status = 'failed', error_message = 'malformed discovery_job payload: targets is empty', delivered_at = NOW(), acknowledged_at = NOW()
		WHERE payload ->> 'job_id' = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	f.jp.sweepStaleDispatches(context.Background())
	var status, code string
	var alerts int
	if err := f.raw.QueryRow(`SELECT status, COALESCE(metadata->>$2, '') FROM discovery_jobs WHERE id = $1`, job.ID, sensordispatch.FailureCodeKey).Scan(&status, &code); err != nil {
		t.Fatal(err)
	}
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_alert_history WHERE job_id = $1 AND alert_type = 'job_failed'`, job.ID).Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || code != "" || alerts != 1 {
		t.Fatalf("malformed identity probe = %s / code %q / %d alert(s), want failed / no code / 1", status, code, alerts)
	}
}

// A second delivery of a job that is already with its sensor — the stuck-job
// sweep's republish, a broker redelivery — is recognised as a duplicate at the
// processor's entry and never reaches the dispatcher, which used to log every
// one as "Dispatch of job … failed".
func TestIntegration_SensorDispatch_DuplicateDeliveryOfADispatchedJobIsANoOp(t *testing.T) {
	f, _ := lifecycleFixture(t)
	sensorID := f.liveSensor(t, "branch-sensor")
	job := f.createSensorsJob(t, sensorID)
	if err := f.jp.handleDiscoveryJob(jobMessage(t, job.ID), &countingLease{}); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	for range 3 {
		if err := f.jp.handleDiscoveryJob(jobMessage(t, job.ID), &countingLease{}); err != nil {
			t.Fatal(err)
		}
	}
	out := logs()
	if strings.Contains(out, "failed") {
		t.Errorf("duplicate deliveries logged a failure:\n%s", out)
	}
	if got := strings.Count(out, "not queued — duplicate or late delivery"); got != 3 {
		t.Errorf("duplicate deliveries recognised at entry = %d, want 3 — they reached the dispatcher:\n%s", got, out)
	}
	status, _, _, _ := f.jobRow(t, job.ID)
	var commands int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_commands WHERE payload ->> 'job_id' = $1`, job.ID).Scan(&commands); err != nil {
		t.Fatal(err)
	}
	if status != sensordispatch.StatusAwaitingSensor || commands != 1 {
		t.Fatalf("after duplicate deliveries: status %s, %d command(s); want %s and exactly 1", status, commands, sensordispatch.StatusAwaitingSensor)
	}
}

// The race the entry check cannot see: two deliveries both read the job as
// queued, and the second's dispatch transaction is the one the guard refuses.
// That is not a failure either, and must neither log as one nor fail the job.
func TestIntegration_SensorDispatch_LosingADispatchRaceIsNotAFailure(t *testing.T) {
	f, _ := lifecycleFixture(t)
	sensorID := f.liveSensor(t, "branch-sensor")
	job := f.createSensorsJob(t, sensorID)
	stale, err := f.svc.GetJob(job.ID) // read while queued, as the loser did
	if err != nil {
		t.Fatal(err)
	}
	winner, _ := f.svc.GetJob(job.ID)
	if err := f.jp.dispatchToSensor(winner); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	if err := f.jp.dispatchToSensor(stale); err != nil {
		t.Fatal(err)
	}
	out := logs()
	if strings.Contains(out, "failed") {
		t.Errorf("the losing delivery logged a failure:\n%s", out)
	}
	if !strings.Contains(out, "dispatched by another delivery") {
		t.Errorf("the losing delivery did not say what happened:\n%s", out)
	}
	status, _, _, _ := f.jobRow(t, job.ID)
	var commands int
	_ = f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_commands WHERE payload ->> 'job_id' = $1`, job.ID).Scan(&commands)
	if status != sensordispatch.StatusAwaitingSensor || commands != 1 {
		t.Fatalf("status %s, %d command(s); want %s and exactly 1", status, commands, sensordispatch.StatusAwaitingSensor)
	}
}

// A job waiting in the stream behind a long scan is queued but not stuck: the
// poll republishes it once, and not again on every tick while nothing has
// touched the row.
func TestIntegration_JobReaper_RepublishDoesNotStackCopiesOfAWaitingJob(t *testing.T) {
	f, _ := reaperFixture(t)
	now := time.Now()
	f.jp.clock = func() time.Time { return now }
	var id string
	if err := f.raw.QueryRow(`
		INSERT INTO discovery_jobs (tenant_id, execution_mode, status, created_at, updated_at)
		VALUES ($1, 'sensors', 'queued', NOW() - interval '8 minutes', NOW() - interval '8 minutes') RETURNING id`, f.tenant).Scan(&id); err != nil {
		t.Fatal(err)
	}
	published := 0
	pass := func() {
		t.Helper()
		if ok := f.jp.stuckJobPass(func(got string) error {
			if got == id {
				published++
			}
			return nil
		}); !ok {
			t.Fatal("stuckJobPass reported a failed read")
		}
	}
	pass()
	if published != 1 {
		t.Fatalf("first pass republished the waiting job %d times, want 1", published)
	}
	// Nine more 30-second ticks, all inside one republishInterval. The old
	// poll republished on every one of them.
	for range 9 {
		now = now.Add(30 * time.Second)
		pass()
	}
	if published != 1 {
		t.Fatalf("the poll republished an untouched waiting job %d times inside %s, want 1", published, republishInterval)
	}
	now = now.Add(republishInterval)
	pass()
	if published != 2 {
		t.Fatalf("after %s the job was republished %d times in all, want 2 — a lost message must still be replaced", republishInterval, published)
	}
}
