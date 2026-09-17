package services

// Tenant-sensor dispatch against a real Postgres: a `sensors` job
// becomes ONE sensor_commands row and a job in awaiting_sensor; creation refuses
// a job that cannot run; the sweep fails — loudly, naming the sensor — a job
// whose command nobody collected; and a `sensors` job routed through the
// processor never touches the in-cluster scan path.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type dispatchFixture struct {
	raw    *sql.DB
	db     *sqlx.DB
	svc    *DiscoveryService
	jp     *JobProcessor
	tenant uuid.UUID
}

func newDispatchFixture(t *testing.T) *dispatchFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	svc := NewDiscoveryService(db, db)
	jp := &JobProcessor{db: db, bypassDB: db, discoveryService: svc, rateLimiter: NewRateLimiter(db)}
	return &dispatchFixture{raw: raw, db: db, svc: svc, jp: jp, tenant: testdb.NewTenant(t, raw)}
}

// insertSensor writes a tenant sensor row. lastBeat nil = never heard from.
func (f *dispatchFixture) insertSensor(t *testing.T, name, status string, lastBeat *time.Time, tags []string, platform string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.raw.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, ip_address, reporting_interval, last_heartbeat)
		VALUES ($1, $2, $3, $4, '1.0.0', 'datacenter_host', $5, $6, '192.0.2.173', 30, $7)`,
		id, f.tenant, name, platform, status, pq.Array(tags), lastBeat); err != nil {
		t.Fatalf("insert sensor %s: %v", name, err)
	}
	return id
}

func (f *dispatchFixture) liveSensor(t *testing.T, name string) uuid.UUID {
	t.Helper()
	beat := time.Now().Add(-20 * time.Second)
	return f.insertSensor(t, name, "active", &beat, nil, "linux")
}

func (f *dispatchFixture) createSensorsJob(t *testing.T, sensorID uuid.UUID) *models.DiscoveryJob {
	t.Helper()
	job, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets:            []string{"192.0.2.10", "192.0.2.11"},
		ExecutionMode:      "sensors",
		PreferredSensorIDs: []string{sensorID.String()},
		Protocols:          []string{"TLS", "SSH"},
		Ports:              []int{443, 22},
		Options:            map[string]interface{}{"active_scan": true},
	})
	if err != nil {
		t.Fatalf("CreateJob(sensors): %v", err)
	}
	return job
}

func (f *dispatchFixture) jobRow(t *testing.T, jobID string) (status string, assigned sql.NullString, dispatched sql.NullTime, errMsg sql.NullString) {
	t.Helper()
	if err := f.raw.QueryRow(`SELECT status, assigned_sensor_id, dispatched_at, error_message FROM discovery_jobs WHERE id = $1`, jobID).
		Scan(&status, &assigned, &dispatched, &errMsg); err != nil {
		t.Fatalf("read job %s: %v", jobID, err)
	}
	return
}

func TestIntegration_SensorDispatch_WritesOneCommandAndMarksTheJobAwaiting(t *testing.T) {
	f := newDispatchFixture(t)
	sensorID := f.liveSensor(t, "xps16-sensor")
	job := f.createSensorsJob(t, sensorID)

	if job.Status != "queued" {
		t.Fatalf("created job status = %q, want queued (dispatch is the processor's job, not creation's)", job.Status)
	}
	full, err := f.svc.GetJob(job.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if full.Executor != "sensor" {
		t.Errorf("executor before dispatch = %q, want sensor — a sensors job is never the platform's", full.Executor)
	}

	if err := f.jp.dispatchToSensor(full); err != nil {
		t.Fatalf("dispatchToSensor: %v", err)
	}

	status, assigned, dispatched, _ := f.jobRow(t, job.ID)
	if status != sensordispatch.StatusAwaitingSensor {
		t.Fatalf("job status = %q, want %s", status, sensordispatch.StatusAwaitingSensor)
	}
	if !assigned.Valid || assigned.String != sensorID.String() {
		t.Errorf("assigned_sensor_id = %v, want %s", assigned, sensorID)
	}
	if !dispatched.Valid {
		t.Error("dispatched_at not stamped")
	}

	var (
		count     int
		cmdStatus string
		payload   []byte
		expires   sql.NullTime
		gotSensor uuid.UUID
	)
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_commands WHERE command_type = $1 AND payload ->> 'job_id' = $2`,
		sensordispatch.CommandType, job.ID).Scan(&count); err != nil {
		t.Fatalf("count commands: %v", err)
	}
	if count != 1 {
		t.Fatalf("sensor_commands rows for the job = %d, want exactly 1", count)
	}
	if err := f.raw.QueryRow(`SELECT sensor_id, status, payload, expires_at FROM sensor_commands WHERE payload ->> 'job_id' = $1`, job.ID).
		Scan(&gotSensor, &cmdStatus, &payload, &expires); err != nil {
		t.Fatalf("read command: %v", err)
	}
	if gotSensor != sensorID || cmdStatus != "pending" {
		t.Errorf("command sensor/status = %s/%s, want %s/pending", gotSensor, cmdStatus, sensorID)
	}
	if !expires.Valid || !expires.Time.After(time.Now()) {
		t.Errorf("expires_at = %v, want a future dispatch deadline", expires)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	parsed, err := sensordispatch.ParsePayload(m)
	if err != nil {
		t.Fatalf("the sensor would refuse the stored payload: %v", err)
	}
	if strings.Join(parsed.Targets, ",") != "192.0.2.10,192.0.2.11" || strings.Join(parsed.Protocols, ",") != "SSH,TLS" ||
		len(parsed.Ports) != 2 || parsed.Ports[0] != 22 || parsed.Ports[1] != 443 {
		t.Errorf("payload = %+v", parsed)
	}
	if parsed.TenantID != f.tenant.String() {
		t.Errorf("payload tenant = %q", parsed.TenantID)
	}

	// The read path reports the executor by name.
	after, err := f.svc.GetJob(job.ID)
	if err != nil {
		t.Fatalf("GetJob after dispatch: %v", err)
	}
	if after.Executor != "sensor" || after.AssignedSensorName == nil || *after.AssignedSensorName != "xps16-sensor" || after.DispatchedAt == nil {
		t.Errorf("GetJob after dispatch = executor %q name %v dispatched %v", after.Executor, after.AssignedSensorName, after.DispatchedAt)
	}
	jobs, _, err := f.svc.GetJobs(f.tenant.String(), 1, 10, "", "", "", "")
	if err != nil {
		t.Fatalf("GetJobs: %v", err)
	}
	var listed *models.DiscoveryJob
	for i := range jobs {
		if jobs[i].ID == job.ID {
			listed = &jobs[i]
		}
	}
	if listed == nil || listed.Executor != "sensor" || listed.AssignedSensorName == nil || listed.Status != sensordispatch.StatusAwaitingSensor {
		t.Errorf("GetJobs lists the job as %+v", listed)
	}

	// Dispatching the same job again must not write a second command.
	if err := f.jp.dispatchToSensor(after); err != nil {
		t.Fatalf("second dispatchToSensor: %v", err)
	}
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_commands WHERE payload ->> 'job_id' = $1`, job.ID).Scan(&count); err != nil {
		t.Fatalf("recount: %v", err)
	}
	if count != 1 {
		t.Errorf("a repeated dispatch wrote %d commands, want 1", count)
	}
	status, _, _, _ = f.jobRow(t, job.ID)
	if status != sensordispatch.StatusAwaitingSensor {
		t.Errorf("a repeated dispatch changed the job to %q", status)
	}
}

func TestIntegration_SensorDispatch_CreationRefusesAJobThatCannotRun(t *testing.T) {
	f := newDispatchFixture(t)
	stale := time.Now().Add(-time.Hour)
	offline := f.insertSensor(t, "branch-sensor", "active", &stale, nil, "linux")
	live := time.Now().Add(-10 * time.Second)
	system := f.insertSensor(t, "Platform Discovery Sensor", "active", &live, []string{"system"}, "platform")

	// A sensor belonging to ANOTHER tenant is unknown to this one.
	other := testdb.NewTenant(t, f.raw)
	foreign := uuid.New()
	if _, err := f.raw.Exec(`
		INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, last_heartbeat)
		VALUES ($1, $2, 'their-sensor', 'linux', '1.0.0', 'datacenter_host', 'active', $3)`, foreign, other, live); err != nil {
		t.Fatalf("insert foreign sensor: %v", err)
	}

	cases := []struct {
		name    string
		sensor  uuid.UUID
		wantErr error
	}{
		{"offline", offline, ErrSensorOffline},
		{"the platform's own", system, ErrSensorDispatchInvalid},
		{"unknown", uuid.New(), ErrSensorNotFound},
		{"another tenant's", foreign, ErrSensorNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
				Targets:            []string{"192.0.2.10"},
				ExecutionMode:      "sensors",
				PreferredSensorIDs: []string{tc.sensor.String()},
				Protocols:          []string{"TLS"},
				Ports:              []int{443},
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CreateJob = %v, want %v", err, tc.wantErr)
			}
		})
	}

	var jobs int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_jobs WHERE tenant_id = $1`, f.tenant).Scan(&jobs); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if jobs != 0 {
		t.Fatalf("%d job row(s) written for refused requests — a refused job must leave nothing behind", jobs)
	}
}

// The sensor went offline between creation and dispatch. The job must FAIL
// with the reason, not sit in awaiting_sensor behind a command nobody will
// collect, and not run in-cluster.
func TestIntegration_SensorDispatch_SensorGoneOfflineFailsLoudly(t *testing.T) {
	f := newDispatchFixture(t)
	sensorID := f.liveSensor(t, "xps16-sensor")
	job := f.createSensorsJob(t, sensorID)

	if _, err := f.raw.Exec(`UPDATE sensors SET last_heartbeat = NOW() - interval '1 hour' WHERE id = $1`, sensorID); err != nil {
		t.Fatalf("age the sensor: %v", err)
	}
	full, _ := f.svc.GetJob(job.ID)
	if err := f.jp.dispatchToSensor(full); err != nil {
		t.Fatalf("dispatchToSensor: %v", err)
	}
	status, _, _, errMsg := f.jobRow(t, job.ID)
	if status != "failed" {
		t.Fatalf("job status = %q, want failed", status)
	}
	if !errMsg.Valid || !strings.Contains(errMsg.String, "xps16-sensor") || !strings.Contains(errMsg.String, "nothing was scanned") {
		t.Errorf("error_message = %v, want it to name the sensor and say nothing was scanned", errMsg)
	}
	var count int
	_ = f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_commands WHERE payload ->> 'job_id' = $1`, job.ID).Scan(&count)
	if count != 0 {
		t.Errorf("%d command(s) written for a sensor that is offline", count)
	}
}

func TestIntegration_SensorDispatch_ExpirySweepFailsTheUncollectedJob(t *testing.T) {
	f := newDispatchFixture(t)
	sensorID := f.liveSensor(t, "xps16-sensor")
	job := f.createSensorsJob(t, sensorID)
	full, _ := f.svc.GetJob(job.ID)
	if err := f.jp.dispatchToSensor(full); err != nil {
		t.Fatalf("dispatchToSensor: %v", err)
	}

	// Not yet expired: the sweep leaves it alone.
	f.jp.sweepStaleDispatches(context.Background())
	if status, _, _, _ := f.jobRow(t, job.ID); status != sensordispatch.StatusAwaitingSensor {
		t.Fatalf("sweep touched an unexpired dispatch: status = %q", status)
	}

	// The command's deadline passes with the sensor silent.
	if _, err := f.raw.Exec(`UPDATE sensor_commands SET expires_at = NOW() - interval '1 minute' WHERE payload ->> 'job_id' = $1`, job.ID); err != nil {
		t.Fatalf("expire command: %v", err)
	}
	if _, err := f.raw.Exec(`UPDATE sensors SET last_heartbeat = NOW() - interval '30 minutes' WHERE id = $1`, sensorID); err != nil {
		t.Fatalf("age the sensor: %v", err)
	}
	f.jp.sweepStaleDispatches(context.Background())

	status, _, _, errMsg := f.jobRow(t, job.ID)
	if status != "failed" {
		t.Fatalf("job status after sweep = %q, want failed", status)
	}
	for _, want := range []string{"xps16-sensor", "offline", "nothing was scanned", "last heartbeat"} {
		if !errMsg.Valid || !strings.Contains(errMsg.String, want) {
			t.Errorf("error_message %v lacks %q", errMsg, want)
		}
	}
	var cmdStatus string
	if err := f.raw.QueryRow(`SELECT status FROM sensor_commands WHERE payload ->> 'job_id' = $1`, job.ID).Scan(&cmdStatus); err != nil {
		t.Fatalf("read command: %v", err)
	}
	if cmdStatus != "failed" {
		t.Errorf("command status = %q, want failed — a late heartbeat must not collect a job the platform declared dead", cmdStatus)
	}
	// And the read path shows the failure beside the sensor's last heartbeat.
	after, _ := f.svc.GetJob(job.ID)
	if after.AssignedSensorLastHeartbeat == nil {
		t.Error("GetJob does not carry the assigned sensor's last heartbeat for a sensor-offline failure")
	}
}

// A command the sensor REFUSED (its ack marked the command failed) fails the
// job with the sensor's reason.
func TestIntegration_SensorDispatch_RefusedCommandFailsTheJob(t *testing.T) {
	f := newDispatchFixture(t)
	sensorID := f.liveSensor(t, "xps16-sensor")
	job := f.createSensorsJob(t, sensorID)
	full, _ := f.svc.GetJob(job.ID)
	if err := f.jp.dispatchToSensor(full); err != nil {
		t.Fatalf("dispatchToSensor: %v", err)
	}
	if _, err := f.raw.Exec(`UPDATE sensor_commands SET status = 'failed', error_message = 'malformed discovery_job payload: targets is empty', delivered_at = NOW(), acknowledged_at = NOW()
		WHERE payload ->> 'job_id' = $1`, job.ID); err != nil {
		t.Fatalf("refuse command: %v", err)
	}
	f.jp.sweepStaleDispatches(context.Background())
	status, _, _, errMsg := f.jobRow(t, job.ID)
	if status != "failed" || !errMsg.Valid || !strings.Contains(errMsg.String, "refused") || !strings.Contains(errMsg.String, "targets is empty") {
		t.Fatalf("job = %q / %v, want failed with the sensor's refusal", status, errMsg)
	}
}

// The guard the whole feature stands on: a `sensors` job driven through the
// processor's entry point is DISPATCHED, and never runs the in-cluster scan.
// Delete the routing in processDiscoveryJobByID and this goes red: the job
// would be marked running, reach processDiscoveryJob's last-line guard and
// end `failed` — or, with that guard gone too, run nmap from the cluster and
// end `completed` with no findings.
func TestIntegration_SensorDispatch_ProcessorNeverRunsASensorsJobInCluster(t *testing.T) {
	f := newDispatchFixture(t)
	sensorID := f.liveSensor(t, "xps16-sensor")
	job := f.createSensorsJob(t, sensorID)

	if err := f.jp.processDiscoveryJobByID(job.ID); err != nil {
		t.Fatalf("processDiscoveryJobByID: %v", err)
	}
	status, assigned, _, errMsg := f.jobRow(t, job.ID)
	if status != sensordispatch.StatusAwaitingSensor {
		t.Fatalf("status = %q (error %v), want %s — the processor ran or failed a job that belongs to the sensor",
			status, errMsg, sensordispatch.StatusAwaitingSensor)
	}
	if !assigned.Valid || assigned.String != sensorID.String() {
		t.Errorf("assigned_sensor_id = %v, want %s", assigned, sensorID)
	}
	var findings, targetsRunning int
	_ = f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1`, job.ID).Scan(&findings)
	_ = f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_targets WHERE job_id = $1 AND status <> 'pending'`, job.ID).Scan(&targetsRunning)
	if findings != 0 || targetsRunning != 0 {
		t.Errorf("in-cluster scan activity for a sensors job: findings=%d targets touched=%d", findings, targetsRunning)
	}
}
