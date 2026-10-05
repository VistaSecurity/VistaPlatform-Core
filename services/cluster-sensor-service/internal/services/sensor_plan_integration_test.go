package services

// A scan-plan job run by a TENANT sensor ( WP2b), end to end against a
// real Postgres: the platform creates and authorizes the units and dispatches
// the plan; the REAL sensor-side executor (shared/sensordispatch/planrun) runs
// it on a FakeNet (nothing leaves loopback) and reports each host through the
// REAL intake sensor-manager serves (shared/jobunits.RecordSensorBatch); and
// the job's coverage, findings and inventory queue then come out of the same
// readers as a platform run's — compared field by field with a platform run of
// the same hosts. Plus the progress lease, cancel (by report answer and by
// command), and a Retry that scans only what is left.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch/planrun"
)

// dbReporter is the sensor's reporter wired straight to the platform's intake.
type dbReporter struct {
	db                  *sql.DB
	tenant, sensor, job uuid.UUID
	mu                  sync.Mutex
	responses           []sensordispatch.UnitBatchResponse
	last                []sensordispatch.UnitResult
	before              func(units []sensordispatch.UnitResult)
	after               func(units []sensordispatch.UnitResult)
	// firstStopOnPing: the first "stop" answer came to an empty report.
	firstStopOnPing *bool
}

func (r *dbReporter) Report(ctx context.Context, units []sensordispatch.UnitResult) error {
	if r.before != nil {
		r.before(units)
	}
	resp, err := jobunits.RecordSensorBatch(ctx, r.db, r.tenant, r.sensor, r.job, sensordispatch.UnitBatch{Units: units})
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.responses = append(r.responses, resp)
	if len(units) > 0 {
		r.last = units
	}
	if resp.Stop() && r.firstStopOnPing == nil {
		onPing := len(units) == 0
		r.firstStopOnPing = &onPing
	}
	r.mu.Unlock()
	if r.after != nil && !resp.Stop() {
		r.after(units)
	}
	if resp.Stop() {
		return fmt.Errorf("%w: %s", planrun.ErrJobStopped, resp.Code)
	}
	return nil
}

// capableSensor is a live tenant sensor whose software runs planned scans.
func (f *dispatchFixture) capableSensor(t *testing.T, name string) uuid.UUID {
	t.Helper()
	id := f.liveSensor(t, name)
	if _, err := f.raw.Exec(`UPDATE sensors SET reported_capabilities = $2 WHERE id = $1`, id, pq.Array([]string{sensordispatch.ScanPlanCapability})); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *dispatchFixture) createSensorPlanJob(t *testing.T, sensor uuid.UUID, tcp string, targets ...string) string {
	t.Helper()
	job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: targets, ScanDepth: "custom", TCPPorts: tcp, RunFrom: "sensor", SensorID: sensor.String(),
	})
	if err != nil {
		t.Fatalf("CreateJob(run_from sensor): %v", err)
	}
	return job.ID
}

// dispatchPlan runs the dispatcher for jobID and returns the command it wrote,
// as the sensor parses it, marking it collected.
func (f *dispatchFixture) dispatchPlan(t *testing.T, jobID string) (sensordispatch.Payload, string) {
	t.Helper()
	job, err := f.svc.GetJob(jobID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.dispatchToSensor(job); err != nil {
		t.Fatalf("dispatchToSensor: %v", err)
	}
	var (
		cmdID string
		raw   []byte
	)
	if err := f.raw.QueryRow(`SELECT id, payload FROM sensor_commands WHERE command_type = $1 AND payload ->> 'job_id' = $2 ORDER BY created_at DESC LIMIT 1`,
		sensordispatch.CommandType, jobID).Scan(&cmdID, &raw); err != nil {
		t.Fatalf("no command for %s: %v (job %s)", jobID, err, f.jobStatus(t, jobID))
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	payload, err := sensordispatch.ParsePayload(m)
	if err != nil || payload.Plan == nil {
		t.Fatalf("the sensor would refuse the stored payload: %+v %v", payload, err)
	}
	if _, err := f.raw.Exec(`UPDATE sensor_commands SET status = 'delivered', delivered_at = NOW() WHERE id = $1`, cmdID); err != nil {
		t.Fatal(err)
	}
	return payload, cmdID
}

// runOnSensor is the sensor's executor, with the sensor's own address rule
// over a scope that owns private space.
func runOnSensor(ctx context.Context, plan sensordispatch.PlanPayload, rep planrun.Reporter, fake *FakeNet) (planrun.Summary, error) {
	return planrun.Run(ctx, plan, planrun.Config{
		Allow:    planrun.SensorRule(func() probeconsent.Scope { return probeconsent.Scope{} }),
		Reporter: rep, Dialer: fake, ReportBackoff: 10 * time.Millisecond,
	})
}

type findingKey struct {
	Protocol string
	Port     int
	IP       string
}

func (f *dispatchFixture) findingKeys(t *testing.T, jobID string) []findingKey {
	t.Helper()
	rows, err := f.raw.Query(`SELECT protocol, port, host(resolved_ip) FROM discovery_findings WHERE job_id = $1`, jobID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []findingKey
	for rows.Next() {
		var k findingKey
		if err := rows.Scan(&k.Protocol, &k.Port, &k.IP); err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
	return out
}

func (f *dispatchFixture) mirrored(t *testing.T, jobID string, sensor string) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_discoveries WHERE batch_id = $1 AND sensor_id::text = $2`, jobID, sensor).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The same hosts, run once by the platform and once by a tenant sensor, come
// out the same: coverage, findings, the inventory queue. A re-sent report
// stores nothing twice.
func TestIntegration_SensorPlan_EndToEndMatchesAPlatformRun(t *testing.T) {
	f, fake := newUnitFixture(t)
	sixHosts(t, fake)
	const targets, tcp = "10.183.8.8/29", "20-30"

	// The platform's run.
	platformJob := f.createPlanJob(t, tcp, targets)
	if err := f.jp.handleDiscoveryJob(jobMessage(t, platformJob), &countingLease{}); err != nil {
		t.Fatal(err)
	}
	if s := f.jobStatus(t, platformJob); s != "completed" {
		t.Fatalf("platform run = %s", s)
	}

	// The sensor's.
	sensor := f.capableSensor(t, "edge-01")
	jobID := f.createSensorPlanJob(t, sensor, tcp, targets)
	payload, _ := f.dispatchPlan(t, jobID)
	if p := payload.Plan; p.Attempt != 1 || len(p.Targets) != 1 || p.Targets[0].Target != targets || p.Targets[0].TCPPorts != tcp || len(p.Targets[0].SkipAddresses) != 0 {
		t.Fatalf("plan = %+v", p)
	}
	rep := &dbReporter{db: f.raw, tenant: f.tenant, sensor: sensor, job: uuid.MustParse(jobID)}
	sum, err := runOnSensor(context.Background(), *payload.Plan, rep, NewFakeNetLike(t, fake))
	if err != nil || sum.Units != 8 || sum.Done != 8 {
		t.Fatalf("sensor run = %+v %v", sum, err)
	}
	if s := f.jobStatus(t, jobID); s != sensordispatch.StatusAwaitingSensor {
		t.Fatalf("job while the sensor reports = %s", s)
	}

	pc, pp, ok, err := f.svc.JobUnitCoverage(f.tenant.String(), platformJob, "completed", "platform")
	if err != nil || !ok {
		t.Fatal(err)
	}
	sc, sp, ok, err := f.svc.JobUnitCoverage(f.tenant.String(), jobID, "completed", "sensor")
	if err != nil || !ok {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pc, sc) || pp != sp || sp != 100 {
		t.Fatalf("coverage differs:\n platform %+v (%d%%)\n sensor   %+v (%d%%)", pc, pp, sc, sp)
	}
	if sc.HostsTotal != 8 || sc.HostsResponded != 6 || sc.HostsNoAnswer != 2 {
		t.Fatalf("coverage = %+v, want 8 hosts, 6 responded, 2 no answer", sc)
	}
	pf, sf := f.findingKeys(t, platformJob), f.findingKeys(t, jobID)
	if len(sf) == 0 || !reflect.DeepEqual(pf, sf) {
		t.Fatalf("findings differ: platform %v sensor %v", pf, sf)
	}
	if n := f.mirrored(t, jobID, sensor.String()); n != len(sf) {
		t.Fatalf("%d finding(s) queued for inventory under the sensor, want %d", n, len(sf))
	}

	// The same report again (a retry after a lost answer): nothing new.
	before := len(f.findingKeys(t, jobID))
	resp, err := jobunits.RecordSensorBatch(context.Background(), f.raw, f.tenant, sensor, uuid.MustParse(jobID), sensordispatch.UnitBatch{Units: rep.last})
	if err != nil || resp.Duplicate != len(rep.last) || resp.Accepted != 0 {
		t.Fatalf("re-sent batch = %+v %v, want all duplicate", resp, err)
	}
	if after := len(f.findingKeys(t, jobID)); after != before || f.mirrored(t, jobID, sensor.String()) != before {
		t.Fatalf("a re-sent batch stored again: findings %d → %d", before, after)
	}
}

// NewFakeNetLike returns a FakeNet with the same hosts as src, so two runs
// see the same network without sharing dial records.
func NewFakeNetLike(t *testing.T, src *FakeNet) *FakeNet {
	t.Helper()
	n := NewFakeNet()
	src.mu.Lock()
	defer src.mu.Unlock()
	for a, h := range src.hosts {
		n.hosts[a] = h
	}
	return n
}

// The lease, not a deadline: a job whose sensor keeps reporting stays alive
// long past the old two-hour kill; one whose sensor goes quiet for the lease
// is failed with a reason, its finished hosts kept. A protocols × ports job
// keeps the two-hour rule.
func TestIntegration_SensorPlan_ProgressLeaseReplacesTheFixedTimeout(t *testing.T) {
	f, fake := newUnitFixture(t)
	f.jp.sweepTenant = f.tenant.String()
	sixHosts(t, fake)
	sensor := f.capableSensor(t, "edge-02")
	jobID := f.createSensorPlanJob(t, sensor, "20-30", "10.183.8.10", "10.183.8.11")
	payload, cmdID := f.dispatchPlan(t, jobID)
	// Collected three hours ago: past ExecutionTimeout.
	if _, err := f.raw.Exec(`UPDATE sensor_commands SET delivered_at = NOW() - INTERVAL '3 hours' WHERE id = $1`, cmdID); err != nil {
		t.Fatal(err)
	}
	old := planProgressLease
	planProgressLease = 300 * time.Millisecond
	t.Cleanup(func() { planProgressLease = old })
	// Longer than the (test) lease since the dispatch: only the report below
	// keeps the job alive.
	time.Sleep(400 * time.Millisecond)
	rep := &dbReporter{db: f.raw, tenant: f.tenant, sensor: sensor, job: uuid.MustParse(jobID)}
	one := *payload.Plan
	one.Targets = one.Targets[:1]
	if sum, err := runOnSensor(context.Background(), one, rep, fake); err != nil || sum.Done != 1 {
		t.Fatalf("run = %+v %v", sum, err)
	}
	f.jp.sweepStaleDispatches(context.Background())
	if s := f.jobStatus(t, jobID); s != sensordispatch.StatusAwaitingSensor {
		t.Fatalf("a job reporting progress was failed, three hours after pickup: %s", s)
	}

	// Then silence for the lease.
	time.Sleep(500 * time.Millisecond)
	f.jp.sweepStaleDispatches(context.Background())
	status, _, _, errMsg := f.jobRow(t, jobID)
	if status != "failed" || !strings.Contains(errMsg.String, "edge-02 stopped reporting progress") || !strings.Contains(errMsg.String, "retry to scan the rest") {
		t.Fatalf("silent job = %s / %q", status, errMsg.String)
	}
	st := f.unitStatuses(t, jobID)
	if st["10.183.8.10"] != unitDone || st["10.183.8.11"] != unitPending {
		t.Fatalf("units after the lease = %v, want the finished host kept and the other left to retry", st)
	}
	// A late report of the failed job is told to stop and stores nothing.
	resp, err := jobunits.RecordSensorBatch(context.Background(), f.raw, f.tenant, sensor, uuid.MustParse(jobID), sensordispatch.UnitBatch{})
	if err != nil || resp.Code != sensordispatch.UnitsCodeJobEnded {
		t.Fatalf("late ping = %+v %v, want %s", resp, err, sensordispatch.UnitsCodeJobEnded)
	}

	// The legacy job collected three hours ago still fails on the old rule.
	// Only a sensor without plan support is sent one ( D3, WP5).
	legacy := f.createSensorsJob(t, f.liveSensor(t, "edge-old"))
	if legacy.Plan != nil {
		t.Fatal("the job for a sensor without plan support was planned")
	}
	full, _ := f.svc.GetJob(legacy.ID)
	if err := f.jp.dispatchToSensor(full); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`UPDATE sensor_commands SET status = 'delivered', delivered_at = NOW() - INTERVAL '3 hours' WHERE payload ->> 'job_id' = $1`, legacy.ID); err != nil {
		t.Fatal(err)
	}
	f.jp.sweepStaleDispatches(context.Background())
	if _, _, _, msg := f.jobRow(t, legacy.ID); !strings.Contains(msg.String, "never reported completion within 2h0m0s") {
		t.Fatalf("legacy job = %q, want the 2h rule", msg.String)
	}
}

// Cancel mid-run: the sensor's next report is answered "cancelled", it stops
// at once, nothing more is stored, the job stays cancelled — and a
// cancel_discovery_job command is queued for a sensor that is between reports.
func TestIntegration_SensorPlan_CancelStopsTheSensor(t *testing.T) {
	f, fake := newUnitFixture(t)
	sixHosts(t, fake)
	sensor := f.capableSensor(t, "edge-03")
	jobID := f.createSensorPlanJob(t, sensor, "20-30", "10.183.8.10-10.183.8.15")
	payload, _ := f.dispatchPlan(t, jobID)

	// .10 answers at once; the other hosts' port scans hang until the run
	// stops, so they are in flight when the cancel lands.
	holdHosts(fake, "10.183.8.11", "10.183.8.12", "10.183.8.13", "10.183.8.14", "10.183.8.15")
	var once sync.Once
	rep := &dbReporter{db: f.raw, tenant: f.tenant, sensor: sensor, job: uuid.MustParse(jobID)}
	rep.after = func(units []sensordispatch.UnitResult) {
		if len(units) > 0 {
			// A person cancels once the first host is stored.
			once.Do(func() {
				if err := f.svc.CancelJob(jobID); err != nil {
					t.Errorf("CancelJob: %v", err)
				}
			})
		}
	}
	start := time.Now()
	sum, err := planrun.Run(context.Background(), *payload.Plan, planrun.Config{
		Allow:    planrun.SensorRule(func() probeconsent.Scope { return probeconsent.Scope{} }),
		Reporter: rep, Dialer: fake, PingInterval: 50 * time.Millisecond,
	})
	if !errors.Is(err, planrun.ErrJobStopped) {
		t.Fatalf("run = %+v %v, want stopped", sum, err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the sensor took %s to stop", d)
	}
	// The hosts in flight were still scanning: the sensor learned of the
	// cancel from its progress ping, not from a host it finished.
	if rep.firstStopOnPing == nil || !*rep.firstStopOnPing {
		t.Fatalf("the stop answer did not come to a ping (%v): a sensor between reports would not stop", rep.firstStopOnPing)
	}
	if s := f.jobStatus(t, jobID); s != "cancelled" {
		t.Fatalf("job = %s, want cancelled", s)
	}
	var done int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_job_units WHERE job_id = $1 AND status = 'done'`, jobID).Scan(&done); err != nil {
		t.Fatal(err)
	}
	if done != 1 {
		t.Fatalf("%d host(s) stored done, want only the one before the cancel", done)
	}
	var cancels int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_commands WHERE sensor_id = $1 AND command_type = $2 AND payload ->> 'job_id' = $3 AND status = 'pending'`,
		sensor, sensordispatch.CancelCommandType, jobID).Scan(&cancels); err != nil {
		t.Fatal(err)
	}
	if cancels != 1 {
		t.Fatalf("cancel commands = %d, want 1 for a sensor between reports", cancels)
	}

	// Cancelled before the sensor collected it: the command is withdrawn.
	other := f.createSensorPlanJob(t, sensor, "20-30", "10.183.8.12")
	job, _ := f.svc.GetJob(other)
	if err := f.jp.dispatchToSensor(job); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CancelJob(other); err != nil {
		t.Fatal(err)
	}
	var cmdStatus string
	if err := f.raw.QueryRow(`SELECT status FROM sensor_commands WHERE command_type = $1 AND payload ->> 'job_id' = $2`, sensordispatch.CommandType, other).Scan(&cmdStatus); err != nil {
		t.Fatal(err)
	}
	if cmdStatus != "failed" {
		t.Fatalf("uncollected command after cancel = %s, want withdrawn (failed)", cmdStatus)
	}
}

// A sensor lost mid-scan, the job failed by the lease, a person's Retry:
// the second dispatch hands over only the hosts not done (attempt 2), the
// sensor scans only those, and a straggler report from attempt 1 is refused.
func TestIntegration_SensorPlan_RetryScansOnlyTheUnfinishedHosts(t *testing.T) {
	f, fake := newUnitFixture(t)
	f.jp.sweepTenant = f.tenant.String()
	sixHosts(t, fake)
	sensor := f.capableSensor(t, "edge-04")
	jobID := f.createSensorPlanJob(t, sensor, "20-30", "10.183.8.10-10.183.8.15")
	first, _ := f.dispatchPlan(t, jobID)

	// The sensor delivers two hosts, then the network to the platform dies.
	delivered := 0
	rep := &dbReporter{db: f.raw, tenant: f.tenant, sensor: sensor, job: uuid.MustParse(jobID)}
	cut := &cutReporter{inner: rep, allow: 2, delivered: &delivered}
	plan := *first.Plan
	if _, err := planrun.Run(context.Background(), plan, planrun.Config{
		Allow:    planrun.SensorRule(func() probeconsent.Scope { return probeconsent.Scope{} }),
		Reporter: cut, Dialer: fake, ReportAttempts: 1, ReportBackoff: time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	stale := cut.lost[0]

	old := planProgressLease
	planProgressLease = 200 * time.Millisecond
	t.Cleanup(func() { planProgressLease = old })
	time.Sleep(400 * time.Millisecond)
	f.jp.sweepStaleDispatches(context.Background())
	if s := f.jobStatus(t, jobID); s != "failed" {
		t.Fatalf("job = %s, want failed by the lease", s)
	}
	planProgressLease = old

	if err := f.svc.RequeueJobForRetry(jobID); err != nil {
		t.Fatal(err)
	}
	second, _ := f.dispatchPlan(t, jobID)
	if second.Plan.Attempt != 2 || len(second.Plan.Targets[0].SkipAddresses) != 2 {
		t.Fatalf("retry plan = attempt %d skip %v, want attempt 2 skipping the two finished hosts", second.Plan.Attempt, second.Plan.Targets[0].SkipAddresses)
	}
	fake2 := NewFakeNetLike(t, fake)
	rep2 := &dbReporter{db: f.raw, tenant: f.tenant, sensor: sensor, job: uuid.MustParse(jobID)}
	sum, err := runOnSensor(context.Background(), *second.Plan, rep2, fake2)
	if err != nil || sum.Units != 4 || sum.Done != 4 {
		t.Fatalf("retry run = %+v %v, want the four unfinished hosts", sum, err)
	}
	for _, skipped := range second.Plan.Targets[0].SkipAddresses {
		if n := fake2.DialedAddrs()[skipped]; n != 0 {
			t.Errorf("the retry rescanned the finished host %s", skipped)
		}
	}
	// The straggler of attempt 1, arriving now, is stale.
	resp, err := jobunits.RecordSensorBatch(context.Background(), f.raw, f.tenant, sensor, uuid.MustParse(jobID), sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{stale}})
	if err != nil || resp.Stale != 1 || resp.Accepted != 0 {
		t.Fatalf("attempt-1 straggler = %+v %v, want stale", resp, err)
	}
	if st := f.unitStatuses(t, jobID); countStatus(st, unitDone) != 6 {
		t.Fatalf("units = %v, want all six done", st)
	}
}

// cutReporter delivers `allow` host reports, then loses the rest (pings too).
type cutReporter struct {
	inner     *dbReporter
	allow     int
	delivered *int
	mu        sync.Mutex
	lost      []sensordispatch.UnitResult
}

func (c *cutReporter) Report(ctx context.Context, units []sensordispatch.UnitResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(units) > 0 && *c.delivered < c.allow {
		*c.delivered += len(units)
		return c.inner.Report(ctx, units)
	}
	c.lost = append(c.lost, units...)
	return errors.New("connection reset")
}
