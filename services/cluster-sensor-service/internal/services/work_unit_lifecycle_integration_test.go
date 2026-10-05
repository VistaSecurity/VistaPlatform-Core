package services

// A scan-plan job's units through the job lifecycle of/ (
// WP2): cancel, shutdown hand-back and resume, a crash reaped then retried,
// the attempt fence that keeps a unit's findings single, the per-address
// authorization re-checked at run time, and RLS on the new table. Driven
// through the real processor paths with a FakeNet as the engine's only network
// (nothing leaves loopback), so deleting the line that closes each hole turns
// a test here red.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// planFixture is a dispatch fixture whose processor runs scan-plan jobs on a
// FakeNet, with a live processor context (so Stop works) and the tenant's
// Platform Discovery Sensor (so findings are queued for inventory).
func newUnitFixture(t *testing.T) (*dispatchFixture, *FakeNet) {
	t.Helper()
	// lifecycleFixture seeds the platform sensor findings are mirrored under;
	// this fixture replaces its gated network with a plain FakeNet.
	f, _ := lifecycleFixture(t)
	fake := NewFakeNet()
	f.net = nil
	f.jp.planEngineOptions = []shareddisc.Option{shareddisc.WithDialer(fake)}
	f.jp.ctx, f.jp.cancel = context.WithCancelCause(context.Background())
	return f, fake
}

// replica is another processor over the same database, as a second pod.
func (f *dispatchFixture) replica(fake *FakeNet) *JobProcessor {
	jp := &JobProcessor{db: f.db, bypassDB: f.db, discoveryService: f.svc, rateLimiter: f.jp.rateLimiter,
		alertService: f.jp.alertService, planEngineOptions: []shareddisc.Option{shareddisc.WithDialer(fake)}}
	jp.ctx, jp.cancel = context.WithCancelCause(context.Background())
	return jp
}

func (f *dispatchFixture) createPlanJob(t *testing.T, tcp string, targets ...string) string {
	t.Helper()
	job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: targets, ScanDepth: "custom", TCPPorts: tcp, RunFrom: "platform",
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	return job.ID
}

func (f *dispatchFixture) unitStatuses(t *testing.T, jobID string) map[string]string {
	t.Helper()
	rows, err := f.raw.Query(`SELECT address, status FROM discovery_job_units WHERE job_id = $1`, jobID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var a, s string
		if err := rows.Scan(&a, &s); err != nil {
			t.Fatal(err)
		}
		out[a] = s
	}
	return out
}

// holdHosts makes every port-scan connect (not a liveness probe) to the given
// hosts wait until ctx ends — the connect timeout, or the job — so those units
// are reliably in flight when a test acts. host .10 is never held.
func holdHosts(fake *FakeNet, hosts ...string) {
	held := map[string]bool{}
	for _, h := range hosts {
		held[h] = true
	}
	liveness := shareddisc.DefaultLivenessPorts()
	fake.OnDial = func(ctx context.Context, network string, ap netip.AddrPort) {
		if network == "tcp" && held[ap.Addr().String()] && !liveness.Contains(int(ap.Port())) {
			<-ctx.Done()
		}
	}
}

// waitUnits polls until cond holds over the job's unit statuses.
func (f *dispatchFixture) waitUnits(t *testing.T, jobID string, what string, cond func(map[string]string) bool) map[string]string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		st := f.unitStatuses(t, jobID)
		if cond(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("units never reached %q: %v", what, st)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func countStatus(st map[string]string, status string) int {
	n := 0
	for _, s := range st {
		if s == status {
			n++
		}
	}
	return n
}

// sixHosts registers 10.183.8.10-15 as up; .10 also has an SMTP listener, so
// its unit produces one finding.
func sixHosts(t *testing.T, fake *FakeNet) {
	fake.Host("10.183.8.10", map[uint16]string{25: ServeBanner(t, "220 mx.example.test ESMTP\r\n")}, nil)
	for _, h := range []string{"10.183.8.11", "10.183.8.12", "10.183.8.13", "10.183.8.14", "10.183.8.15"} {
		fake.Host(h, nil, nil)
	}
}

// Cancel mid-run: the units in flight stop and are cancelled, the units not
// reached are cancelled, the finished unit keeps its finding, the job ends
// cancelled — promptly — and the late "completed" never lands.
func TestIntegration_PlanUnits_CancelStopsWorkersAndKeepsFinishedUnits(t *testing.T) {
	f, fake := newUnitFixture(t)
	sixHosts(t, fake)
	holdHosts(fake, "10.183.8.11", "10.183.8.12", "10.183.8.13", "10.183.8.14", "10.183.8.15")
	jobID := f.createPlanJob(t, "1-300", "10.183.8.10-10.183.8.15")

	done := make(chan error, 1)
	go func() { done <- f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}) }()
	f.waitUnits(t, jobID, ".10 done and others running", func(st map[string]string) bool {
		return st["10.183.8.10"] == unitDone && countStatus(st, unitRunning) > 0
	})

	if err := f.svc.CancelJob(jobID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	if err := waitErr(t, done, 5*time.Second, "the processor after a cancel"); err != nil {
		t.Fatalf("processing returned %v", err)
	}
	st := f.unitStatuses(t, jobID)
	if st["10.183.8.10"] != unitDone || countStatus(st, unitCancelled) != 5 {
		t.Fatalf("units after cancel = %v, want .10 done and the other five cancelled", st)
	}
	if s := f.jobStatus(t, jobID); s != "cancelled" {
		t.Fatalf("job = %s, want cancelled", s)
	}
	if n := f.findingCount(t, jobID); n != 1 {
		t.Fatalf("findings = %d, want .10's one finding kept", n)
	}
	cov, progress, ok, err := f.svc.JobUnitCoverage(f.tenant.String(), jobID, "cancelled", "platform")
	if err != nil || !ok {
		t.Fatalf("coverage: ok=%v err=%v", ok, err)
	}
	if progress != 16 || cov.HostsCancelled != 5 || cov.HostsResponded != 1 {
		t.Errorf("progress %d coverage %+v, want 16%% with 5 hosts cancelled", progress, cov)
	}
	if !strings.Contains(strings.Join(cov.Warnings, "|"), "stopped at 1 of 6 hosts") {
		t.Errorf("warnings = %q, want the partial-scan note", cov.Warnings)
	}
}

// Shutdown mid-run hands the job back: units in flight return to pending,
// the finished unit stays done, and the next run — on another replica —
// resumes without contacting the finished host again or storing its finding
// twice.
func TestIntegration_PlanUnits_HandBackOnStopResumesUnfinishedUnits(t *testing.T) {
	f, fake := newUnitFixture(t)
	sixHosts(t, fake)
	holdHosts(fake, "10.183.8.11", "10.183.8.12", "10.183.8.13", "10.183.8.14", "10.183.8.15")
	jobID := f.createPlanJob(t, "1-300", "10.183.8.10-10.183.8.15")

	done := make(chan error, 1)
	go func() { done <- f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}) }()
	f.waitUnits(t, jobID, ".10 done and others running", func(st map[string]string) bool {
		return st["10.183.8.10"] == unitDone && countStatus(st, unitRunning) > 0
	})
	f.jp.Stop()
	if err := waitErr(t, done, 5*time.Second, "the processor after Stop"); err != nil {
		t.Fatalf("processing returned %v", err)
	}
	if s := f.jobStatus(t, jobID); s != "queued" {
		t.Fatalf("job after Stop = %s, want queued (handed back)", s)
	}
	st := f.unitStatuses(t, jobID)
	if st["10.183.8.10"] != unitDone || countStatus(st, unitPending) != 5 {
		t.Fatalf("units after Stop = %v, want .10 done and five pending", st)
	}

	fake2 := NewFakeNet()
	sixHosts(t, fake2)
	if err := f.replica(fake2).handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if s := f.jobStatus(t, jobID); s != "completed" {
		t.Fatalf("job after resume = %s, want completed", s)
	}
	if n := fake2.DialedAddrs()["10.183.8.10"]; n != 0 {
		t.Errorf("the resumed run contacted the finished host %d time(s)", n)
	}
	if n := f.findingCount(t, jobID); n != 1 {
		t.Errorf("findings = %d, want 1 (no duplicate from the resume)", n)
	}
	if st := f.unitStatuses(t, jobID); countStatus(st, unitDone) != 6 {
		t.Errorf("units after resume = %v, want all done", st)
	}
}

// A crash mid-unit: the job is reaped (failed), its unit in flight with it; a
// person's Retry puts every unit that is not done back to pending; the next
// run finishes only those; and the crashed owner's late commit — if it was
// alive after all — is refused by the attempt fence.
//
// This is the path once a job has used its automatic resumes (see
// plan_resume_integration_test.go for the resume itself): limit 1, one
// resume already spent.
func TestIntegration_PlanUnits_CrashReapRetryResumes(t *testing.T) {
	setResumeLimit(t, 1)
	f, fake := newUnitFixture(t)
	sixHosts(t, fake)
	jobID := f.createPlanJob(t, "20-30", "10.183.8.10", "10.183.8.11")
	if _, err := f.raw.Exec(`UPDATE discovery_jobs SET metadata = jsonb_set(metadata, '{auto_resumes}', '1') WHERE id = $1`, jobID); err != nil {
		t.Fatal(err)
	}
	job, err := f.svc.GetJob(jobID)
	if err != nil {
		t.Fatal(err)
	}
	// The crashed run: claimed, units created, .10 done, .11 in flight.
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	run, targets, err := f.jp.newPlanRun(job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.ensureUnits(job, targets, run.auth); err != nil {
		t.Fatal(err)
	}
	units, err := f.jp.pendingUnits(job)
	if err != nil || len(units) != 2 {
		t.Fatalf("units = %v %v", units, err)
	}
	byAddr := map[string]jobUnit{}
	for _, u := range units {
		byAddr[u.Address] = u
	}
	if err := run.runUnit(context.Background(), byAddr["10.183.8.10"]); err != nil {
		t.Fatal(err)
	}
	stale := byAddr["10.183.8.11"]
	staleAttempt, ok, err := f.jp.claimUnit(job, stale, run.targets[stale.TargetID])
	if err != nil || !ok {
		t.Fatalf("claim unit: %v %v", ok, err)
	}
	staleOut, err := run.engine.Run(context.Background(), shareddisc.UnitInput{Addr: netip.MustParseAddr("10.183.8.11"), TCP: run.targets[stale.TargetID].tcp})
	if err != nil {
		t.Fatal(err)
	}
	// ...and the owner dies. The reaper fails the job and its unit in flight.
	// (updated_at is set by a trigger and cannot be backdated: wait out a
	// short lease instead, as the reaper's own tests do.)
	time.Sleep(testLease + 100*time.Millisecond)
	if reaped, err := f.svc.ReapStalledJob(jobID, testLease); err != nil || !reaped {
		t.Fatalf("reap: %v %v", reaped, err)
	}
	if st := f.unitStatuses(t, jobID); st["10.183.8.11"] != unitFailed || st["10.183.8.10"] != unitDone {
		t.Fatalf("units after the reaper = %v, want the one in flight failed", st)
	}
	if s, msg := f.jobStatusAndError(t, jobID); s != "failed" || !strings.Contains(msg, "stopped after 1 automatic resumes") {
		t.Fatalf("job past its resume limit = %s %q, want failed, saying it stopped after 1 automatic resume", s, msg)
	}

	if err := f.svc.RequeueJobForRetry(jobID); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if st := f.unitStatuses(t, jobID); st["10.183.8.11"] != unitPending || st["10.183.8.10"] != unitDone {
		t.Fatalf("units after Retry = %v, want only the unfinished one pending", st)
	}
	fake2 := NewFakeNet()
	sixHosts(t, fake2)
	if err := f.replica(fake2).handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatalf("retry run: %v", err)
	}
	if s := f.jobStatus(t, jobID); s != "completed" {
		t.Fatalf("job after Retry = %s, want completed", s)
	}
	if n := fake2.DialedAddrs()["10.183.8.10"]; n != 0 {
		t.Errorf("the retry contacted the finished host %d time(s)", n)
	}

	// The crashed owner was alive after all, and commits its attempt now.
	if err := run.commitUnit(stale, run.targets[stale.TargetID], staleAttempt, staleOut); !errors.Is(err, errUnitFenced) {
		t.Fatalf("stale commit = %v, want errUnitFenced", err)
	}
	if n := f.findingCount(t, jobID); n != 1 {
		t.Errorf("findings = %d, want .10's one (nothing from .11, nothing twice)", n)
	}
}

// The attempt fence: of two runs of the same unit, only the attempt that
// currently owns it can commit — a stale attempt's results are refused even
// while the unit is running — and a commit that somehow got past the fence
// still cannot leave two copies of the unit's findings in the job record.
func TestIntegration_PlanUnits_CommitIsFencedAndFindingsSingle(t *testing.T) {
	f, fake := newUnitFixture(t)
	sixHosts(t, fake)
	jobID := f.createPlanJob(t, "20-30", "10.183.8.10")
	job, _ := f.svc.GetJob(jobID)
	run, targets, err := f.jp.newPlanRun(job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.ensureUnits(job, targets, run.auth); err != nil {
		t.Fatal(err)
	}
	units, _ := f.jp.pendingUnits(job)
	u, tg := units[0], targets[0]
	first, _, _ := f.jp.claimUnit(job, u, tg)
	if _, err := f.raw.Exec(`UPDATE discovery_job_units SET status = 'pending' WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	second, _, _ := f.jp.claimUnit(job, u, tg)
	if second != first+1 {
		t.Fatalf("attempts %d then %d", first, second)
	}

	// Two different results, so the stored one says whose it is.
	staleOut := shareddisc.UnitOutput{Host: shareddisc.HostScan{Addr: netip.MustParseAddr("10.183.8.10"), PortsRequested: 11, OpenCount: 1, Open: []int{21}, Closed: 10},
		TCP: []shareddisc.Observation{{Port: 21, Transport: "tcp", State: "open"}}}
	currentOut := shareddisc.UnitOutput{Host: shareddisc.HostScan{Addr: netip.MustParseAddr("10.183.8.10"), PortsRequested: 11, OpenCount: 1, Open: []int{25}, Closed: 10},
		TCP: []shareddisc.Observation{{Port: 25, Transport: "tcp", State: "open"}}}
	if err := run.commitUnit(u, tg, first, staleOut); !errors.Is(err, errUnitFenced) {
		t.Fatalf("stale attempt's commit = %v, want errUnitFenced while the current attempt runs", err)
	}
	if err := run.commitUnit(u, tg, second, currentOut); err != nil {
		t.Fatalf("current attempt's commit: %v", err)
	}
	ports := func() []int {
		var out []int
		if err := f.db.Select(&out, `SELECT port FROM discovery_findings WHERE job_id = $1 ORDER BY port`, jobID); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := ports(); len(got) != 1 || got[0] != 25 {
		t.Fatalf("stored findings on ports %v, want the current attempt's [25]", got)
	}
	// Past the fence by force (a hand-edited row): still one copy.
	if _, err := f.raw.Exec(`UPDATE discovery_job_units SET status = 'running' WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := run.commitUnit(u, tg, second, currentOut); err != nil {
		t.Fatal(err)
	}
	if got := ports(); len(got) != 1 {
		t.Fatalf("after a second commit of the same unit, findings on ports %v, want one copy", got)
	}
}

// H16 at run time: an address cleared when its unit was created but excluded
// before the unit ran is refused at that moment — by the liveness sweep for a
// range, by the port phase for a named host — and never contacted.
func TestIntegration_PlanUnits_AuthorizationIsRecheckedBeforeEveryPacket(t *testing.T) {
	old := unitScopeTTL
	unitScopeTTL = 0
	t.Cleanup(func() { unitScopeTTL = old })
	f, fake := newUnitFixture(t)
	fake.Host("10.183.9.10", nil, nil)
	fake.Host("10.183.9.21", nil, nil)
	fake.Host("10.183.9.22", nil, nil)
	jobID := f.createPlanJob(t, "20-30", "10.183.9.10", "10.183.9.21-10.183.9.22")
	job, _ := f.svc.GetJob(jobID)
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatal(claimed, err)
	}
	run, targets, err := f.jp.newPlanRun(job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.ensureUnits(job, targets, run.auth); err != nil {
		t.Fatal(err)
	}
	if st := f.unitStatuses(t, jobID); countStatus(st, unitPending) != 3 {
		t.Fatalf("units = %v, want three cleared", st)
	}
	for _, excluded := range []string{"10.183.9.10/32", "10.183.9.22/32"} {
		if _, err := f.raw.Exec(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
			VALUES ($1, $2, 'cidr', $2, 'private', 'production', true, '{"sensitive": "true"}')`, f.tenant, excluded); err != nil {
			t.Fatal(err)
		}
	}
	if err := run.livenessPhase(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := run.portPhase(context.Background()); err != nil {
		t.Fatal(err)
	}
	dialed := fake.DialedAddrs()
	for _, addr := range []string{"10.183.9.10", "10.183.9.22"} {
		if dialed[addr] != 0 {
			t.Errorf("%s was excluded before its unit ran and was dialled %d time(s)", addr, dialed[addr])
		}
	}
	if dialed["10.183.9.21"] == 0 {
		t.Error("the address still cleared was never scanned — the test proves nothing")
	}
	st := f.unitStatuses(t, jobID)
	if st["10.183.9.10"] != unitFailed || st["10.183.9.22"] != unitFailed || st["10.183.9.21"] != unitDone {
		t.Errorf("units = %v, want the two excluded failed and .21 done", st)
	}
}

// A unit claim/storage failure must fail the job instead of letting the job
// complete with pending units that were never scanned.
func TestIntegration_PlanUnits_UnfinishedUnitsBlockJobCompletion(t *testing.T) {
	f, _ := newUnitFixture(t)
	jobID := f.createPlanJob(t, "22", "10.183.9.50")
	installFailUnitClaimTrigger(t, f.raw, jobID)

	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatalf("process job: %v", err)
	}
	if s := f.jobStatus(t, jobID); s != "failed" {
		t.Fatalf("job status = %s, want failed (not completed with unfinished units)", s)
	}
	st := f.unitStatuses(t, jobID)
	if st["10.183.9.50"] != unitPending {
		t.Fatalf("units = %v, want the unclaimed unit still pending", st)
	}
	var msg string
	if err := f.raw.QueryRow(`SELECT COALESCE(error_message, '') FROM discovery_jobs WHERE id = $1`, jobID).Scan(&msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "unfinished work units") {
		t.Fatalf("job error_message = %q, want unfinished-unit guard", msg)
	}
}

func installFailUnitClaimTrigger(t *testing.T, raw *sql.DB, jobID string) {
	t.Helper()
	suffix := strings.ReplaceAll(jobID, "-", "_")
	fn := "test_fail_unit_claim_" + suffix
	trig := fn + "_trg"
	ddl := fmt.Sprintf(`
CREATE OR REPLACE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF NEW.job_id = '%s'::uuid AND OLD.status = 'pending' AND NEW.status = 'running' THEN
		RAISE EXCEPTION 'test claim failure';
	END IF;
	RETURN NEW;
END;
$$;
CREATE TRIGGER %s BEFORE UPDATE OF status ON discovery_job_units
FOR EACH ROW EXECUTE FUNCTION %s();`, fn, jobID, trig, fn)
	if _, err := raw.Exec(ddl); err != nil {
		t.Fatalf("install claim-failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = raw.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON discovery_job_units; DROP FUNCTION IF EXISTS %s();`, trig, fn))
	})
}

// A cancel of a job no processor is running (queued, its units pending from a
// handed-back run) cancels those units too, so the coverage does not show
// them still to do under a cancelled job.
func TestIntegration_PlanUnits_CancelOfAQueuedJobCancelsItsUnits(t *testing.T) {
	f, _ := newUnitFixture(t)
	jobID := f.createPlanJob(t, "22", "10.183.9.40", "10.183.9.41")
	job, _ := f.svc.GetJob(jobID)
	run, targets, err := f.jp.newPlanRun(job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.ensureUnits(job, targets, run.auth); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CancelJob(jobID); err != nil {
		t.Fatal(err)
	}
	if st := f.unitStatuses(t, jobID); countStatus(st, unitCancelled) != 2 {
		t.Fatalf("units after cancelling a queued job = %v, want both cancelled", st)
	}
}

// RLS: a tenant reads and writes only its own units.
func TestIntegration_PlanUnits_RLSIsolatesTenants(t *testing.T) {
	f, _ := newUnitFixture(t)
	jobID := f.createPlanJob(t, "22", "10.183.9.30")
	job, _ := f.svc.GetJob(jobID)
	run, targets, err := f.jp.newPlanRun(job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.ensureUnits(job, targets, run.auth); err != nil {
		t.Fatal(err)
	}
	app := testdb.ConnectAsAppRole(t, f.raw)
	other := testdb.NewTenant(t, f.raw)
	var mine, theirs int
	testdb.AsTenant(t, app, f.tenant, func(tx *sql.Tx) {
		if err := tx.QueryRow(`SELECT count(*) FROM discovery_job_units WHERE job_id = $1`, jobID).Scan(&mine); err != nil {
			t.Fatal(err)
		}
	})
	testdb.AsTenant(t, app, other, func(tx *sql.Tx) {
		if err := tx.QueryRow(`SELECT count(*) FROM discovery_job_units WHERE job_id = $1`, jobID).Scan(&theirs); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`SAVEPOINT s`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(`INSERT INTO discovery_job_units (tenant_id, job_id, target_id, address) VALUES ($1, $2, $3, '10.183.9.31')`, f.tenant, jobID, targets[0].rowID)
		if err == nil {
			t.Error("another tenant inserted a unit into this tenant's job")
		}
		_, _ = tx.Exec(`ROLLBACK TO SAVEPOINT s`)
	})
	if mine != 1 || theirs != 0 {
		t.Fatalf("own tenant sees %d unit(s), another tenant sees %d; want 1 and 0", mine, theirs)
	}
}
