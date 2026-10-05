package services

// The discovery job lifecycle against a real Postgres ( H1/H2):
//
//   - a job is scanned ONCE however many times its message is delivered;
//   - completed / failed / cancelled are sticky, and a person's Retry is the
//     one way back from failed;
//   - a cancel read from the row (another replica's) stops the scan before the
//     next host;
//   - the NATS handler's context is not the job's deadline.
//
// Driven through the real entry point (handleDiscoveryJob / the processor) on
// the real scan engine — the only executor since WP5 — with only the
// network stubbed (a FakeNet whose first connection to each host can be held),
// so deleting the line that closes each hole turns a test here red. Cancel on
// this replica, hand-back on shutdown and resume after a crash are pinned unit
// by unit in work_unit_lifecycle_integration_test.go.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// gateScanner holds the engine's FIRST connection to each host until the test
// lets it go (open) or the job's context ends. It records each host in the
// order it was first contacted; later connections to a host pass at once, so
// a released host is scanned and identified normally.
type gateScanner struct {
	mu      sync.Mutex
	hosts   []string
	seen    map[netip.Addr]bool
	started chan string
	release chan struct{}
	opened  sync.Once
	// onScan, when set, runs at a host's first connection (outside the lock).
	onScan func(host string)
}

func newGateScanner() *gateScanner {
	return &gateScanner{seen: map[netip.Addr]bool{}, started: make(chan string, 64), release: make(chan struct{})}
}

// hold is the FakeNet OnDial hook.
func (s *gateScanner) hold(ctx context.Context, _ string, ap netip.AddrPort) {
	s.mu.Lock()
	if s.seen[ap.Addr()] {
		s.mu.Unlock()
		return
	}
	s.seen[ap.Addr()] = true
	host := ap.Addr().String()
	s.hosts = append(s.hosts, host)
	s.mu.Unlock()
	if s.onScan != nil {
		s.onScan(host)
	}
	s.started <- host
	select {
	case <-s.release:
	case <-ctx.Done():
	}
}

// open lets every blocked and future scan finish. Safe to call twice.
func (s *gateScanner) open() { s.opened.Do(func() { close(s.release) }) }

func (s *gateScanner) scanned() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.hosts...)
}

// lifecycleFixture is a dispatch fixture with the collaborators the full
// processor path touches: the scan engine on a gated FakeNet, the platform
// sensor its findings are mirrored under, and an alert service whose
// notification endpoint answers 200.
func lifecycleFixture(t *testing.T) (*dispatchFixture, *gateScanner) {
	t.Helper()
	f := newDispatchFixture(t)
	notify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(notify.Close)
	t.Setenv("NOTIFICATION_SERVICE_URL", notify.URL)
	f.jp.alertService = &AlertService{db: f.db, httpClient: notify.Client()}
	if _, err := f.raw.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, ip_address, reporting_interval, last_heartbeat)
		VALUES ($1, $2, 'Platform Discovery Sensor', 'platform', '1.0.0', 'discovery', 'active', '{system}', '10.0.0.1', 30, NOW())`, uuid.New(), f.tenant); err != nil {
		t.Fatalf("seed platform sensor: %v", err)
	}
	scanner := newGateScanner()
	// A test that fails while scans are blocked must not hang the package.
	t.Cleanup(scanner.open)
	f.net = NewFakeNet()
	f.net.OnDial = scanner.hold
	// An unrecognised greeting: each host's 443 is one open, unidentified
	// endpoint — one finding — named without a TLS attempt.
	f.banner = ServeBanner(t, "LIFECYCLE-TEST\r\n")
	f.jp.planEngineOptions = []shareddisc.Option{shareddisc.WithDialer(f.net)}
	return f, scanner
}

// createPlatformJob queues an in-cluster job over private targets, in the
// legacy request shape — planned at creation ( D2) — and makes each
// target address answer on 443.
func (f *dispatchFixture) createPlatformJob(t *testing.T, targets ...string) string {
	t.Helper()
	if f.net != nil {
		for _, addr := range shareddisc.ExpandTargets(targets) {
			f.net.Host(addr, map[uint16]string{443: f.banner}, nil)
		}
	}
	job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: targets, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "auto",
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if job.Plan == nil {
		t.Fatal("the platform job was not planned")
	}
	return job.ID
}

func jobMessage(t *testing.T, jobID string) *nats.Msg {
	t.Helper()
	data, err := json.Marshal(events.DiscoveryJobEvent{EventID: uuid.New(), JobID: jobID})
	if err != nil {
		t.Fatal(err)
	}
	return &nats.Msg{Data: data}
}

func (f *dispatchFixture) jobStatus(t *testing.T, jobID string) string {
	t.Helper()
	var status string
	if err := f.raw.QueryRow(`SELECT status FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	return status
}

func (f *dispatchFixture) findingCount(t *testing.T, jobID string) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1`, jobID).Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

func waitStarted(t *testing.T, s *gateScanner) string {
	t.Helper()
	select {
	case host := <-s.started:
		return host
	case <-time.After(10 * time.Second):
		t.Fatal("no host scan started within 10s")
		return ""
	}
}

func waitErr(t *testing.T, done <-chan error, within time.Duration, what string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(within):
		t.Fatalf("%s did not return within %s", what, within)
		return nil
	}
}

// H1. The same message delivered again while the job is still scanning —
// what JetStream does after AckWait when nothing renews the lease — must not
// scan again, and its findings must not be stored twice. Delivered a third
// time after the job ended, still nothing.
func TestIntegration_JobLifecycle_RedeliveryWhileRunningDoesNotRescan(t *testing.T) {
	f, scanner := lifecycleFixture(t)
	jobID := f.createPlatformJob(t, "10.183.0.10")

	first := make(chan error, 1)
	go func() { first <- f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}) }()
	waitStarted(t, scanner)

	// The redelivery, while the first delivery is mid-scan. It must return
	// at once: a redelivery that starts scanning blocks here.
	second := make(chan error, 1)
	go func() { second <- f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}) }()
	if err := waitErr(t, second, 5*time.Second, "redelivery (it is scanning again?)"); err != nil {
		t.Fatalf("redelivery returned %v, want nil (ack, nothing to do)", err)
	}
	if got := scanner.scanned(); len(got) != 1 {
		t.Fatalf("hosts scanned after redelivery = %v, want exactly one scan", got)
	}

	scanner.open()
	if err := waitErr(t, first, 10*time.Second, "first delivery"); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatalf("delivery after completion: %v", err)
	}

	if got := scanner.scanned(); len(got) != 1 {
		t.Errorf("hosts scanned = %v, want exactly one scan for three deliveries", got)
	}
	if n := f.findingCount(t, jobID); n != 1 {
		t.Errorf("discovery_findings rows = %d, want 1 (no duplicate insert)", n)
	}
	if s := f.jobStatus(t, jobID); s != "completed" {
		t.Errorf("job status = %q, want completed", s)
	}
}

// H1, the race the early status check cannot see: several deliveries of a
// queued job arriving at once (replicas each republishing a stuck job, plus a
// broker redelivery). Every one reads `queued`; only the atomic claim keeps
// all but one from scanning.
func TestIntegration_JobLifecycle_ConcurrentDeliveriesScanOnce(t *testing.T) {
	f, scanner := lifecycleFixture(t)
	jobID := f.createPlatformJob(t, "10.183.0.11")

	const deliveries = 8
	var wg sync.WaitGroup
	var returned atomic.Int32
	gate := make(chan struct{})
	for i := 0; i < deliveries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			_ = f.jp.processDiscoveryJobByID(jobID)
			returned.Add(1)
		}()
	}
	close(gate)

	// Every delivery either returns (lost the claim) or blocks in the scanner
	// (won it). Wait for all of them to be one or the other, then let the scans
	// finish.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && int(returned.Load())+len(scanner.scanned()) < deliveries {
		time.Sleep(5 * time.Millisecond)
	}
	scanner.open()
	wg.Wait()

	if got := scanner.scanned(); len(got) != 1 {
		t.Fatalf("%d simultaneous deliveries scanned %d times (%v), want exactly once", deliveries, len(got), got)
	}
	if n := f.findingCount(t, jobID); n != 1 {
		t.Errorf("discovery_findings rows = %d, want 1", n)
	}
}

// H1. The running job keeps its message leased — the broker is told it is in
// progress on the beat — so a scan that outlives AckWait is not redelivered
// at all, and the beats stop once the job has ended.
func TestIntegration_JobLifecycle_RunningJobRenewsItsMessageLease(t *testing.T) {
	f, scanner := lifecycleFixture(t)
	f.jp.leaseInterval = 10 * time.Millisecond
	jobID := f.createPlatformJob(t, "10.183.0.12")

	lease := &countingLease{}
	done := make(chan error, 1)
	go func() { done <- f.jp.handleDiscoveryJob(jobMessage(t, jobID), lease) }()
	waitStarted(t, scanner)
	deadline := time.Now().Add(5 * time.Second)
	for lease.beats.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if beats := lease.beats.Load(); beats < 3 {
		t.Fatalf("a running job renewed its lease %d times, want at least 3", beats)
	}
	scanner.open()
	if err := waitErr(t, done, 10*time.Second, "job"); err != nil {
		t.Fatal(err)
	}
	after := lease.beats.Load()
	time.Sleep(60 * time.Millisecond)
	if extra := lease.beats.Load() - after; extra != 0 {
		t.Fatalf("lease renewed %d times after the job ended", extra)
	}
}

// H1. The subscriber hands the handler a context that expires after
// ProcessingTimeout (four minutes). The job must not inherit it: a handler
// context that is already over still runs the job to the end.
func TestIntegration_JobLifecycle_HandlerContextIsNotTheJobDeadline(t *testing.T) {
	f, scanner := lifecycleFixture(t)
	scanner.open() // scans finish immediately unless their context ends
	jobID := f.createPlatformJob(t, "10.183.0.13")

	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.jp.handleDiscoveryJobJS(expired, jobMessage(t, jobID)); err != nil {
		t.Fatalf("handleDiscoveryJobJS: %v", err)
	}
	if s := f.jobStatus(t, jobID); s != "completed" {
		t.Fatalf("job status = %q, want completed — the handler's expired context cut the scan short", s)
	}
	if n := f.findingCount(t, jobID); n != 1 {
		t.Fatalf("findings = %d, want 1", n)
	}
}

// H2, multi-replica. The cancel is handled by ANOTHER replica: only the row
// changes, nothing signals this process. The engine checks the row before
// every unit, so no host is started once it says cancelled, the hosts already
// finished keep their findings, and a late completion does not overwrite it.
// Six hosts against the pace's four workers: the last two can only start
// after a check of the row.
func TestIntegration_JobLifecycle_CancelSeenThroughTheRowFromAnotherReplica(t *testing.T) {
	f, scanner := lifecycleFixture(t)
	scanner.open() // hosts finish on their own; only the row can stop the job
	hosts := []string{"10.183.4.1", "10.183.4.2", "10.183.4.3", "10.183.4.4", "10.183.4.5", "10.183.4.6"}
	jobID := f.createPlatformJob(t, hosts...)
	var once sync.Once
	scanner.onScan = func(string) {
		once.Do(func() {
			// What the other replica's CancelJob writes. This process's
			// registry is not told.
			if _, err := f.raw.Exec(`UPDATE discovery_jobs SET status = 'cancelled', updated_at = NOW() WHERE id = $1`, jobID); err != nil {
				t.Errorf("cancel from the other replica: %v", err)
			}
		})
	}

	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatalf("handleDiscoveryJob: %v", err)
	}

	if got := scanner.scanned(); len(got) >= len(hosts) {
		t.Errorf("hosts scanned = %v, want fewer than all %d — the cancel was in the row before the last hosts", got, len(hosts))
	}
	if s := f.jobStatus(t, jobID); s != "cancelled" {
		t.Errorf("job status = %q, want cancelled (a late completion must not overwrite it)", s)
	}
	done := countStatus(f.unitStatuses(t, jobID), unitDone)
	if n := f.findingCount(t, jobID); n != done {
		t.Errorf("findings = %d, want one per host finished before the cancel (%d)", n, done)
	}
}

// H1/H2. completed, failed and cancelled are terminal: nothing moves a job out
// of one, so a late success cannot overwrite a cancel.
func TestIntegration_JobLifecycle_TerminalStatesAreSticky(t *testing.T) {
	f, _ := lifecycleFixture(t)
	for _, terminal := range []string{"cancelled", "completed", "failed"} {
		t.Run(terminal, func(t *testing.T) {
			jobID := f.createPlatformJob(t, "10.183.5.1")
			if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
				t.Fatalf("ClaimJob = %v, %v", claimed, err)
			}
			if terminal == "cancelled" {
				if err := f.svc.CancelJob(jobID); err != nil {
					t.Fatalf("CancelJob: %v", err)
				}
			} else if err := f.svc.UpdateJobStatus(jobID, terminal, nil); err != nil {
				t.Fatalf("UpdateJobStatus(%s): %v", terminal, err)
			}

			for _, next := range []string{"completed", "failed", "running", "queued", "cancelled"} {
				if next == terminal {
					continue
				}
				err := f.svc.UpdateJobStatus(jobID, next, nil)
				var conflict *JobStatusConflict
				if !errors.As(err, &conflict) || conflict.Current != terminal {
					t.Errorf("%s → %s: err = %v, want a JobStatusConflict naming %s", terminal, next, err, terminal)
				}
			}
			if err := f.svc.CancelJob(jobID); terminal != "cancelled" && !errors.Is(err, ErrJobStatusConflict) {
				t.Errorf("CancelJob on a %s job: err = %v, want ErrJobStatusConflict", terminal, err)
			}
			if claimed, err := f.svc.ClaimJob(jobID); claimed || err != nil {
				t.Errorf("ClaimJob on a %s job = %v, %v; want false, nil", terminal, claimed, err)
			}
			if s := f.jobStatus(t, jobID); s != terminal {
				t.Errorf("status = %q after the refused writes, want %s", s, terminal)
			}
		})
	}

	if err := f.svc.UpdateJobStatus(uuid.NewString(), "completed", nil); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("UpdateJobStatus on a missing job: err = %v, want ErrJobNotFound", err)
	}
}

// The claim is one conditional UPDATE: of many simultaneous claims exactly one
// wins, and a non-queued job cannot be claimed at all.
func TestIntegration_JobLifecycle_ClaimIsAtomic(t *testing.T) {
	f, _ := lifecycleFixture(t)
	jobID := f.createPlatformJob(t, "10.183.6.1")

	const claimers = 16
	var wins atomic.Int32
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < claimers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			claimed, err := f.svc.ClaimJob(jobID)
			if err != nil {
				t.Errorf("ClaimJob: %v", err)
			}
			if claimed {
				wins.Add(1)
			}
		}()
	}
	close(gate)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d of %d simultaneous claims won, want exactly 1", wins.Load(), claimers)
	}
	if s := f.jobStatus(t, jobID); s != "running" {
		t.Fatalf("status = %q, want running", s)
	}
}

// The one legitimate exit from a terminal state: a person's Retry of a failed
// job. It is put back to queued and runs again. (Which hosts a retry skips is
// the work units' business: work_unit_lifecycle_integration_test.go,
// TestIntegration_PlanUnits_CrashReapRetryResumes.)
func TestIntegration_JobLifecycle_RetryOfAFailedJobStillRuns(t *testing.T) {
	f, scanner := lifecycleFixture(t)
	scanner.open()
	jobID := f.createPlatformJob(t, "10.183.7.1", "10.183.7.2")

	// First run: the job fails before scanning anything.
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatalf("ClaimJob = %v, %v", claimed, err)
	}
	reason := "boom"
	if err := f.svc.UpdateJobStatus(jobID, "failed", &reason); err != nil {
		t.Fatalf("fail the job: %v", err)
	}

	if err := f.svc.RequeueJobForRetry(jobID); err != nil {
		t.Fatalf("RequeueJobForRetry: %v", err)
	}
	var errMsg *string
	if err := f.raw.QueryRow(`SELECT error_message FROM discovery_jobs WHERE id = $1`, jobID).Scan(&errMsg); err != nil {
		t.Fatal(err)
	}
	if s := f.jobStatus(t, jobID); s != "queued" || errMsg != nil {
		t.Fatalf("after retry: status %q, error %v; want queued with the old error cleared", s, errMsg)
	}

	if err := f.jp.processDiscoveryJobByID(jobID); err != nil {
		t.Fatalf("processDiscoveryJobByID after retry: %v", err)
	}
	if s := f.jobStatus(t, jobID); s != "completed" {
		t.Fatalf("retried job status = %q, want completed", s)
	}
	if got := scanner.scanned(); len(got) != 2 {
		t.Fatalf("retry scanned %v, want both hosts", got)
	}

	// Retry is for failed (or still-queued) jobs only.
	if err := f.svc.RequeueJobForRetry(jobID); !errors.Is(err, ErrJobStatusConflict) {
		t.Fatalf("retry of a completed job: err = %v, want ErrJobStatusConflict", err)
	}
}

// Progress is counted from the job's target rows.
func TestIntegration_JobLifecycle_TargetCounts(t *testing.T) {
	f, _ := lifecycleFixture(t)
	jobID := f.createPlatformJob(t, "10.183.9.1", "10.183.9.2", "10.183.9.3", "10.183.9.4")
	if _, err := f.raw.Exec(`
		UPDATE discovery_targets SET status = CASE input
			WHEN '10.183.9.1' THEN 'completed' WHEN '10.183.9.2' THEN 'failed' WHEN '10.183.9.3' THEN 'running' ELSE 'pending' END
		WHERE job_id = $1`, jobID); err != nil {
		t.Fatal(err)
	}
	counts, err := f.svc.JobTargetCounts(f.tenant.String(), jobID)
	if err != nil {
		t.Fatalf("JobTargetCounts: %v", err)
	}
	want := models.JobTargetCounts{Total: 4, Completed: 1, Failed: 1, Running: 1, Pending: 1}
	if counts != want {
		t.Fatalf("counts = %+v, want %+v", counts, want)
	}
	if p := TargetProgress(counts, "running"); p != 50 {
		t.Fatalf("progress = %d, want 50", p)
	}
	// Another tenant's id reads nothing.
	other, err := f.svc.JobTargetCounts(uuid.NewString(), jobID)
	if err != nil || other.Total != 0 {
		t.Fatalf("counts under another tenant = %+v, %v; want zero", other, err)
	}
}
