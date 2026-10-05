package services

// The stuck-job reaper against a real Postgres: a `running` job whose
// owner stopped heartbeating is failed and stops holding its tenant's
// concurrency slot; a job with a live owner is never failed, on any replica;
// a person's Retry resumes a reaped job without rescanning finished targets.
//
// discovery_jobs.updated_at is set by a BEFORE UPDATE trigger, so a test
// cannot backdate a heartbeat. The lease is shortened instead and the test
// waits it out. Every sweep is confined to the test's tenant (sweepTenant):
// the shared test database holds other suites' jobs, which a one-second lease
// must not touch.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

const testLease = time.Second

func reaperFixture(t *testing.T) (*dispatchFixture, *gateScanner) {
	t.Helper()
	f, scanner := lifecycleFixture(t)
	// Every platform job is a scan-plan job ( WP5), which the reaper
	// resumes automatically; these tests pin the reap itself — failed, for a
	// person to Retry — so automatic resume is off (plan_resume_integration_test.go
	// covers it).
	setResumeLimit(t, 0)
	f.jp.heartbeatLease = testLease
	f.jp.sweepTenant = f.tenant.String()
	return f, scanner
}

// anotherReplica is a second processor over the same database: its own
// registry, so it does not know which jobs the first one is running.
func (f *dispatchFixture) anotherReplica() *JobProcessor {
	svc := NewDiscoveryService(f.db, f.db)
	return &JobProcessor{db: f.db, bypassDB: f.db, discoveryService: svc, rateLimiter: NewRateLimiter(f.db),
		heartbeatLease: f.jp.heartbeatLease, sweepTenant: f.jp.sweepTenant}
}

func outlive(lease time.Duration) { time.Sleep(lease + 300*time.Millisecond) }

// A claimed job whose processor died (it never heartbeats again) is failed
// once the lease has passed, with a message a person can act on — and the
// tenant's concurrency slot it held is free again.
func TestIntegration_JobReaper_CrashedJobIsFailedAndFreesItsSlot(t *testing.T) {
	f, _ := reaperFixture(t)
	if _, err := f.jp.rateLimiter.GetRateLimit(f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`UPDATE discovery_rate_limits SET concurrent_jobs = 1 WHERE tenant_id = $1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	jobID := f.createPlatformJob(t, "10.184.0.1")
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatalf("ClaimJob = %v, %v", claimed, err)
	}
	// The crash: nothing touches the row again.

	if n := f.jp.reapStalledJobs(); n != 0 {
		t.Fatalf("reaped %d jobs inside the lease, want 0", n)
	}
	if err := f.jp.rateLimiter.CheckRateLimit(f.tenant.String()); err == nil {
		t.Fatal("the stranded running job did not count against concurrent_jobs=1 — the test proves nothing")
	}

	outlive(testLease)
	// Through the poll's own pass, so the reaper's wiring is what is tested.
	if ok := f.jp.stuckJobPass(func(string) error { return nil }); !ok {
		t.Fatal("stuckJobPass reported a failed read")
	}
	var status, msg string
	if err := f.raw.QueryRow(`SELECT status, error_message FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status, &msg); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !containsAll(msg, "scan stopped responding", "no heartbeat since", "retry to resume") {
		t.Fatalf("reaped job = %q / %q, want failed with the heartbeat message", status, msg)
	}
	if err := f.jp.rateLimiter.CheckRateLimit(f.tenant.String()); err != nil {
		t.Fatalf("CheckRateLimit after the reap: %v — the dead job still holds the slot", err)
	}
}

// A job whose owner is alive — beating from the lease ticker while one long
// host scan blocks the loop — survives every reaper pass, on another replica
// and on its own, however long it runs.
func TestIntegration_JobReaper_LiveJobSurvivesRepeatedPasses(t *testing.T) {
	f, scanner := reaperFixture(t)
	f.jp.leaseInterval = 100 * time.Millisecond
	other := f.anotherReplica()
	jobID := f.createPlatformJob(t, "10.184.1.1")

	done := make(chan error, 1)
	go func() { done <- f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}) }()
	waitStarted(t, scanner)

	// Three leases' worth of passes while the single host scan is blocked:
	// only the ticker keeps the row fresh.
	deadline := time.Now().Add(3 * testLease)
	for time.Now().Before(deadline) {
		if n := other.reapStalledJobs(); n != 0 {
			t.Fatalf("another replica reaped %d live job(s)", n)
		}
		if n := f.jp.reapStalledJobs(); n != 0 {
			t.Fatalf("the owning replica reaped its own live job (%d)", n)
		}
		time.Sleep(100 * time.Millisecond)
	}
	scanner.open()
	if err := waitErr(t, done, 10*time.Second, "live job"); err != nil {
		t.Fatal(err)
	}
	if s := f.jobStatus(t, jobID); s != "completed" {
		t.Fatalf("live job ended %q, want completed", s)
	}
}

// The transition re-checks staleness itself. A job that looked stalled when a
// reaper selected it, and then beat, is not failed — the window between a
// replica's SELECT and its UPDATE cannot kill a live job.
func TestIntegration_JobReaper_HeartbeatBetweenSelectAndUpdateWins(t *testing.T) {
	f, _ := reaperFixture(t)
	jobID := f.createPlatformJob(t, "10.184.2.1")
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatalf("ClaimJob = %v, %v", claimed, err)
	}
	outlive(testLease) // stale: a reaper's SELECT would pick it now
	if running, err := f.svc.TouchRunningJob(jobID); err != nil || !running {
		t.Fatalf("TouchRunningJob = %v, %v", running, err)
	}
	if reaped, err := f.svc.ReapStalledJob(jobID, testLease); err != nil || reaped {
		t.Fatalf("ReapStalledJob after a fresh heartbeat = %v, %v; want false", reaped, err)
	}
	if s := f.jobStatus(t, jobID); s != "running" {
		t.Fatalf("status = %q, want running", s)
	}
}

// Only a `running` job is reaped. A job that ended — however stale its row —
// is never rewritten, so a cancel or a completion keeps its verdict.
func TestIntegration_JobReaper_NeverRewritesAnEndedJob(t *testing.T) {
	f, _ := reaperFixture(t)
	for _, ended := range []string{"cancelled", "completed", "failed"} {
		jobID := f.createPlatformJob(t, "10.184.3.1")
		if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
			t.Fatalf("ClaimJob = %v, %v", claimed, err)
		}
		reason := "earlier verdict"
		if ended == "cancelled" {
			if err := f.svc.CancelJob(jobID); err != nil {
				t.Fatal(err)
			}
		} else if err := f.svc.UpdateJobStatus(jobID, ended, &reason); err != nil {
			t.Fatal(err)
		}
		outlive(testLease)
		if reaped, err := f.svc.ReapStalledJob(jobID, testLease); err != nil || reaped {
			t.Errorf("ReapStalledJob on a %s job = %v, %v; want false", ended, reaped, err)
		}
		if s := f.jobStatus(t, jobID); s != ended {
			t.Errorf("a %s job became %q", ended, s)
		}
	}
	// A job this processor does not run (a tenant sensor's) is never reaped.
	sensorJob := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status) VALUES ($1, $2, 'sensors', 'running')`, sensorJob, f.tenant); err != nil {
		t.Fatal(err)
	}
	outlive(testLease)
	if reaped, err := f.svc.ReapStalledJob(sensorJob.String(), testLease); err != nil || reaped {
		t.Errorf("ReapStalledJob on a sensors job = %v, %v; want false", reaped, err)
	}
}

// Every replica runs the poll. Racing on one dead job, exactly one of them
// performs the transition.
func TestIntegration_JobReaper_RacingReplicasTransitionOnce(t *testing.T) {
	f, _ := reaperFixture(t)
	jobID := f.createPlatformJob(t, "10.184.4.1")
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatalf("ClaimJob = %v, %v", claimed, err)
	}
	outlive(testLease)

	const replicas = 8
	var total atomic.Int32
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < replicas; i++ {
		replica := f.anotherReplica()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			total.Add(int32(replica.reapStalledJobs()))
		}()
	}
	close(gate)
	wg.Wait()
	if total.Load() != 1 {
		t.Fatalf("%d replicas reaped the job %d times, want exactly once", replicas, total.Load())
	}
}

// A heartbeat write that fails — the database briefly unreachable — is logged,
// and the scan goes on: every host is scanned and the job completes.
func TestIntegration_JobReaper_FailedHeartbeatDoesNotStopTheScan(t *testing.T) {
	f, scanner := reaperFixture(t)
	scanner.open()
	f.jp.leaseInterval = 10 * time.Millisecond
	var attempts atomic.Int32
	f.jp.touchJob = func(string) (bool, error) {
		attempts.Add(1)
		return false, errors.New("connection refused")
	}
	jobID := f.createPlatformJob(t, "10.184.6.1-10.184.6.3")

	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatalf("handleDiscoveryJob: %v", err)
	}
	if attempts.Load() == 0 {
		t.Fatal("no heartbeat was attempted — the test proves nothing")
	}
	if got := scanner.scanned(); len(got) != 3 {
		t.Fatalf("hosts scanned = %v, want all 3 despite the failing heartbeat", got)
	}
	if s := f.jobStatus(t, jobID); s != "completed" {
		t.Fatalf("job = %q, want completed", s)
	}
}

// The republish window follows the row's last activity, so a job handed back
// to the queue days after it was created is still picked up; a job idle for a
// day, or created over a week ago, is not.
func TestIntegration_JobReaper_RepublishWindowFollowsLastActivity(t *testing.T) {
	f, _ := reaperFixture(t)
	insert := func(created, updated string) string {
		id := uuid.New()
		if _, err := f.raw.Exec(`
			INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status, created_at, updated_at)
			VALUES ($1, $2, 'auto', 'queued', NOW() - $3::interval, NOW() - $4::interval)`, id, f.tenant, created, updated); err != nil {
			t.Fatal(err)
		}
		return id.String()
	}
	handedBack := insert("3 days", "2 minutes") // ran for days, handed back on shutdown
	fresh := insert("10 seconds", "10 seconds") // its own publish is still in flight
	idle := insert("3 days", "2 days")          // untouched for a day: not republished, as before
	ancient := insert("8 days", "2 minutes")    // past the ceiling

	// Through the poll's own pass, with the NATS publish recorded.
	in := map[string]bool{}
	if ok := f.jp.stuckJobPass(func(id string) error { in[id] = true; return nil }); !ok {
		t.Fatal("stuckJobPass reported a failed read")
	}
	if !in[handedBack] {
		t.Error("a job handed back to the queue three days after creation was not republished")
	}
	for name, id := range map[string]string{"fresh": fresh, "idle": idle, "ancient": ancient} {
		if in[id] {
			t.Errorf("the %s queued job was republished", name)
		}
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
