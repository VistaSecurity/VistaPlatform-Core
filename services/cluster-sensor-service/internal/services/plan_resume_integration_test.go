package services

// Automatic resume of a scan-plan job whose owner died ( WP2 follow-up).
// The reaper, which fails an abandoned job for a person to Retry, instead puts
// a scan-plan job back in the queue — at most planAutoResumeLimit times — and
// publishes it, because its units make resuming safe: done units stay done and
// the attempt fence keeps the dead owner's late commit out. Legacy jobs keep
// fail-and-retry (job_reaper_integration_test.go).
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

func setResumeLimit(t *testing.T, n int) {
	t.Helper()
	old := planAutoResumeLimit
	planAutoResumeLimit = n
	t.Cleanup(func() { planAutoResumeLimit = old })
}

func (f *dispatchFixture) jobStatusAndError(t *testing.T, jobID string) (string, string) {
	t.Helper()
	var status string
	var msg sql.NullString
	if err := f.raw.QueryRow(`SELECT status, error_message FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status, &msg); err != nil {
		t.Fatal(err)
	}
	return status, msg.String
}

func (f *dispatchFixture) autoResumes(t *testing.T, jobID string) int {
	t.Helper()
	var n sql.NullInt64
	if err := f.raw.QueryRow(`SELECT (metadata->>'auto_resumes')::int FROM discovery_jobs WHERE id = $1`, jobID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return int(n.Int64)
}

// crashedPlanJob leaves a scan-plan job as a killed owner would: claimed and
// `running`, .10 done with its finding stored, .11 claimed and scanned but
// not committed — then waits out the (test) heartbeat lease.
type crashedJob struct {
	id           string
	run          *planRun
	stale        jobUnit
	staleAttempt int
	staleOut     shareddisc.UnitOutput
}

func (f *dispatchFixture) crashedPlanJob(t *testing.T) crashedJob {
	t.Helper()
	jobID := f.createPlanJob(t, "20-30", "10.183.8.10", "10.183.8.11")
	job, err := f.svc.GetJob(jobID)
	if err != nil {
		t.Fatal(err)
	}
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
	c := crashedJob{id: jobID, run: run, stale: byAddr["10.183.8.11"]}
	var ok bool
	c.staleAttempt, ok, err = f.jp.claimUnit(job, c.stale, run.targets[c.stale.TargetID])
	if err != nil || !ok {
		t.Fatalf("claim unit: %v %v", ok, err)
	}
	if c.staleOut, err = run.engine.Run(context.Background(), shareddisc.UnitInput{Addr: netip.MustParseAddr("10.183.8.11"), TCP: run.targets[c.stale.TargetID].tcp}); err != nil {
		t.Fatal(err)
	}
	// updated_at is set by a trigger and cannot be backdated: wait out a short
	// lease instead, as the reaper's own tests do.
	time.Sleep(testLease + 100*time.Millisecond)
	return c
}

// A crash is resumed with no person involved: the reaper re-queues and
// publishes the job, the next replica's run (the real executor, on loopback
// fixtures) finishes only what was left — the finished host is not contacted
// again, nothing is stored twice — and the dead owner's late commit is fenced.
func TestIntegration_PlanResume_CrashIsResumedAndCompletes(t *testing.T) {
	f, fake := newUnitFixture(t)
	f.jp.heartbeatLease, f.jp.sweepTenant = testLease, f.tenant.String()
	sixHosts(t, fake)
	c := f.crashedPlanJob(t)

	// The real poll tick (stuckJobPass), so the publish wiring is what runs.
	var published []string
	if ok := f.jp.stuckJobPass(func(id string) error { published = append(published, id); return nil }); !ok {
		t.Fatal("stuck-job pass failed")
	}
	if s, msg := f.jobStatusAndError(t, c.id); s != "queued" || msg != "" {
		t.Fatalf("crashed plan job = %s %q, want queued with no error", s, msg)
	}
	if len(published) != 1 || published[0] != c.id {
		t.Fatalf("published %v, want the resumed job once", published)
	}
	if n := f.autoResumes(t, c.id); n != 1 {
		t.Fatalf("auto_resumes = %d, want 1", n)
	}
	if st := f.unitStatuses(t, c.id); st["10.183.8.10"] != unitDone || st["10.183.8.11"] != unitPending {
		t.Fatalf("units after the resume = %v, want .10 done and .11 pending", st)
	}

	fake2 := NewFakeNet()
	sixHosts(t, fake2)
	if err := f.replica(fake2).handleDiscoveryJob(jobMessage(t, c.id), &countingLease{}); err != nil {
		t.Fatalf("resumed run: %v", err)
	}
	if s := f.jobStatus(t, c.id); s != "completed" {
		t.Fatalf("resumed job = %s, want completed", s)
	}
	if n := fake2.DialedAddrs()["10.183.8.10"]; n != 0 {
		t.Errorf("the resumed run contacted the finished host %d time(s)", n)
	}
	if fake2.DialedAddrs()["10.183.8.11"] == 0 {
		t.Error("the resumed run never scanned the host that was in flight")
	}
	if err := c.run.commitUnit(c.stale, c.run.targets[c.stale.TargetID], c.staleAttempt, c.staleOut); !errors.Is(err, errUnitFenced) {
		t.Fatalf("the dead owner's late commit = %v, want errUnitFenced", err)
	}
	if n := f.findingCount(t, c.id); n != 1 {
		t.Errorf("findings = %d, want .10's one, stored once", n)
	}
}

// Past the limit the job is failed, saying how many times it was resumed, and
// nothing is published.
func TestIntegration_PlanResume_LimitReachedFails(t *testing.T) {
	setResumeLimit(t, 3)
	f, fake := newUnitFixture(t)
	f.jp.heartbeatLease, f.jp.sweepTenant = testLease, f.tenant.String()
	sixHosts(t, fake)
	jobID := f.createPlanJob(t, "20-30", "10.183.8.12")
	if _, err := f.raw.Exec(`UPDATE discovery_jobs SET metadata = jsonb_set(metadata, '{auto_resumes}', '3') WHERE id = $1`, jobID); err != nil {
		t.Fatal(err)
	}
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatal(claimed, err)
	}
	time.Sleep(testLease + 100*time.Millisecond)
	published := 0
	if n := f.jp.reapStalledJobs(func(string) error { published++; return nil }); n != 1 {
		t.Fatalf("reaper moved %d job(s), want 1", n)
	}
	s, msg := f.jobStatusAndError(t, jobID)
	if s != "failed" || !strings.Contains(msg, "retry to resume") || !strings.Contains(msg, "stopped after 3 automatic resumes") {
		t.Fatalf("job past the limit = %s %q, want failed with both sentences", s, msg)
	}
	if published != 0 {
		t.Fatalf("a failed job was published %d time(s)", published)
	}
}

// A live owner is never touched, plan job or not.
func TestIntegration_PlanResume_LiveOwnerUntouched(t *testing.T) {
	f, fake := newUnitFixture(t)
	sixHosts(t, fake)
	jobID := f.createPlanJob(t, "20-30", "10.183.8.13")
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatal(claimed, err)
	}
	if moved, err := f.svc.ReapStalledJob(jobID, time.Hour); err != nil || moved {
		t.Fatalf("reaping a job heartbeat a moment ago = %v %v, want untouched", moved, err)
	}
	if s := f.jobStatus(t, jobID); s != "running" || f.autoResumes(t, jobID) != 0 {
		t.Fatalf("live job = %s (resumes %d), want running, never resumed", s, f.autoResumes(t, jobID))
	}
}

// Two replicas' reapers racing for the same abandoned jobs: each job moves
// exactly once — one resume counted, one publish — whoever wins.
func TestIntegration_PlanResume_RacingReapersMoveOnce(t *testing.T) {
	f, fake := newUnitFixture(t)
	sixHosts(t, fake)
	var jobs []string
	for _, h := range []string{"10.183.8.20", "10.183.8.21", "10.183.8.22", "10.183.8.23"} {
		id := f.createPlanJob(t, "20-30", h)
		if claimed, err := f.svc.ClaimJob(id); err != nil || !claimed {
			t.Fatal(claimed, err)
		}
		jobs = append(jobs, id)
	}
	time.Sleep(testLease + 100*time.Millisecond)
	for _, id := range jobs {
		var wg sync.WaitGroup
		var mu sync.Mutex
		outcomes := map[reapOutcome]int{}
		start := make(chan struct{})
		for range 4 {
			wg.Go(func() {
				<-start
				out, err := f.svc.reapStalledJob(id, testLease)
				if err != nil {
					t.Error(err)
				}
				mu.Lock()
				outcomes[out]++
				mu.Unlock()
			})
		}
		close(start)
		wg.Wait()
		if outcomes[reapResumed] != 1 || outcomes[reapNone] != 3 {
			t.Fatalf("job %s: outcomes %v, want exactly one resume", id, outcomes)
		}
		if n := f.autoResumes(t, id); n != 1 {
			t.Fatalf("job %s: auto_resumes = %d, want 1", id, n)
		}
	}
}
