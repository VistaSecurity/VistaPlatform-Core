package services

// The parts of the job lifecycle that need no database ( H1/H3). The
// claim, the status guard and cancel are pinned against a real Postgres in
// job_lifecycle_integration_test.go.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// Progress is the share of targets the scanner is finished with — never a
// number derived from the status alone (it used to be 0 / 50 / 100).
func TestTargetProgress(t *testing.T) {
	cases := []struct {
		name   string
		counts models.JobTargetCounts
		status string
		want   int
	}{
		{"nothing done yet", models.JobTargetCounts{Total: 4, Pending: 3, Running: 1}, "running", 0},
		{"one of three", models.JobTargetCounts{Total: 3, Completed: 1, Running: 1, Pending: 1}, "running", 33},
		{"two of three floors, never rounds up", models.JobTargetCounts{Total: 3, Completed: 2, Running: 1}, "running", 66},
		{"a refused target is finished too", models.JobTargetCounts{Total: 4, Completed: 1, Failed: 1, Pending: 2}, "running", 50},
		{"all done", models.JobTargetCounts{Total: 4, Completed: 3, Failed: 1}, "completed", 100},
		// A running job is not halfway because it is running.
		{"running with nothing finished is 0, not 50", models.JobTargetCounts{Total: 1, Running: 1}, "running", 0},
		// A cancelled target was never reached: cancelling after one of ten
		// targets is 10%, not "done".
		{"cancelled targets are not progress", models.JobTargetCounts{Total: 10, Completed: 1, Cancelled: 9}, "cancelled", 10},
		// No target rows: nothing to count. Completed reads 100, anything else 0.
		{"no targets, completed", models.JobTargetCounts{}, "completed", 100},
		{"no targets, running", models.JobTargetCounts{}, "running", 0},
		{"no targets, queued", models.JobTargetCounts{}, "queued", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TargetProgress(tc.counts, tc.status); got != tc.want {
				t.Fatalf("TargetProgress(%+v, %q) = %d, want %d", tc.counts, tc.status, got, tc.want)
			}
		})
	}
}

// countingLease stands in for a *nats.Msg and counts InProgress calls.
type countingLease struct{ beats atomic.Int32 }

func (l *countingLease) InProgress(...nats.AckOpt) error {
	l.beats.Add(1)
	return nil
}

// The lease is renewed on its interval while the job runs and not after the
// stop func returns — a beat after the ack would be an error at best.
func TestKeepLeaseAlive_BeatsWhileRunningAndStopsAfter(t *testing.T) {
	jp := &JobProcessor{leaseInterval: 5 * time.Millisecond}
	lease := &countingLease{}
	stop := jp.keepLeaseAlive(lease, "job-1")
	deadline := time.Now().Add(2 * time.Second)
	for lease.beats.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stop()
	beats := lease.beats.Load()
	if beats < 3 {
		t.Fatalf("lease renewed %d times in 2s at a 5ms interval, want at least 3", beats)
	}
	time.Sleep(30 * time.Millisecond)
	if after := lease.beats.Load(); after != beats {
		t.Fatalf("lease renewed %d more times after stop", after-beats)
	}
}

// The heartbeat must sit well inside AckWait, or the broker redelivers a live
// job between beats.
func TestJobLeaseIntervalIsWellUnderAckWait(t *testing.T) {
	if jobLeaseInterval*3 > jobAckWait {
		t.Fatalf("lease interval %s is not well under AckWait %s (want at least 3 beats per window)", jobLeaseInterval, jobAckWait)
	}
}

// A cancel reaches exactly the job it names, with the cause the processor
// reads as "cancelled" rather than "shutting down".
func TestRunningJobRegistry_CancelReachesTheNamedJobOnly(t *testing.T) {
	svc := &DiscoveryService{}
	ctxA, releaseA := svc.runningJobs().start(context.Background(), "a")
	defer releaseA()
	ctxB, releaseB := svc.runningJobs().start(context.Background(), "b")
	defer releaseB()

	if !svc.runningJobs().cancel("a") {
		t.Fatal("cancel(a) found no running job")
	}
	if !errors.Is(stopReason(ctxA), errJobNoLongerRunning) {
		t.Fatalf("job a stop reason = %v, want errJobNoLongerRunning", stopReason(ctxA))
	}
	if stopReason(ctxB) != nil {
		t.Fatalf("cancelling a stopped b: %v", stopReason(ctxB))
	}
	if svc.runningJobs().cancel("c") {
		t.Fatal("cancel of a job not running here reported success")
	}
}

// Shutdown is told apart from a cancel: a stopping processor hands the job
// back instead of leaving it cancelled.
func TestStopReason_ShutdownIsNotACancel(t *testing.T) {
	parent, stop := context.WithCancelCause(context.Background())
	ctx, release := (&DiscoveryService{}).runningJobs().start(parent, "a")
	defer release()
	stop(errProcessorStopping)
	if got := stopReason(ctx); !errors.Is(got, errProcessorStopping) || errors.Is(got, errJobNoLongerRunning) {
		t.Fatalf("stopReason after shutdown = %v, want errProcessorStopping only", got)
	}
}
