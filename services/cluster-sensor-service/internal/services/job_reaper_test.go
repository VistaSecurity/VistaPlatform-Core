package services

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The lease ticker writes the database heartbeat only for a job this replica
// is running. A delivery that lost the claim (the job runs elsewhere) must not
// vouch for it: if that owner died, the reaper has to see the row go stale.
func TestKeepLeaseAlive_HeartbeatsOnlyAJobThisReplicaRuns(t *testing.T) {
	svc := &DiscoveryService{}
	var touches atomic.Int32
	jp := &JobProcessor{discoveryService: svc, leaseInterval: 5 * time.Millisecond,
		touchJob: func(string) (bool, error) { touches.Add(1); return true, nil }}

	stop := jp.keepLeaseAlive(&countingLease{}, "elsewhere")
	time.Sleep(50 * time.Millisecond)
	stop()
	if n := touches.Load(); n != 0 {
		t.Fatalf("heartbeat written %d times for a job another replica owns", n)
	}

	_, release := svc.runningJobs().start(context.Background(), "mine")
	defer release()
	stop = jp.keepLeaseAlive(&countingLease{}, "mine")
	deadline := time.Now().Add(2 * time.Second)
	for touches.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stop()
	if n := touches.Load(); n < 3 {
		t.Fatalf("heartbeat written %d times for a job this replica runs, want at least 3", n)
	}
}

// The lease must survive several missed heartbeats, not one.
func TestJobHeartbeatLeaseToleratesMissedBeats(t *testing.T) {
	if jobHeartbeatLease < 4*jobLeaseInterval {
		t.Fatalf("lease %s tolerates fewer than 3 missed heartbeats at %s", jobHeartbeatLease, jobLeaseInterval)
	}
}
