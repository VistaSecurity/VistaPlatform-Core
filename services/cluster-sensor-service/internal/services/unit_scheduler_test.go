package services

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// No tenant holds more than its share, the replica holds no more than its
// cap, and a tenant waiting at its own cap holds nothing of the global pool.
func TestUnitScheduler_CapsTenantAndReplica(t *testing.T) {
	s := newUnitScheduler(unitConcurrency{Global: 3, PerTenant: 2})
	var inA, inAll, peakA, peakAll atomic.Int32
	bump := func(c, peak *atomic.Int32) {
		n := c.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				return
			}
		}
	}
	var wg sync.WaitGroup
	for i := range 12 {
		tenant := "a"
		if i%3 == 0 {
			tenant = "b"
		}
		wg.Go(func() {
			release, ok := s.acquire(context.Background(), tenant, 1)
			if !ok {
				t.Error("acquire failed")
				return
			}
			if tenant == "a" {
				bump(&inA, &peakA)
			}
			bump(&inAll, &peakAll)
			time.Sleep(5 * time.Millisecond)
			if tenant == "a" {
				inA.Add(-1)
			}
			inAll.Add(-1)
			release()
		})
	}
	wg.Wait()
	if peakA.Load() > 2 || peakAll.Load() > 3 {
		t.Fatalf("peaks: tenant a %d (cap 2), replica %d (cap 3)", peakA.Load(), peakAll.Load())
	}
	g, ta := s.peaks("a")
	if g > 3 || ta > 2 || ta < 1 {
		t.Fatalf("scheduler peaks: replica %d, tenant a %d", g, ta)
	}
}

// Tenant B is not starved by tenant A sitting at its own cap: A's waiting
// requests hold no global slot.
func TestUnitScheduler_WaitingAtATenantCapHoldsNoGlobalSlot(t *testing.T) {
	s := newUnitScheduler(unitConcurrency{Global: 2, PerTenant: 1})
	relA, _ := s.acquire(context.Background(), "a", 1)
	defer relA()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = s.acquire(ctx, "a", 1) }() // waits on A's cap
	time.Sleep(20 * time.Millisecond)
	got := make(chan bool, 1)
	go func() {
		rel, ok := s.acquire(context.Background(), "b", 1)
		if ok {
			rel()
		}
		got <- ok
	}()
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("tenant b refused")
		}
	case <-time.After(time.Second):
		t.Fatal("tenant b waited behind tenant a's queued request")
	}
}

func TestUnitScheduler_AcquireHonoursCancel(t *testing.T) {
	s := newUnitScheduler(unitConcurrency{Global: 1, PerTenant: 1})
	rel, _ := s.acquire(context.Background(), "a", 1)
	defer rel()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, ok := s.acquire(ctx, "b", 1); ok {
		t.Fatal("acquired past a full replica")
	}
}

func TestUnitConcurrencyFromEnv_FailsClosedToDefaults(t *testing.T) {
	for _, tc := range []struct {
		global, perTenant string
		want              unitConcurrency
	}{
		{"", "", unitConcurrency{16, 4}},
		{"32", "8", unitConcurrency{32, 8}},
		{"0", "-1", unitConcurrency{16, 4}},
		{"lots", "999", unitConcurrency{16, 4}},
		{"2", "8", unitConcurrency{2, 2}}, // per tenant never above the replica
	} {
		t.Setenv(envMaxConcurrentUnits, tc.global)
		t.Setenv(envMaxConcurrentUnitsPerTenant, tc.perTenant)
		if got := unitConcurrencyFromEnv(); got != tc.want {
			t.Errorf("%q/%q = %+v, want %+v", tc.global, tc.perTenant, got, tc.want)
		}
	}
}

// Production builds the scheduler and detaches plan jobs; without either, a
// long scan holds the replica and the caps are never applied.
func TestNewJobProcessor_SharesUnitsAndDetachesPlanJobs(t *testing.T) {
	jp := NewJobProcessor(nil, nil, nil, nil, nil, nil)
	if jp.units == nil || !jp.detachPlanJobs {
		t.Fatalf("units %v detach %v: production must share units out and run plan jobs off the handler", jp.units, jp.detachPlanJobs)
	}
}
