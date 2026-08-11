package subscribers

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// newTestSubscriber builds a LifecycleSubscriber wired only for the debounce
// path (no NATS / HealthService), capturing recalcs in a counter.
func newTestSubscriber(window time.Duration, recalc func(uuid.UUID)) *LifecycleSubscriber {
	s := &LifecycleSubscriber{
		debounceWindow: window,
		pending:        make(map[uuid.UUID]*time.Timer),
	}
	s.recalcFn = recalc
	return s
}

// TestScheduleRecalc_CoalescesBurst verifies that a burst of events for the
// same tenant collapses into a single recalc — the regression that caused 236
// auth-service calls in one minute during demo seeding.
func TestScheduleRecalc_CoalescesBurst(t *testing.T) {
	var calls int64
	tenant := uuid.New()
	s := newTestSubscriber(40*time.Millisecond, func(id uuid.UUID) {
		if id != tenant {
			t.Errorf("recalc for unexpected tenant %s", id)
		}
		atomic.AddInt64(&calls, 1)
	})

	// 200 rapid events, as a seeding burst would produce.
	for i := 0; i < 200; i++ {
		s.scheduleRecalc(tenant)
		time.Sleep(time.Millisecond)
	}

	// Wait past the debounce window for the coalesced recalc to fire.
	time.Sleep(120 * time.Millisecond)

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("expected exactly 1 coalesced recalc, got %d", got)
	}
}

// TestScheduleRecalc_PerTenant verifies each distinct tenant gets its own
// recalc (coalescing is keyed by tenant, not global).
func TestScheduleRecalc_PerTenant(t *testing.T) {
	var mu sync.Mutex
	seen := map[uuid.UUID]int{}
	s := newTestSubscriber(30*time.Millisecond, func(id uuid.UUID) {
		mu.Lock()
		seen[id]++
		mu.Unlock()
	})

	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for _, tn := range tenants {
		s.scheduleRecalc(tn)
		s.scheduleRecalc(tn) // duplicate within window — should coalesce
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(tenants) {
		t.Fatalf("expected %d tenants recalculated, got %d", len(tenants), len(seen))
	}
	for tn, n := range seen {
		if n != 1 {
			t.Errorf("tenant %s recalculated %d times, want 1", tn, n)
		}
	}
}

// TestScheduleRecalc_SeparateBurstsAfterFire verifies that events arriving
// after a recalc has already fired schedule a fresh recalc (we don't
// permanently suppress a tenant).
func TestScheduleRecalc_SeparateBurstsAfterFire(t *testing.T) {
	var calls int64
	tenant := uuid.New()
	s := newTestSubscriber(20*time.Millisecond, func(id uuid.UUID) {
		atomic.AddInt64(&calls, 1)
	})

	s.scheduleRecalc(tenant)
	time.Sleep(60 * time.Millisecond) // let the first recalc fire
	s.scheduleRecalc(tenant)
	time.Sleep(60 * time.Millisecond) // let the second recalc fire

	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("expected 2 recalcs across two separated bursts, got %d", got)
	}
}
