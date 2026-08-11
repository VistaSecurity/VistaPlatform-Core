package services

// tenantCoalescer (W2-13): whole-tenant reconciles must debounce per tenant.
//
// A whole-tenant reconcile re-evaluates every published control against every asset, and
// it is a convergent diff — a pass that starts AFTER a change lands already covers that
// change. So running one concurrently with (or right after) another for the same tenant
// is pure waste, and a cert-heavy ingest batch used to do exactly that, once per event.

import (
	"errors"
	"sync"
	"testing"
)

// A burst of requests arriving while a tenant's reconcile is in flight must collapse into
// ONE follow-up pass, not N passes.
func TestTenantCoalescer_CollapsesBurstIntoOneFollowup(t *testing.T) {
	c := newTenantCoalescer()

	const burst = 20
	var mu sync.Mutex
	var passes, coalesced int

	// The first pass fires the burst from INSIDE the run, so every request provably
	// arrives while the key is in flight — deterministic, no sleeps.
	n, wasCoalesced, err := c.Run("tenant-a", func() error {
		mu.Lock()
		passes++
		first := passes == 1
		mu.Unlock()
		if !first {
			return nil
		}
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, co, _ := c.Run("tenant-a", func() error {
					t.Error("a coalesced request must not run its own pass")
					return nil
				})
				if co {
					mu.Lock()
					coalesced++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		return nil
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if wasCoalesced {
		t.Fatal("the first caller must run, not coalesce")
	}
	if coalesced != burst {
		t.Fatalf("coalesced %d of %d burst requests, want all of them", coalesced, burst)
	}
	// 1 original + exactly 1 follow-up that absorbs the whole burst.
	if n != 2 || passes != 2 {
		t.Fatalf("passes = %d (fn ran %d times), want 2 — the burst must collapse into a single follow-up", n, passes)
	}
}

// Different tenants must never coalesce into each other — the key is the isolation.
func TestTenantCoalescer_DoesNotCoalesceAcrossKeys(t *testing.T) {
	c := newTenantCoalescer()
	inner := 0

	_, _, err := c.Run("tenant-a", func() error {
		_, co, err := c.Run("tenant-b", func() error {
			inner++
			return nil
		})
		if err != nil {
			return err
		}
		if co {
			t.Error("tenant-b was coalesced into tenant-a's in-flight run")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if inner != 1 {
		t.Fatalf("tenant-b passes = %d, want 1", inner)
	}
}

// A sequential caller (nothing in flight) always runs — coalescing must not decay into a
// permanent suppression once a key has been used.
func TestTenantCoalescer_SequentialCallsAllRun(t *testing.T) {
	c := newTenantCoalescer()
	passes := 0
	for i := 0; i < 3; i++ {
		n, co, err := c.Run("t", func() error { passes++; return nil })
		if err != nil || co || n != 1 {
			t.Fatalf("call %d: passes=%d coalesced=%v err=%v, want 1/false/nil", i, n, co, err)
		}
	}
	if passes != 3 {
		t.Fatalf("passes = %d, want 3", passes)
	}
}

// A failing pass must surface its error and must not leave the key wedged in-flight —
// that would silently suppress every later reconcile for that tenant.
func TestTenantCoalescer_ErrorReleasesTheKey(t *testing.T) {
	c := newTenantCoalescer()
	boom := errors.New("boom")

	if _, _, err := c.Run("t", func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}

	ran := false
	if _, co, err := c.Run("t", func() error { ran = true; return nil }); err != nil || co {
		t.Fatalf("after a failed pass: coalesced=%v err=%v, want false/nil", co, err)
	}
	if !ran {
		t.Fatal("the key stayed in flight after an error — later reconciles would be dropped")
	}
}

// A nil coalescer runs inline: FindingsService values built as struct literals (tests, and
// any caller not going through the constructor) must keep working.
func TestTenantCoalescer_NilRunsInline(t *testing.T) {
	var c *tenantCoalescer
	ran := false
	n, co, err := c.Run("t", func() error { ran = true; return nil })
	if !ran || co || n != 1 || err != nil {
		t.Fatalf("nil coalescer: ran=%v passes=%d coalesced=%v err=%v", ran, n, co, err)
	}
}

// Continuous churn must not let one runner spin forever holding a JetStream message
// unacked: follow-ups are bounded, and the runner returns an error so JetStream
// redelivers the owning message. Coalesced sibling messages ACK immediately, so a nil
// return here would drop the last dirty request when no later job exists.
func TestTenantCoalescer_FollowupsAreBounded(t *testing.T) {
	c := newTenantCoalescer()
	passes := 0

	// Every pass re-dirties the key from inside, i.e. permanent churn.
	n, _, err := c.Run("t", func() error {
		passes++
		_, co, _ := c.Run("t", func() error {
			t.Error("re-entrant request must coalesce, not run")
			return nil
		})
		if !co {
			t.Error("re-entrant request was not coalesced")
		}
		return nil
	})
	if !errors.Is(err, errReconcileStillDirty) {
		t.Fatalf("err = %v, want errReconcileStillDirty", err)
	}
	if n != maxCoalescedFollowups+1 {
		t.Fatalf("passes = %d, want %d (1 original + %d bounded follow-ups)", n, maxCoalescedFollowups+1, maxCoalescedFollowups)
	}
	if passes != n {
		t.Fatalf("fn ran %d times but Run reported %d passes", passes, n)
	}

	recoveryPasses := 0
	n, co, err := c.Run("t", func() error {
		recoveryPasses++
		return nil
	})
	if err != nil || co || n != 1 || recoveryPasses != 1 {
		t.Fatalf("redelivery recovery: passes=%d fn=%d coalesced=%v err=%v, want one normal pass", n, recoveryPasses, co, err)
	}
}
