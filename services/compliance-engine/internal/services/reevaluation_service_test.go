package services

// Pure-logic tests for the cooldown arithmetic (no database). The persistence and
// concurrency behaviour is proven in reevaluation_integration_test.go.

import (
	"testing"
	"time"
)

func TestReevaluationState_FromLastRun(t *testing.T) {
	svc := &ReevaluationService{cooldown: time.Hour}
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

	t.Run("never run", func(t *testing.T) {
		st := svc.stateFrom(nil, now)
		if !st.Allowed {
			t.Fatal("a tenant that never ran one must be allowed")
		}
		if st.NextAllowedAt != nil {
			t.Fatal("next_allowed_at must be nil exactly when allowed")
		}
	})

	t.Run("inside the window", func(t *testing.T) {
		last := now.Add(-30 * time.Minute)
		st := svc.stateFrom(&last, now)
		if st.Allowed {
			t.Fatal("30 minutes into a 1h cooldown must not be allowed")
		}
		if st.NextAllowedAt == nil || !st.NextAllowedAt.Equal(last.Add(time.Hour)) {
			t.Fatalf("next_allowed_at = %v, want %v", st.NextAllowedAt, last.Add(time.Hour))
		}
		if got := st.RetryAfter(now); got != 1800 {
			t.Fatalf("RetryAfter = %d, want 1800", got)
		}
	})

	// The boundary is inclusive: at exactly one hour the next run is allowed. If
	// this flips, the UI's "Available in 0s" state becomes permanently unreachable
	// and the button never re-enables without a refresh.
	t.Run("exactly at the boundary", func(t *testing.T) {
		last := now.Add(-time.Hour)
		st := svc.stateFrom(&last, now)
		if !st.Allowed {
			t.Fatal("at exactly the cooldown boundary the next run must be allowed")
		}
		if got := st.RetryAfter(now); got != 0 {
			t.Fatalf("RetryAfter = %d, want 0 when allowed", got)
		}
	})

	// Rounded UP: a 0 would render as "available now" while the server still
	// refuses, which is the disabled-button-that-403s defect in miniature.
	t.Run("sub-second remainder rounds up", func(t *testing.T) {
		last := now.Add(-time.Hour).Add(500 * time.Millisecond)
		st := svc.stateFrom(&last, now)
		if st.Allowed {
			t.Fatal("half a second short of the boundary must still be blocked")
		}
		if got := st.RetryAfter(now); got != 1 {
			t.Fatalf("RetryAfter = %d, want 1 (rounded up, never 0 while blocked)", got)
		}
	})
}

func TestReevaluationService_DefaultCooldownIsOneHour(t *testing.T) {
	// Owner decision: 1 hour, per tenant. Pinned so a "tuning" edit is a visible
	// test change rather than a silent product change.
	if DefaultReevaluationCooldown != time.Hour {
		t.Fatalf("DefaultReevaluationCooldown = %v, want 1h", DefaultReevaluationCooldown)
	}
}
