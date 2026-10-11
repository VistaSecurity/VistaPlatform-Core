package jobs

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeBackfiller struct {
	unevaluated map[uuid.UUID]int
	incomplete  map[uuid.UUID]int
	limits      []int
}

func (f *fakeBackfiller) RecomputeUnevaluated(_ context.Context, t uuid.UUID, limit int) (int, error) {
	f.unevaluated[t]++
	f.limits = append(f.limits, limit)
	return 0, nil
}

func (f *fakeBackfiller) RetryIncomplete(_ context.Context, t uuid.UUID, limit int) (int, error) {
	f.incomplete[t]++
	f.limits = append(f.limits, limit)
	return 0, nil
}

// Every pass evaluates never-evaluated certificates; incomplete chains are
// retried at most once per 24 hours per tenant; both halves are bounded.
func TestCertTrustBackfill_RetriesIncompleteOncePerDay(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	f := &fakeBackfiller{unevaluated: map[uuid.UUID]int{}, incomplete: map[uuid.UUID]int{}}
	clock := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	last := map[uuid.UUID]time.Time{}

	for i := 0; i < 4; i++ { // four 6-hour ticks = 18 hours
		backfillTenants(context.Background(), []uuid.UUID{a, b}, f, last, now)
		clock = clock.Add(6 * time.Hour)
	}
	if f.unevaluated[a] != 4 || f.unevaluated[b] != 4 {
		t.Errorf("unevaluated passes = %d/%d, want 4/4 (every tick)", f.unevaluated[a], f.unevaluated[b])
	}
	if f.incomplete[a] != 1 || f.incomplete[b] != 1 {
		t.Errorf("incomplete retries in 18h = %d/%d, want 1/1", f.incomplete[a], f.incomplete[b])
	}
	backfillTenants(context.Background(), []uuid.UUID{a, b}, f, last, now) // t = 24h
	if f.incomplete[a] != 2 {
		t.Errorf("incomplete retries after 24h = %d, want 2", f.incomplete[a])
	}
	for _, l := range f.limits {
		if l != certTrustBackfillPerTenant {
			t.Fatalf("limit %d, want %d", l, certTrustBackfillPerTenant)
		}
	}
}

func TestCertTrustBackfillEnabled(t *testing.T) {
	t.Setenv("CERT_TRUST_BACKFILL_ENABLED", "")
	if !CertTrustBackfillEnabled() {
		t.Error("unset must mean on")
	}
	t.Setenv("CERT_TRUST_BACKFILL_ENABLED", "false")
	if CertTrustBackfillEnabled() {
		t.Error("false must turn it off")
	}
}

// A backfill nobody starts leaves every pre-existing certificate "not yet
// evaluated" for ever.
func TestCertTrustBackfill_MainStartsTheWorker(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatalf("reading cmd/main.go: %v", err)
	}
	want := "go jobs.StartCertTrustBackfillWorker(ctx, bypassDB, jobs.CertTrustBackfillTenants, trustEvaluator)"
	if !strings.Contains(string(src), want) {
		t.Errorf("cmd/main.go no longer contains %q — the trust backfill is built and never run", want)
	}
	for _, k := range []int64{sweepAdvisoryLockKey, activeScanFinishLockKey, ouiVendorBackfillLockKey, classFloorSweepLockKey} {
		if k == certTrustBackfillLockKey {
			t.Error("the trust backfill shares a sibling's advisory lock key")
		}
	}
}
