package processor

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The kill switch. Anything but the literal "false" keeps the sweep on — an
// operator who wants it off has to say so explicitly.
func TestRetentionKillSwitch(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"", "enabled by default (unset)"},
		{"true", "enabled"},
		{"garbage", "enabled (unrecognized value is not \"false\")"},
		{"false", "disabled"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			t.Setenv("SENSOR_DISCOVERY_RETENTION_ENABLED", tc.env)
			j := NewRetentionSweepJob(nil)
			wantEnabled := tc.env != "false"
			if j.enabled != wantEnabled {
				t.Fatalf("SENSOR_DISCOVERY_RETENTION_ENABLED=%q: enabled=%v, want %v", tc.env, j.enabled, wantEnabled)
			}
		})
	}
}

// A disabled sweep must not tick at all — Start returns immediately rather
// than looping with the delete function neutered, which is what a "disabled
// but still running" implementation would look like from the outside.
func TestRetentionSweep_DisabledNeverDeletes(t *testing.T) {
	t.Setenv("SENSOR_DISCOVERY_RETENTION_ENABLED", "false")
	j := NewRetentionSweepJob(nil)
	calls := 0
	j.delete = func(context.Context, time.Time) (int, error) { calls++; return 0, nil }

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Start would block forever on a live ticker if it ran at all.
	j.Start(ctx)

	if calls != 0 {
		t.Fatalf("delete was called %d time(s) while the sweep is disabled", calls)
	}
}

// The retention window. Default 168h (7 days); an explicit, valid, positive
// value overrides it; garbage falls back to the default rather than sweeping
// with an unintended window (0h would delete everything; a negative would
// delete nothing found, silently).
func TestRetentionWindowFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		want time.Duration
	}{
		{"unset default", "", 168 * time.Hour},
		{"explicit override", "24", 24 * time.Hour},
		{"non-numeric falls back to default", "not-a-number", 168 * time.Hour},
		{"zero falls back to default", "0", 168 * time.Hour},
		{"negative falls back to default", "-5", 168 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SENSOR_DISCOVERY_RETENTION_HOURS", tc.env)
			if got := retentionWindowFromEnv(); got != tc.want {
				t.Errorf("SENSOR_DISCOVERY_RETENTION_HOURS=%q: window=%v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

// The batch loop must keep deleting while a batch comes back FULL, and stop
// as soon as one comes back short — which is also what makes an unbounded
// backlog safe: no single statement, and no single Sweep() call, touches more
// than one batch's worth without yielding back to the loop.
//
// Mutation that proves it: change `if n < j.batchSize` to `if n == 0` — this
// test's "stops after a full batch" case would loop forever on a store that
// always returns exactly one batchSize's worth (this test uses a tiny
// batchSize and a fixed total, so that mutation would hang the test, not
// merely miscount).
func TestRetentionSweep_LoopsUntilAShortBatch(t *testing.T) {
	j := NewRetentionSweepJob(nil)
	j.batchSize = 3
	j.tryLock = func(context.Context) (func(), bool, error) { return func() {}, true, nil }

	// 3, 3, 2 — two full batches then a short one. The loop must run exactly
	// three times and total 8.
	sizes := []int{3, 3, 2}
	calls := 0
	j.delete = func(context.Context, time.Time) (int, error) {
		n := sizes[calls]
		calls++
		return n, nil
	}

	j.Sweep(context.Background())

	if calls != 3 {
		t.Fatalf("delete was called %d time(s), want 3 (two full batches + one short)", calls)
	}
}

// A delete error stops the sweep immediately rather than looping forever
// (or silently swallowing partial progress) — the same "fail loudly, keep
// what already committed" shape the rest of this service uses.
func TestRetentionSweep_StopsOnError(t *testing.T) {
	j := NewRetentionSweepJob(nil)
	j.batchSize = 3
	j.tryLock = func(context.Context) (func(), bool, error) { return func() {}, true, nil }

	calls := 0
	j.delete = func(context.Context, time.Time) (int, error) {
		calls++
		if calls == 2 {
			return 0, errors.New("connection reset")
		}
		return 3, nil
	}

	j.Sweep(context.Background()) // Must return, not loop or panic.

	if calls != 2 {
		t.Fatalf("delete was called %d time(s), want exactly 2 (stop at the error)", calls)
	}
}

// Another replica holding the lock means this pass does nothing at all.
func TestRetentionSweep_SkipsWhenAnotherReplicaHoldsTheLock(t *testing.T) {
	j := NewRetentionSweepJob(nil)
	j.tryLock = func(context.Context) (func(), bool, error) { return nil, false, nil }
	calls := 0
	j.delete = func(context.Context, time.Time) (int, error) { calls++; return 0, nil }

	j.Sweep(context.Background())

	if calls != 0 {
		t.Fatalf("delete was called %d time(s) while another replica held the sweep lock", calls)
	}
}

// A lock error is not a licence to sweep anyway.
func TestRetentionSweep_SkipsWhenTheLockCannotBeTaken(t *testing.T) {
	j := NewRetentionSweepJob(nil)
	j.tryLock = func(context.Context) (func(), bool, error) { return nil, false, errors.New("no connection") }
	calls := 0
	j.delete = func(context.Context, time.Time) (int, error) { calls++; return 0, nil }

	j.Sweep(context.Background())

	if calls != 0 {
		t.Fatalf("delete was called %d time(s) without holding the sweep lock", calls)
	}
}

// The lock must be released after the pass, or the next tick on this pod
// finds it held forever.
func TestRetentionSweep_ReleasesTheLockAfterThePass(t *testing.T) {
	j := NewRetentionSweepJob(nil)
	released := false
	j.tryLock = func(context.Context) (func(), bool, error) {
		return func() { released = true }, true, nil
	}
	j.delete = func(context.Context, time.Time) (int, error) { return 0, nil }

	j.Sweep(context.Background())

	if !released {
		t.Fatal("the sweep lock was not released")
	}
}

// deleteBatch with a nil bypassDB (a single-process context with nothing to
// sweep against) must return cleanly rather than panic on a nil pointer
// deref — the same seam AutoActiveScanJob's pgTryLock uses for the same
// reason.
func TestRetentionSweep_NilBypassDBIsANoOp(t *testing.T) {
	j := NewRetentionSweepJob(nil)
	n, err := j.deleteBatch(context.Background(), time.Now())
	if err != nil || n != 0 {
		t.Fatalf("deleteBatch(nil bypassDB) = (%d, %v), want (0, nil)", n, err)
	}
	release, ok, err := j.pgTryLock(context.Background())
	if err != nil || !ok {
		t.Fatalf("pgTryLock(nil bypassDB) = (_, %v, %v), want (_, true, nil)", ok, err)
	}
	release() // Must not panic.
}

// The source guard: the sweep is constructed AND STARTED from main, and its
// kill switch and window exist where the pod's environment is actually
// assembled. Nothing else in this repository can observe a startup line that
// stopped being executed.
func TestRetentionSweep_MainStartsTheWorker(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatalf("reading cmd/main.go: %v", err)
	}
	main := string(src)

	for _, want := range []string{
		"processor.NewRetentionSweepJob(bypassDB)",
		"retentionSweep.Start(retentionCtx)",
		// ...and shutdown actually stops it, not just the poller.
		"cancelRetention()",
	} {
		if !strings.Contains(main, want) {
			t.Errorf("cmd/main.go no longer contains %q — the sweep is built and never reached (or never stopped)", want)
		}
	}
}

// A kill switch that does not exist in the pod is not a kill switch. A
// backend's environment is the shared ConfigMap plus its chart `extraEnv`
// list; without an entry the variable does not exist, os.Getenv returns "",
// and an unset value means ON — the switch would be documented and
// unreachable.
func TestRetentionSweep_TheKillSwitchExistsWhereItIsRead(t *testing.T) {
	read := func(t *testing.T, rel string) string {
		t.Helper()
		b, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		return string(b)
	}

	wanted := []string{EnvRetentionEnabled, EnvRetentionHours}

	values := read(t, "../../../../charts/vistaplatform/values.yaml")
	// Scoped to this service's block: the variable existing under SOME other
	// backend would satisfy a whole-file search while doing nothing for this
	// pod.
	start := strings.Index(values, "\n  discovery-processor-service:")
	if start < 0 {
		t.Fatal("values.yaml has no discovery-processor-service backend block")
	}
	rest := values[start+1:]
	end := strings.Index(rest, "\n  mcp-service:")
	if end < 0 {
		t.Fatal("could not find the end of the discovery-processor-service block in values.yaml")
	}
	block := rest[:end]
	for _, name := range wanted {
		if !strings.Contains(block, name) {
			t.Errorf("charts/vistaplatform/values.yaml: %s is missing from backends.discovery-processor-service.extraEnv — it does not exist in the pod, so the code's os.Getenv returns \"\" and the switch is unreachable", name)
		}
	}

	env := read(t, "../../../../env.example")
	for _, name := range wanted {
		if !strings.Contains(env, name) {
			t.Errorf("env.example: %s is undocumented, so a compose operator cannot find it", name)
		}
	}
}
