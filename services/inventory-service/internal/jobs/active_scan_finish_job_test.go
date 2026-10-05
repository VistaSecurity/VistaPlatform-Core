package jobs

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

type fakeFinisher struct {
	mu    sync.Mutex
	calls []uuid.UUID
	err   error
}

func (f *fakeFinisher) FinishActiveScans(_ context.Context, tenantID uuid.UUID) (autoscan.FinishedScans, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, tenantID)
	return autoscan.FinishedScans{}, f.err
}

func (f *fakeFinisher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newFinishJob(store activeScanFinisher, tenants ...uuid.UUID) *ActiveScanFinishJob {
	j := NewActiveScanFinishJob(store, nil)
	j.listInFlight = func() ([]uuid.UUID, error) { return tenants, nil }
	return j
}

// The tick settles every tenant with a scan in flight.
func TestFinishInFlight_SettlesEachTenantWithAScanInFlight(t *testing.T) {
	store := &fakeFinisher{}
	newFinishJob(store, uuid.New(), uuid.New()).FinishInFlight(context.Background())
	if store.count() != 2 {
		t.Fatalf("FinishActiveScans called %d times, want 2", store.count())
	}
}

// The settle is a record, not a gate: one tenant failing does not stop the next.
func TestFinishInFlight_AFailedTenantDoesNotStopTheRest(t *testing.T) {
	store := &fakeFinisher{err: errors.New("assets is locked")}
	newFinishJob(store, uuid.New(), uuid.New()).FinishInFlight(context.Background())
	if store.count() != 2 {
		t.Fatalf("FinishActiveScans called %d times, want 2 — a failed settle must not abort the pass", store.count())
	}
}

// A replica that cannot take the lock does nothing this tick.
func TestFinishInFlight_SkipsWhenAnotherReplicaHoldsTheLock(t *testing.T) {
	store := &fakeFinisher{}
	j := newFinishJob(store, uuid.New())
	j.tryLock = func(context.Context) (func(), bool, error) { return func() {}, false, nil }
	j.FinishInFlight(context.Background())
	if store.count() != 0 {
		t.Fatalf("settled %d tenants without holding the lock", store.count())
	}
}

// The lock is released when the pass ends, so the next tick can take it.
func TestFinishInFlight_ReleasesTheLock(t *testing.T) {
	released := 0
	j := newFinishJob(&fakeFinisher{}, uuid.New())
	j.tryLock = func(context.Context) (func(), bool, error) { return func() { released++ }, true, nil }
	j.FinishInFlight(context.Background())
	if released != 1 {
		t.Fatalf("lock released %d times, want 1", released)
	}
}

// Start settles on its own ticker, with no help from the automatic-scan worker.
func TestActiveScanFinishJob_StartSettlesOnItsTicker(t *testing.T) {
	store := &fakeFinisher{}
	j := newFinishJob(store, uuid.New())
	j.interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { j.Start(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for store.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return when its context was cancelled")
	}
	if store.count() == 0 {
		t.Fatal("the finish worker never settled anything — a person's Active Scan would read `scanning` for good")
	}
}

// The wiring this package exists for: with automatic scanning switched off by
// its environment flag, the automatic worker does not run, AND a person's scan
// is still settled — by the finish worker, started the way the service starts it.
func TestActiveScanFinish_SettlesWhileAutomaticScanningIsOff(t *testing.T) {
	t.Setenv(EnvAutoScanEnabled, "false")

	auto := NewAutoActiveScanJob(&fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}, &fakeDispatcher{}, nil, nil)
	autoDone := make(chan struct{})
	go func() { auto.Start(context.Background()); close(autoDone) }()
	select {
	case <-autoDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the automatic worker is still running with its flag off")
	}

	store := &fakeFinisher{}
	fin := newFinishJob(store, uuid.New())
	fin.interval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fin.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for store.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if store.count() == 0 {
		t.Fatal("with automatic scanning off, a person-initiated scan was never settled")
	}
}

// The source guard, as TestAutoActiveScan_MainStartsTheWorker: a startup line
// that stopped being executed is invisible to every other test.
func TestActiveScanFinish_MainStartsTheWorker(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatalf("reading cmd/main.go: %v", err)
	}
	body := string(src)
	for _, want := range []string{
		"jobs.NewActiveScanFinishJob(autoScanStore, bypassDB)",
		"go activeScanFinishJob.Start(ctx)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("cmd/main.go no longer contains %q — Active Scans would read `scanning` for good", want)
		}
	}
	// Started unconditionally: a top-level statement of the function, not
	// inside the automatic worker's flag or policy.
	if i := strings.Index(body, "go activeScanFinishJob.Start(ctx)"); i >= 0 {
		line := body[strings.LastIndex(body[:i], "\n")+1 : i]
		if line != "\t" {
			t.Errorf("activeScanFinishJob.Start must be started unconditionally, but it is indented %q", line)
		}
	}
}

// The automatic worker no longer carries the settle pass at all.
func TestAutoActiveScan_DoesNotSettleActiveScans(t *testing.T) {
	src, err := os.ReadFile("auto_active_scan_job.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "FinishActiveScans") {
		t.Error("auto_active_scan_job.go references FinishActiveScans — settling person-initiated scans belongs to ActiveScanFinishJob")
	}
}
