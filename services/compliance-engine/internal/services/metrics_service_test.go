package services

import (
	"errors"
	"sync"
	"testing"
)

// Exercises the metrics service under many concurrent writers and readers.
// Run with -race: this catches data races, and the GetMetrics() snapshot path
// also guards the lock-copy that returning EventMetrics by value used to
// trigger (the mutex now lives on MetricsService, not EventMetrics).
func TestMetricsService_ConcurrentAccess(t *testing.T) {
	s := NewMetricsService()
	const workers = 50

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.RecordEventPublished("asset.changed")
			s.RecordEventProcessed("asset.changed", n%2 == 0, int64(n), errors.New("boom"))
			s.RecordStateTransition("INACTIVE", "ACTIVE")
			_ = s.GetMetrics()
			_ = s.GetAverageLatency()
			_ = s.GetErrorRate()
		}(i)
	}
	wg.Wait()

	got := s.GetMetrics()
	if got.EventsProcessed != workers {
		t.Fatalf("expected %d events processed, got %d", workers, got.EventsProcessed)
	}
	if got.EventsPublished != workers {
		t.Fatalf("expected %d events published, got %d", workers, got.EventsPublished)
	}
}

// GetMetrics must return an independent snapshot: mutating the returned value's
// maps or scalars must not bleed back into the service's internal state.
func TestMetricsService_SnapshotIsIndependent(t *testing.T) {
	s := NewMetricsService()
	s.RecordEventProcessed("asset.changed", true, 5, nil)

	snap := s.GetMetrics()
	snap.EventsProcessed = 999
	snap.EventsProcessedByType["asset.changed"] = 999

	again := s.GetMetrics()
	if again.EventsProcessed != 1 {
		t.Fatalf("snapshot scalar mutation leaked into service: got EventsProcessed=%d", again.EventsProcessed)
	}
	if again.EventsProcessedByType["asset.changed"] != 1 {
		t.Fatalf("snapshot map mutation leaked into service: got %d", again.EventsProcessedByType["asset.changed"])
	}
}
