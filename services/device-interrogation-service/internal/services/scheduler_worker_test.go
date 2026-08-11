package services

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeScheduleProcessor records how many times the worker swept.
type fakeScheduleProcessor struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeScheduleProcessor) ProcessDueSchedules(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return 0, f.err
}

func (f *fakeScheduleProcessor) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// TestSchedulerWorker_SweepsOnInterval is the regression test for the missing
// driver loop: ProcessDueSchedules had zero callers, so schedules never
// fired. The worker must sweep immediately at start and then keep sweeping.
func TestSchedulerWorker_SweepsOnInterval(t *testing.T) {
	p := &fakeScheduleProcessor{}
	w := NewSchedulerWorker(p, 10*time.Millisecond)
	go w.Start()
	defer w.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.count() >= 3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("SchedulerWorker swept %d time(s) in 2s, want >= 3", p.count())
}

// TestSchedulerWorker_SweepsImmediately pins the start-up sweep: a schedule that
// is already overdue when the service boots must not wait a whole interval.
func TestSchedulerWorker_SweepsImmediately(t *testing.T) {
	p := &fakeScheduleProcessor{}
	w := NewSchedulerWorker(p, time.Hour) // interval long enough that only the initial sweep can land
	go w.Start()
	defer w.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.count() >= 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("SchedulerWorker did not sweep at start")
}

// TestSchedulerWorker_StopHaltsSweeps ensures shutdown is clean — Stop must wait
// for the loop to exit, and no sweep may land afterwards.
func TestSchedulerWorker_StopHaltsSweeps(t *testing.T) {
	p := &fakeScheduleProcessor{}
	w := NewSchedulerWorker(p, 5*time.Millisecond)
	go w.Start()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && p.count() < 2 {
		time.Sleep(2 * time.Millisecond)
	}
	w.Stop()

	after := p.count()
	time.Sleep(50 * time.Millisecond)
	if got := p.count(); got != after {
		t.Fatalf("SchedulerWorker swept %d more time(s) after Stop, want 0", got-after)
	}
}

// TestSchedulerWorker_SurvivesSweepErrors — a transient DB error must not kill
// the loop, or one blip would silently stop every tenant's schedules until the
// pod restarts.
func TestSchedulerWorker_SurvivesSweepErrors(t *testing.T) {
	p := &fakeScheduleProcessor{err: context.DeadlineExceeded}
	w := NewSchedulerWorker(p, 5*time.Millisecond)
	go w.Start()
	defer w.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.count() >= 3 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("SchedulerWorker stopped sweeping after errors (%d sweeps)", p.count())
}

// TestSchedulerWorkerInterval_RejectsNonPositive guards the config path: a
// mistyped INTERROGATION_SCHEDULER_INTERVAL must not turn into a zero-duration
// ticker (time.NewTicker panics) or a busy loop.
func TestSchedulerWorkerInterval_RejectsNonPositive(t *testing.T) {
	t.Setenv("INTERROGATION_SCHEDULER_INTERVAL", "0s")
	if got := SchedulerWorkerInterval(); got != defaultSchedulerInterval {
		t.Fatalf("SchedulerWorkerInterval() = %v, want %v", got, defaultSchedulerInterval)
	}
	if w := NewSchedulerWorker(&fakeScheduleProcessor{}, -1); w.interval != defaultSchedulerInterval {
		t.Fatalf("NewSchedulerWorker(-1).interval = %v, want %v", w.interval, defaultSchedulerInterval)
	}
}
