package services

import (
	"context"
	"log"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// scheduleProcessor is the slice of SchedulerService the worker drives. It is an
// interface so the loop can be exercised without a database.
type scheduleProcessor interface {
	ProcessDueSchedules(ctx context.Context) (int, error)
}

// SchedulerWorker is the driver loop for interrogation schedules.
//
// SchedulerService.ProcessDueSchedules had no caller anywhere in the repo: the
// API and the UI let a tenant create a cron schedule, and nothing ever swept for
// due rows, so a schedule's next_run_at simply drifted into the past and the
// interrogation never ran. This worker is that missing caller — the
// same shape as PlatformAgentWorker, so both background loops in this service
// start and stop the same way.
type SchedulerWorker struct {
	processor scheduleProcessor
	interval  time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
}

// Default sweep cadence. Cron granularity in interrogation_schedules is one
// minute (the parser is Minute|Hour|Dom|Month|Dow), so sweeping every minute is
// the finest cadence that can matter.
const defaultSchedulerInterval = time.Minute

// SchedulerWorkerEnabled reports whether the schedule sweep should run. The
// kill-switch exists so an operator can stop scheduled interrogations fleet-wide
// without editing schedules or rolling back the service.
func SchedulerWorkerEnabled() bool {
	return sharedconfig.GetEnvAsBool("INTERROGATION_SCHEDULER_ENABLED", true)
}

// SchedulerWorkerInterval is the configured sweep cadence.
func SchedulerWorkerInterval() time.Duration {
	d := sharedconfig.GetEnvAsDuration("INTERROGATION_SCHEDULER_INTERVAL", defaultSchedulerInterval)
	if d <= 0 {
		return defaultSchedulerInterval
	}
	return d
}

// NewSchedulerWorker creates a worker that sweeps due schedules on interval.
func NewSchedulerWorker(processor scheduleProcessor, interval time.Duration) *SchedulerWorker {
	if interval <= 0 {
		interval = defaultSchedulerInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &SchedulerWorker{
		processor: processor,
		interval:  interval,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
}

// Start runs the sweep loop until Stop. It blocks, so callers run it in a
// goroutine (mirrors PlatformAgentWorker.Start).
func (w *SchedulerWorker) Start() {
	defer close(w.done)
	log.Printf("[SchedulerWorker] Interrogation schedule sweep started (interval: %s)", w.interval)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.sweep()
	for {
		select {
		case <-w.ctx.Done():
			log.Println("[SchedulerWorker] Interrogation schedule sweep stopping...")
			return
		case <-ticker.C:
			w.sweep()
		}
	}
}

// Stop cancels the loop and waits for the in-flight sweep to return.
func (w *SchedulerWorker) Stop() {
	w.cancel()
	<-w.done
}

func (w *SchedulerWorker) sweep() {
	// Bound a single sweep so a wedged trigger cannot stall the loop forever.
	ctx, cancel := context.WithTimeout(w.ctx, 5*time.Minute)
	defer cancel()

	triggered, err := w.processor.ProcessDueSchedules(ctx)
	if err != nil {
		log.Printf("[SchedulerWorker] Sweep failed: %v", err)
		return
	}
	if triggered > 0 {
		log.Printf("[SchedulerWorker] Triggered %d due schedule(s)", triggered)
	}
}
