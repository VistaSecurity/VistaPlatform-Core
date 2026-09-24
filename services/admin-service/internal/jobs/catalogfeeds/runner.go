package catalogfeeds

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
)

// Feed is one mirror source. Sync is handed the stored cursor and returns the
// next one; it never writes catalog_feed_state itself, so "the cursor only
// advances on success" is one rule in one place (SQLStore.MarkResult) rather
// than three implementations of it.
type Feed interface {
	Name() string
	Sync(ctx context.Context, store Store, cursor string) (SyncResult, error)
}

// logger is the package's log sink, named so the feeds can report a countable
// coverage gap without importing a logging framework.
var logger = log.New(log.Writer(), "[catalogfeeds] ", log.LstdFlags)

func osvLogf(format string, args ...any) { logger.Printf(format, args...) }

// Config is the runner's environment-derived settings.
type Config struct {
	// Enabled is the kill switch (CATALOG_FEEDS_ENABLED, default true). When
	// false nothing is scheduled AND the manual trigger refuses, so an
	// operator who turned the feeds off does not find them running anyway
	// because someone clicked a button.
	Enabled bool
	// Interval between scheduled passes (CATALOG_FEEDS_INTERVAL, default 24h).
	// Daily is the cadence endoflife.date's data changes at and well inside
	// what NVD's rate limits tolerate.
	Interval time.Duration
	// StartupDelay staggers the first pass after boot so a rolling restart of
	// N replicas does not fire N simultaneous passes at NVD.
	StartupDelay time.Duration

	NVDAPIKey     string
	OSVEcosystems []string
	// SpoolDir is where downloaded archives are written before they are read
	// (CATALOG_FEEDS_SPOOL_DIR; "" = the OS temp dir). The chart mounts a
	// size-limited scratch volume there, sized for the OSV archive cap.
	SpoolDir string
}

// LoadConfig reads the runner's settings from the environment.
func LoadConfig() Config {
	eco := []string{}
	for _, part := range strings.Split(sharedconfig.GetEnv("OSV_ECOSYSTEMS", ""), ",") {
		if p := strings.TrimSpace(part); p != "" {
			eco = append(eco, p)
		}
	}
	if len(eco) == 0 {
		eco = DefaultOSVEcosystems
	}
	return Config{
		Enabled:       sharedconfig.GetEnvAsBool("CATALOG_FEEDS_ENABLED", true),
		Interval:      sharedconfig.GetEnvAsDuration("CATALOG_FEEDS_INTERVAL", 24*time.Hour),
		StartupDelay:  sharedconfig.GetEnvAsDuration("CATALOG_FEEDS_STARTUP_DELAY", 2*time.Minute),
		NVDAPIKey:     sharedconfig.GetEnv("NVD_API_KEY", ""),
		OSVEcosystems: eco,
		SpoolDir:      strings.TrimSpace(sharedconfig.GetEnv("CATALOG_FEEDS_SPOOL_DIR", "")),
	}
}

// Runner owns the scheduled passes and the manual trigger.
type Runner struct {
	cfg   Config
	store Store
	db    *sql.DB
	feeds map[string]Feed

	mu       sync.Mutex
	inFlight map[string]bool

	// runCtx is the runner's own lifetime. A MANUAL sync descends from it
	// rather than from the HTTP request (which gin cancels the instant the
	// handler answers 202) or from a bare Background (which Stop could not
	// reach, so a shutdown would wait out the whole run budget).
	runCtx    context.Context
	runCancel context.CancelFunc

	// schedCancel stops the scheduled loop. Separate from runCancel only
	// because Start's caller supplies the parent context for the schedule.
	schedCancel context.CancelFunc

	// followUp is work to run after a full scheduled pass — today, the
	// Enricher seam's gap pass (ADR-0008, workstream 4.5b). A plain func rather
	// than an interface because this package must not learn what the follow-up
	// IS: the mirrors fill the catalogues, and what reads the holes they leave
	// is the enricher's business, wired from outside both.
	followUp func(ctx context.Context)

	wg sync.WaitGroup
}

// NewRunner wires the three production feeds. EOL and NVD share one HTTP
// client; OSV gets its own with a longer timeout, because a Client.Timeout
// covers reading the whole body and OSV's bulk archives are up to the 2 GiB
// cap — a cap the per-request timeout would otherwise enforce first.
func NewRunner(cfg Config, store Store, db *sql.DB) *Runner {
	client := newFeedHTTPClient()
	osv := NewOSVFeed(newOSVHTTPClient(), cfg.OSVEcosystems)
	osv.SpoolDir = cfg.SpoolDir
	return NewRunnerWithFeeds(cfg, store, db, []Feed{
		NewEOLFeed(client),
		NewNVDFeed(client, cfg.NVDAPIKey),
		osv,
	})
}

// NewRunnerWithFeeds is the injectable constructor the tests use.
func NewRunnerWithFeeds(cfg Config, store Store, db *sql.DB, feeds []Feed) *Runner {
	byName := make(map[string]Feed, len(feeds))
	for _, f := range feeds {
		byName[f.Name()] = f
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	return &Runner{
		cfg: cfg, store: store, db: db, feeds: byName, inFlight: map[string]bool{},
		runCtx: runCtx, runCancel: runCancel,
	}
}

// Enabled reports the kill switch, for the status endpoint.
func (r *Runner) Enabled() bool { return r.cfg.Enabled }

// Interval reports the scheduled cadence, for the status endpoint.
func (r *Runner) Interval() time.Duration { return r.cfg.Interval }

// Start begins the scheduled passes. A no-op when the kill switch is off —
// with a log line, because "the feeds are not running" must be visible in the
// pod's output rather than inferred from a catalogue that never grows.
func (r *Runner) Start(ctx context.Context) {
	if !r.cfg.Enabled {
		logger.Printf("catalogue feeds are DISABLED (CATALOG_FEEDS_ENABLED=false); no scheduled passes, manual sync refused")
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	r.schedCancel = cancel
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		logger.Printf("catalogue feeds scheduled every %s (first pass in %s): %s",
			r.cfg.Interval, r.cfg.StartupDelay, strings.Join(FeedNames, ", "))

		select {
		case <-ctx.Done():
			return
		case <-time.After(r.cfg.StartupDelay):
		}
		r.runAll(ctx)

		ticker := time.NewTicker(r.cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Printf("stopping catalogue feed runner")
				return
			case <-ticker.C:
				r.runAll(ctx)
			}
		}
	}()
}

// Stop cancels the scheduler AND any in-flight manual run, then waits. Both
// cancels matter: without the second, a shutdown during a manually triggered
// pass would block until that pass used up its whole budget.
func (r *Runner) Stop() {
	if r.schedCancel != nil {
		r.schedCancel()
	}
	if r.runCancel != nil {
		r.runCancel()
	}
	r.wg.Wait()
}

// SetFollowUp registers work to run after each full scheduled pass.
//
// Ordering is the whole reason it exists: the follow-up is the catalogue
// enricher's gap pass, and a gap the endoflife.date mirror has just filled is
// not one a model should be asked about. Running the mirrors first costs
// nothing and removes that class of wasted call entirely.
//
// Call before Start. A nil f clears it.
func (r *Runner) SetFollowUp(f func(ctx context.Context)) { r.followUp = f }

func (r *Runner) runAll(ctx context.Context) {
	for _, name := range FeedNames {
		if err := ctx.Err(); err != nil {
			return
		}
		r.runOne(ctx, name)
	}
	if r.followUp != nil && ctx.Err() == nil {
		r.followUpRecovering(ctx)
	}
}

// followUpRecovering runs the follow-up and turns a panic into a log line.
//
// Same reasoning as syncRecovering: these runs are goroutines, so an
// unrecovered panic in one takes the whole admin-service process with it — the
// console, every admin route, and the feeds. The follow-up's input is a model's
// answer, whose shape nobody here controls, which is if anything a stronger
// case than a fetched document.
func (r *Runner) followUpRecovering(ctx context.Context) {
	defer func() {
		if p := recover(); p != nil {
			logger.Printf("post-pass follow-up PANICKED (recovered): %v\n%s", p, debug.Stack())
		}
	}()
	r.followUp(ctx)
}

// SyncNow triggers one feed out of band and returns immediately; the run
// continues in the background and its outcome lands in catalog_feed_state,
// which is what the console polls.
//
// Returns ErrFeedsDisabled / ErrFeedUnknown / ErrFeedBusy so the handler can
// map each to its own status rather than flattening three different situations
// into one 500.
func (r *Runner) SyncNow(feed string) error {
	if !r.cfg.Enabled {
		return ErrFeedsDisabled
	}
	if _, ok := r.feeds[feed]; !ok {
		return ErrFeedUnknown
	}
	r.mu.Lock()
	if r.inFlight[feed] {
		r.mu.Unlock()
		return ErrFeedBusy
	}
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		// Detached from the request — an HTTP handler's context is cancelled
		// the moment it responds, and a mirror pass outlives its trigger by
		// minutes — but NOT from the runner, so Stop() still ends it. runOne
		// applies the per-run budget.
		r.runOne(r.runCtx, feed)
	}()
	return nil
}

// runOne executes a single feed, holding both the in-process flag and the
// cross-replica advisory lock, and recording the outcome either way.
func (r *Runner) runOne(ctx context.Context, name string) {
	feed, ok := r.feeds[name]
	if !ok {
		return
	}

	r.mu.Lock()
	if r.inFlight[name] {
		r.mu.Unlock()
		return
	}
	r.inFlight[name] = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inFlight, name)
		r.mu.Unlock()
	}()

	// Cross-replica exclusion. Skipped (with a log line) when the lock is held
	// elsewhere — not an error: the feed IS running, just not here.
	if r.db != nil {
		release, got, err := TryLock(ctx, r.db, name)
		if err != nil {
			logger.Printf("feed %s: could not take the run lock: %v", name, err)
			return
		}
		if !got {
			logger.Printf("feed %s: another replica is running it; skipping this pass", name)
			return
		}
		defer release()
	}

	// One pass gets a whole-run budget of its own, distinct from the
	// per-request timeout. See feedRunTimeout.
	ctx, cancelRun := context.WithTimeout(ctx, feedRunTimeout)
	defer cancelRun()

	states, err := r.store.FeedStates(ctx)
	if err != nil {
		logger.Printf("feed %s: could not read feed state: %v", name, err)
		return
	}
	cursor := ""
	for _, st := range states {
		if st.Feed == name && st.Cursor != nil {
			cursor = *st.Cursor
		}
	}

	if err := r.store.MarkRunning(ctx, name); err != nil {
		logger.Printf("feed %s: could not mark running: %v", name, err)
		// Not fatal — the run is still worth doing; the console just shows the
		// previous status until it finishes.
	}

	started := time.Now()
	res, runErr := r.syncRecovering(ctx, feed, cursor)
	if runErr != nil {
		logger.Printf("feed %s FAILED after %s (%d rows written): %v", name, time.Since(started).Round(time.Second), res.Rows, runErr)
	} else {
		logger.Printf("feed %s ok in %s: %d rows", name, time.Since(started).Round(time.Second), res.Rows)
	}

	// Recorded with a context that outlives a cancelled run, so a shutdown
	// mid-pass still leaves the operator an explanation rather than a row stuck
	// on 'running' forever.
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := r.store.MarkResult(recordCtx, name, res, runErr); err != nil {
		logger.Printf("feed %s: could not record result: %v", name, err)
	}
}

// syncRecovering runs a feed and turns a panic into that feed's error.
//
// "A feed error is recorded, never fatal" is this package's first stated rule,
// and a panic is the one error that would break it: these runs are goroutines,
// so an unrecovered panic in one takes the whole admin-service process with it —
// the console, every other admin route, the other two feeds. The input is
// documents fetched from the public internet, whose shape nobody here controls.
// A run that dies must leave a red feed card, not a CrashLoopBackOff.
func (r *Runner) syncRecovering(ctx context.Context, feed Feed, cursor string) (res SyncResult, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("feed %s panicked: %v", feed.Name(), p)
			logger.Printf("feed %s PANICKED (recovered, recorded as a failed run): %v\n%s",
				feed.Name(), p, debug.Stack())
		}
	}()
	return feed.Sync(ctx, r.store, cursor)
}
