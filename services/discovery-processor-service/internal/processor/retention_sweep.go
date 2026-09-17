// Package processor: RetentionSweepJob purges PROCESSED sensor_discoveries
// rows once they have sat past the retention window.
//
// sensor_discoveries is the raw ingestion queue, not a record of the
// inventory: once a row is processed_at (BatchProcessor has materialized,
// suppressed, deferred or routed whatever it carried — see markProcessed and
// adoptEffectiveStatus), the queue row itself has no further job to do. It was
// never purged, so a one-sensor lab with an hourly re-report cadence
// (sensor_discoveries.dedup_ttl_minutes default 60) accumulated 13,779 rows in
// 24 hours with nothing bounding the total. This sweep is that bound.
//
// It NEVER touches an unprocessed row (processed_at IS NULL) — those are
// exactly the rows the poller in discovery_processor.go is still working
// through, and deleting one would silently drop a discovery no differently
// than the "held by merge proposal"/failed-route paths this codebase is
// otherwise careful to log rather than lose quietly.
package processor

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
)

// Environment knobs.
const (
	// EnvRetentionEnabled is the kill switch. Anything but "false" leaves the
	// sweep on, matching the auto-scan worker's convention
	// (DISCOVERY_AUTO_SCAN_WORKER_ENABLED): the product's default is that
	// processed rows do not accumulate forever, and an operator turning that
	// off should have to say so.
	EnvRetentionEnabled = "SENSOR_DISCOVERY_RETENTION_ENABLED"
	// EnvRetentionHours is how long a PROCESSED row is kept before the sweep
	// deletes it. It says nothing about unprocessed rows, which are never
	// touched regardless of age.
	EnvRetentionHours = "SENSOR_DISCOVERY_RETENTION_HOURS"
)

const (
	// defaultRetentionHours is 7 days — long enough that a re-import
	// investigation ("did this batch already run?") or a support ticket about
	// last week's discovery has the raw row to look at, short enough that a
	// lab or a tenant with a busy segment does not grow this table without
	// bound.
	defaultRetentionHours = 168

	// retentionBatchSize bounds each DELETE so the sweep never holds row locks
	// or a single statement's worth of WAL for an unbounded set. Matches the
	// batch size CLAUDE.md's schema-change guidance already uses as the
	// reference figure for a bounded delete loop.
	retentionBatchSize = 5000

	// retentionSweepInterval is how often the sweep LOOKS for work, not the
	// retention window itself. Sub-daily on purpose: a busy tenant can
	// accumulate well over a day's worth of processed rows from one sensor
	// alone, and waiting a full day between sweeps would let more than one
	// day's worth of purgeable rows stack up before the first pass ever ran.
	retentionSweepInterval = 1 * time.Hour
)

// retentionAdvisoryLockKey is the fixed 64-bit key the sweep takes so that, on
// a multi-replica deployment, only one replica runs it per tick — the same
// cross-replica problem and the same fix inventory-service's
// AutoActiveScanJob documents at its own lock key: two replicas racing the
// DELETE is not unsafe (each is a plain idempotent batch), but it is wasted
// work and doubled lock contention on a table already busy with the poller.
// Hand-picked rather than hashed so it is greppable, and distinct from every
// other advisory-lock user in the platform (inventory-service's auto-scan
// sweep uses 0x7641_5343_0000_0001).
const retentionAdvisoryLockKey int64 = 0x5344_5253_0000_0001 // "SDRS": Sensor Discovery Retention Sweep

// RetentionSweepJob deletes processed sensor_discoveries rows older than the
// retention window, in bounded batches, on its own ticker.
type RetentionSweepJob struct {
	bypassDB *sqlx.DB
	logger   *log.Logger

	enabled   bool
	window    time.Duration
	interval  time.Duration
	batchSize int

	// Seams for tests.
	tryLock func(context.Context) (func(), bool, error)
	now     func() time.Time
	delete  func(context.Context, time.Time) (int, error)
}

// NewRetentionSweepJob builds the worker. bypassDB is the BYPASSRLS
// (crypto_bypass) handle — this sweep deletes across every tenant in one pass,
// the same cross-tenant reach discovery_processor.go's processNextBatch
// already documents for this table.
func NewRetentionSweepJob(bypassDB *sqlx.DB) *RetentionSweepJob {
	j := &RetentionSweepJob{
		bypassDB:  bypassDB,
		logger:    log.New(log.Writer(), "[RetentionSweep] ", log.LstdFlags),
		enabled:   os.Getenv(EnvRetentionEnabled) != "false",
		window:    retentionWindowFromEnv(),
		interval:  retentionSweepInterval,
		batchSize: retentionBatchSize,
		now:       time.Now,
	}
	j.tryLock = j.pgTryLock
	j.delete = j.deleteBatch
	return j
}

func retentionWindowFromEnv() time.Duration {
	hours := defaultRetentionHours
	if raw := os.Getenv(EnvRetentionHours); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			hours = n
		}
	}
	return time.Duration(hours) * time.Hour
}

// Start runs the sweep on its ticker until ctx is cancelled. One pass runs
// immediately so a freshly deployed retention window (or a cluster upgraded
// into having one for the first time) does not wait a full interval before
// working through an existing backlog.
func (j *RetentionSweepJob) Start(ctx context.Context) {
	if !j.enabled {
		j.logger.Printf("disabled by %s=false — processed sensor_discoveries rows will not be purged", EnvRetentionEnabled)
		return
	}
	j.logger.Printf("started (retention window %v, sweep every %v, batch size %d)", j.window, j.interval, j.batchSize)

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	j.Sweep(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Println("stopped")
			return
		case <-ticker.C:
			j.Sweep(ctx)
		}
	}
}

// Sweep runs one purge pass while holding the cross-replica advisory lock, or
// does nothing when another replica already holds it.
func (j *RetentionSweepJob) Sweep(ctx context.Context) {
	release, ok, err := j.tryLock(ctx)
	if err != nil {
		j.logger.Printf("ERROR: could not take the sweep lock: %v", err)
		return
	}
	if !ok {
		j.logger.Printf("another replica is running the sweep; skipping this tick")
		return
	}
	defer release()

	cutoff := j.now().Add(-j.window)
	total := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := j.delete(ctx, cutoff)
		if err != nil {
			j.logger.Printf("ERROR: sweep stopped after deleting %d row(s): %v", total, err)
			return
		}
		total += n
		if n < j.batchSize {
			break
		}
	}
	// One line per sweep, always — including "0 row(s)", which is the healthy
	// steady state once the backlog is worked through and distinguishes a
	// sweep that ran and found nothing to do from one that did not run at all.
	j.logger.Printf("swept %d processed sensor_discoveries row(s) older than %s (retention %v)",
		total, cutoff.UTC().Format(time.RFC3339), j.window)
}

// deleteBatch deletes up to batchSize processed, expired rows in one
// statement and reports how many it removed.
//
// The predicate is exactly `processed_at IS NOT NULL AND processed_at <
// cutoff` — never anything broader. `id IN (subquery LIMIT n)` rather than a
// bare `DELETE ... LIMIT` (Postgres has no LIMIT on DELETE) bounds each
// statement's lock footprint; looping in Sweep until a batch comes back
// short is what makes an arbitrarily large backlog safe to work through
// without one unbounded transaction.
func (j *RetentionSweepJob) deleteBatch(ctx context.Context, cutoff time.Time) (int, error) {
	if j.bypassDB == nil {
		return 0, nil
	}
	res, err := j.bypassDB.ExecContext(ctx, `
		DELETE FROM sensor_discoveries
		WHERE id IN (
			SELECT id FROM sensor_discoveries
			WHERE processed_at IS NOT NULL AND processed_at < $1
			LIMIT $2
		)`, cutoff, j.batchSize)
	if err != nil {
		return 0, fmt.Errorf("delete batch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(n), nil
}

// pgTryLock takes the session-level advisory lock on the bypass handle.
//
// Session-level and best-effort, same as AutoActiveScanJob's: a replica that
// cannot take the lock does nothing this tick and tries again on the next
// one, which is correct for a pass that is idempotent anyway.
func (j *RetentionSweepJob) pgTryLock(ctx context.Context) (func(), bool, error) {
	if j.bypassDB == nil {
		// No database handle: single-process contexts (tests) have nothing to
		// contend with.
		return func() {}, true, nil
	}
	conn, err := j.bypassDB.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire a connection for the sweep lock: %w", err)
	}
	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", retentionAdvisoryLockKey).Scan(&got); err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("try the sweep advisory lock: %w", err)
	}
	if !got {
		_ = conn.Close()
		return nil, false, nil
	}
	return func() {
		// Released on the SAME connection that took it — a session-level lock
		// belongs to the session, so releasing through the pool could hit a
		// different backend and leave the lock held until the pod restarts.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", retentionAdvisoryLockKey)
		_ = conn.Close()
	}, true, nil
}
