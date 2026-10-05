package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
)

// ActiveScanFinishJob records person-initiated Active Scans and revalidations
// as finished once their jobs have ended (autoscan.FinishActiveScans).
//
// # Why it is its own worker
//
// A scan a PERSON started is recorded as `scanning` at dispatch, and something
// has to move it on when its job ends — otherwise Discovery → Active Scan reads
// "Scanning…" for good. That used to be a pass inside AutoActiveScanJob, which
// meant switching automatic scanning off (EnvAutoScanEnabled) could not stop the
// automatic worker without also stopping this bookkeeping, so the worker stayed
// up with its scanning half disabled. The two have nothing to do with each
// other — this one has no policy, no environment flag and no sweep — so it runs
// on its own ticker and is started unconditionally from main.
type ActiveScanFinishJob struct {
	store    activeScanFinisher
	bypassDB *sql.DB
	logger   *log.Logger

	interval time.Duration

	// Seams for tests, as on AutoActiveScanJob.
	listInFlight func() ([]uuid.UUID, error)
	tryLock      func(context.Context) (func(), bool, error)
}

// activeScanFinisher is the slice of internal/autoscan.Store this job uses.
type activeScanFinisher interface {
	FinishActiveScans(ctx context.Context, tenantID uuid.UUID) (autoscan.FinishedScans, error)
}

// activeScanFinishInterval is how often the pass runs. Short, so Discovery →
// Active Scan stops showing a scan as running within about a minute of its job
// ending.
const activeScanFinishInterval = 60 * time.Second

// activeScanFinishLockKey is the fixed 64-bit key one pass takes. Hand-picked
// rather than hashed so it is greppable, and distinct from every other
// advisory-lock user in the platform (the automatic-scan sweep is ..._0001, the
// rule-merge executor ..._0002).
const activeScanFinishLockKey int64 = 0x7641_5343_0000_0003

// NewActiveScanFinishJob builds the worker. `store` is the concrete
// internal/autoscan.Store in production.
func NewActiveScanFinishJob(store activeScanFinisher, bypassDB *sql.DB) *ActiveScanFinishJob {
	j := &ActiveScanFinishJob{
		store:    store,
		bypassDB: bypassDB,
		logger:   log.New(log.Writer(), "[ActiveScanFinish] ", log.LstdFlags),
		interval: activeScanFinishInterval,
	}
	j.listInFlight = j.tenantsWithActiveScansInFlight
	j.tryLock = j.pgTryLock
	return j
}

// Start runs the worker until ctx is cancelled.
func (j *ActiveScanFinishJob) Start(ctx context.Context) {
	j.logger.Printf("started (person-initiated scans are settled every %v)", j.interval)
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			j.logger.Println("stopped")
			return
		case <-ticker.C:
			j.FinishInFlight(ctx)
		}
	}
}

// FinishInFlight settles the person-initiated scans of every tenant that has
// one in flight, unless another replica is already doing so.
//
// The lock is for wasted work, not for correctness: the settle is idempotent (a
// settled record no longer matches), so two replicas doing it at once is
// harmless. Session-level and best-effort — a replica that cannot take it does
// nothing this tick and tries again on the next.
func (j *ActiveScanFinishJob) FinishInFlight(ctx context.Context) {
	release, ok, err := j.tryLock(ctx)
	if err != nil {
		j.logger.Printf("ERROR: could not take the settle lock: %v", err)
		return
	}
	if !ok {
		j.logger.Printf("another replica is settling active scans; skipping this tick")
		return
	}
	defer release()

	tenants, err := j.listInFlight()
	if err != nil {
		j.logger.Printf("ERROR: could not enumerate tenants with active scans in flight: %v", err)
		return
	}
	for _, tenantID := range tenants {
		select {
		case <-ctx.Done():
			return
		default:
		}
		j.finishActiveScans(ctx, tenantID)
	}
}

// finishActiveScans settles one tenant's person-initiated scans whose jobs
// have ended. Logged and moved past on error: it is a record, re-attempted on
// every pass.
func (j *ActiveScanFinishJob) finishActiveScans(ctx context.Context, tenantID uuid.UUID) {
	done, err := j.store.FinishActiveScans(ctx, tenantID)
	if err != nil {
		j.logger.Printf("ERROR: tenant %s: could not settle finished active scans: %v", tenantID, err)
		return
	}
	if done.Assets > 0 || done.Endpoints > 0 {
		j.logger.Printf("tenant %s: settled %d asset(s) and %d endpoint(s) whose active scan has finished", tenantID, done.Assets, done.Endpoints)
	}
}

// tenantsWithActiveScansInFlight enumerates the tenants that have a
// person-initiated scan recorded as running: an asset whose Active Scan record
// is `scanning`, or an endpoint marked `scanning` (including one marked by an
// older build, before the record existed).
//
// RLS: cross-tenant — runs on the bypass role, like AutoActiveScanJob's
// tenantsToSweep: finding out which tenants have work is the question.
func (j *ActiveScanFinishJob) tenantsWithActiveScansInFlight() ([]uuid.UUID, error) {
	if j.bypassDB == nil {
		return nil, nil
	}
	rows, err := j.bypassDB.Query(`
		SELECT tenant_id FROM assets
		WHERE deleted_at IS NULL AND metadata ->> '` + autoscan.MetaActiveScanStatus + `' = '` + autoscan.ActiveScanScanning + `'
		UNION
		SELECT tenant_id FROM asset_endpoints WHERE last_scan_status = '` + autoscan.ActiveScanScanning + `'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// pgTryLock takes the session-level advisory lock on the bypass handle, and
// releases it on the SAME connection (a session lock belongs to the session;
// unlocking through the pool could hit a different backend and leave it held
// until the pod restarts).
func (j *ActiveScanFinishJob) pgTryLock(ctx context.Context) (func(), bool, error) {
	if j.bypassDB == nil {
		// No database handle at all: single-process contexts have nothing to
		// contend with.
		return func() {}, true, nil
	}
	conn, err := j.bypassDB.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire a connection for the settle lock: %w", err)
	}
	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", activeScanFinishLockKey).Scan(&got); err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("try the settle advisory lock: %w", err)
	}
	if !got {
		_ = conn.Close()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", activeScanFinishLockKey)
		_ = conn.Close()
	}, true, nil
}
