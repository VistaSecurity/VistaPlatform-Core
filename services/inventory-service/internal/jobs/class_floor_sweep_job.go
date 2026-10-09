package jobs

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// ClassFloorSweeper is the per-tenant pass (services.AssetService).
type ClassFloorSweeper interface {
	SweepClassFloor(ctx context.Context, tenantID uuid.UUID) (services.ClassFloorSweepResult, error)
}

// classFloorSweepLockKey is the session advisory lock one replica holds while
// it runs a pass. Hand-picked and greppable, distinct from its siblings
// (sweepAdvisoryLockKey …0001, ruleMergeAdvisoryLockKey …0002,
// activeScanFinishLockKey …0003, ouiVendorBackfillLockKey …0004).
const classFloorSweepLockKey int64 = 0x7641_5343_0000_0005

const (
	// classFloorSweepStartDelay puts the first pass AFTER the OUI vendor
	// backfill's first pass (ouiVendorBackfillStartDelay, 2 minutes), so a
	// pre-existing asset's registry vendor is in place before the sweep reads
	// its evidence — and keeps it off the startup path either way.
	classFloorSweepStartDelay = 5 * time.Minute
	// classFloorSweepInterval is how often the sweep re-asks. What it catches
	// changes slowly — a curated rule edited, a new registry snapshot, a
	// vendor backfilled — and an observation of the asset promotes it at
	// intake without waiting for this.
	classFloorSweepInterval = 6 * time.Hour
)

// StartClassFloorSweepWorker runs the class floor sweep (see
// services/class_floor_sweep.go) five minutes after startup and then every six
// hours, for every live tenant.
//
// Same shape as StartOUIVendorBackfillWorker: enumerate tenants through the
// bypass connection, hand each to a pass that does its own reads and writes in
// the tenant's RLS session, one replica at a time through a session advisory
// lock. Runs in its own goroutine; nothing here blocks startup or a request.
// There is no on-demand trigger, because the OUI backfill it follows has none.
func StartClassFloorSweepWorker(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), sweeper ClassFloorSweeper) {
	if bypass == nil || sweeper == nil {
		return
	}
	timer := time.NewTimer(classFloorSweepStartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(classFloorSweepInterval)
	defer ticker.Stop()
	for {
		runClassFloorSweepPass(ctx, bypass, tenants, sweeper)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runClassFloorSweepPass is one tick: take the lock or skip, then walk every
// tenant, logging one summary line each. A failing tenant is logged and the
// rest carry on; the next tick retries it.
func runClassFloorSweepPass(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), sweeper ClassFloorSweeper) {
	conn, err := bypass.Conn(ctx)
	if err != nil {
		log.Printf("[ClassFloorSweep] acquire a connection for the lock: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, classFloorSweepLockKey).Scan(&got); err != nil {
		log.Printf("[ClassFloorSweep] try the advisory lock: %v", err)
		return
	}
	if !got {
		return
	}
	// Released on the SAME session that took it: a session-level lock belongs
	// to the backend, and unlocking through the pool could miss it.
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, classFloorSweepLockKey)
	}()

	ids, err := tenants(ctx, bypass)
	if err != nil {
		log.Printf("[ClassFloorSweep] enumerate tenants: %v", err)
		return
	}
	for _, tenant := range ids {
		if ctx.Err() != nil {
			return
		}
		res, err := sweeper.SweepClassFloor(ctx, tenant)
		if err != nil {
			log.Printf("[ClassFloorSweep] tenant %s: %v (considered %d, promoted %d before stopping; retried next tick)",
				tenant, err, res.Considered, res.Promoted)
			continue
		}
		log.Printf("[ClassFloorSweep] tenant %s: considered %d floor asset(s), promoted %d, %d rule conflict(s)",
			tenant, res.Considered, res.Promoted, res.Conflicts)
	}
}
