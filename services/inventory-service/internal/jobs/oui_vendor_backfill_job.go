package jobs

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
)

// OUIVendorBackfiller is the per-tenant pass (services.AssetService).
type OUIVendorBackfiller interface {
	BackfillRegistryVendors(ctx context.Context, tenantID uuid.UUID) (int, error)
}

// ouiVendorBackfillLockKey is the session advisory lock one replica holds while
// it runs a pass. Hand-picked like its siblings (sweepAdvisoryLockKey,
// activeScanFinishLockKey, ruleMergeAdvisoryLockKey) so it is greppable and
// distinct from every other advisory-lock user.
const ouiVendorBackfillLockKey int64 = 0x7641_5343_0000_0004

const (
	// ouiVendorBackfillStartDelay keeps the first pass off the startup path:
	// the service is serving, its pools are warm and migrations have settled
	// before any tenant is walked.
	ouiVendorBackfillStartDelay = 2 * time.Minute
	// ouiVendorBackfillInterval is how often the worker re-checks for due
	// tenants. The registry is compiled in, so a NEW snapshot only ever arrives
	// with a new binary — i.e. at startup. The ticks exist for what the first
	// pass could not finish: a tenant whose pass failed has no state row for the
	// running snapshot and is retried here, and a tenant created since is
	// picked up. A tick with nothing due is one indexed query.
	ouiVendorBackfillInterval = time.Hour
)

// StartOUIVendorBackfillWorker runs the OUI vendor backfill (see
// services/oui_vendor_backfill.go) shortly after startup and then hourly, for
// every tenant whose last completed pass ran under a different IEEE registry
// snapshot than this binary carries.
//
// Same shape as the identity workers next door: enumerate tenants through the
// bypass connection, then hand each to a pass that does all of its own reads
// and writes in the tenant's RLS session. One replica at a time, through a
// session advisory lock (the auto-scan sweep's pattern): the pass is
// idempotent, so a second replica would only duplicate work. Runs in its own
// goroutine; nothing here blocks startup or a request.
func StartOUIVendorBackfillWorker(ctx context.Context, bypass *sql.DB, dueTenants func(context.Context, *sql.DB) ([]uuid.UUID, error), backfiller OUIVendorBackfiller) {
	if bypass == nil || backfiller == nil {
		return
	}
	timer := time.NewTimer(ouiVendorBackfillStartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(ouiVendorBackfillInterval)
	defer ticker.Stop()
	for {
		runOUIVendorBackfillPass(ctx, bypass, dueTenants, backfiller)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runOUIVendorBackfillPass is one tick: take the lock or skip, then walk every
// due tenant. A failing tenant is logged and left due; it never stops the rest.
func runOUIVendorBackfillPass(ctx context.Context, bypass *sql.DB, dueTenants func(context.Context, *sql.DB) ([]uuid.UUID, error), backfiller OUIVendorBackfiller) {
	conn, err := bypass.Conn(ctx)
	if err != nil {
		log.Printf("[OUIVendorBackfill] acquire a connection for the lock: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, ouiVendorBackfillLockKey).Scan(&got); err != nil {
		log.Printf("[OUIVendorBackfill] try the advisory lock: %v", err)
		return
	}
	if !got {
		return
	}
	// Released on the SAME session that took it: a session-level lock belongs
	// to the backend, and unlocking through the pool could miss it.
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, ouiVendorBackfillLockKey)
	}()

	tenants, err := dueTenants(ctx, bypass)
	if err != nil {
		log.Printf("[OUIVendorBackfill] enumerate due tenants: %v", err)
		return
	}
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			return
		}
		n, err := backfiller.BackfillRegistryVendors(ctx, tenant)
		if err != nil {
			log.Printf("[OUIVendorBackfill] tenant %s: %v (wrote %d before stopping; retried next tick)", tenant, err, n)
			continue
		}
		if n > 0 {
			log.Printf("[OUIVendorBackfill] tenant %s: wrote the registry vendor for %d asset(s)", tenant, n)
		}
	}
}
