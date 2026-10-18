package jobs

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/orphans"
)

// OrphanSweeper is the per-tenant pass (services.OrphanSweeper).
type OrphanSweeper interface {
	SweepTenant(ctx context.Context, tenant uuid.UUID) (orphans.Report, error)
}

// orphanSweepLockKey is the session advisory lock one replica holds while it
// runs a pass; distinct from its siblings (…0001–…0008).
const orphanSweepLockKey int64 = 0x7641_5343_0000_0009

const (
	orphanSweepStartDelay = 10 * time.Minute
	orphanSweepInterval   = 24 * time.Hour
)

// StartOrphanSweepWorker removes references to deleted DCIM objects (tags,
// journal entries, contacts, images, scopes, assignments: see
// shared/dcim/orphans) ten minutes after startup and then daily, for every
// tenant. Same shape as the cable resolver: tenants through the bypass
// connection, each pass in the tenant's RLS session, one replica at a time.
func StartOrphanSweepWorker(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), s OrphanSweeper) {
	if bypass == nil || s == nil {
		return
	}
	timer := time.NewTimer(orphanSweepStartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(orphanSweepInterval)
	defer ticker.Stop()
	for {
		RunOrphanSweepPass(ctx, bypass, tenants, s)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOrphanSweepPass is one tick: take the lock or skip, then sweep every
// tenant. A failing tenant is logged; the next tick retries it.
func RunOrphanSweepPass(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), s OrphanSweeper) {
	conn, err := bypass.Conn(ctx)
	if err != nil {
		log.Printf("[OrphanSweep] acquire a connection for the lock: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, orphanSweepLockKey).Scan(&got); err != nil {
		log.Printf("[OrphanSweep] try the advisory lock: %v", err)
		return
	}
	if !got {
		return
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, orphanSweepLockKey)
	}()
	ids, err := tenants(ctx, bypass)
	if err != nil {
		log.Printf("[OrphanSweep] enumerate tenants: %v", err)
		return
	}
	for _, tenant := range ids {
		if ctx.Err() != nil {
			return
		}
		rep, err := s.SweepTenant(ctx, tenant)
		if err != nil {
			log.Printf("[OrphanSweep] tenant %s: %v (retried next tick)", tenant, err)
			continue
		}
		if rep.Total() > 0 {
			log.Printf("[OrphanSweep] tenant %s: %d reference(s) to deleted objects cleaned (%s)", tenant, rep.Total(), strings.Join(rep.Keys(), ", "))
		}
	}
}
