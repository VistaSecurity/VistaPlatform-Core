package jobs

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changenotify"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
)

// CableResolver is the per-tenant pass (services.CableIntake).
type CableResolver interface {
	ResolveParked(ctx context.Context, tenant uuid.UUID) (unresolved.ResolvedCount, error)
}

// cableResolverLockKey is the session advisory lock one replica holds while it
// runs a pass; distinct from its siblings (…0001–…0007).
const cableResolverLockKey int64 = 0x7641_5343_0000_0008

const (
	cableResolverStartDelay = 3 * time.Minute
	// cableResolverInterval: the resolver also runs after every intake batch
	// that files interfaces (internal sightings); the hourly pass catches a far
	// interface that arrived some other way (a person adding it, an import)
	// and expires rows past their 30 days.
	cableResolverInterval = time.Hour
)

// StartCableResolverWorker runs the LLDP / CDP cable resolver (DCIM row 3.3,
// services/cable_resolver.go) three minutes after startup and then hourly, for
// every tenant with a parked neighbour. Same shape as the class floor sweep:
// tenants through the bypass connection, each pass in the tenant's RLS session,
// one replica at a time.
func StartCableResolverWorker(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), r CableResolver) {
	if bypass == nil || r == nil {
		return
	}
	timer := time.NewTimer(cableResolverStartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(cableResolverInterval)
	defer ticker.Stop()
	for {
		RunCableResolverPass(ctx, bypass, tenants, r)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunCableResolverPass is one tick: take the lock or skip, then resolve every
// tenant with a parked neighbour. A failing tenant is logged; the next tick
// retries it.
func RunCableResolverPass(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), r CableResolver) {
	conn, err := bypass.Conn(ctx)
	if err != nil {
		log.Printf("[CableResolver] acquire a connection for the lock: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, cableResolverLockKey).Scan(&got); err != nil {
		log.Printf("[CableResolver] try the advisory lock: %v", err)
		return
	}
	if !got {
		return
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, cableResolverLockKey)
	}()
	ids, err := tenants(ctx, bypass)
	if err != nil {
		log.Printf("[CableResolver] enumerate tenants: %v", err)
		return
	}
	for _, tenant := range ids {
		if ctx.Err() != nil {
			return
		}
		// One change-notification unit per tenant: the proposed cables this
		// pass files raise object_changed (for a rule that includes intake)
		// once it has committed.
		var n unresolved.ResolvedCount
		err := changenotify.Unit(ctx, func(ctx context.Context) error {
			var err error
			n, err = r.ResolveParked(ctx, tenant)
			return err
		})
		if err != nil {
			log.Printf("[CableResolver] tenant %s: %v (resolved %d before the error; retried next tick)", tenant, err, n.Resolved)
			continue
		}
		if n.Resolved+n.Expired > 0 {
			log.Printf("[CableResolver] tenant %s: %d parked neighbour(s) became proposed cables, %d expired, %d still waiting",
				tenant, n.Resolved, n.Expired, n.Unmatched)
		}
	}
}
