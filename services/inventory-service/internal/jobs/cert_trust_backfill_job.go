package jobs

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CertTrustBackfiller is the per-tenant trust evaluation the backfill drives
// (*certtrust.Evaluator).
type CertTrustBackfiller interface {
	RecomputeUnevaluated(ctx context.Context, tenantID uuid.UUID, limit int) (int, error)
	RetryIncomplete(ctx context.Context, tenantID uuid.UUID, limit int) (int, error)
}

// certTrustBackfillLockKey: one replica runs a pass at a time. Distinct from
// its siblings (…0001 to …0005, see class_floor_sweep_job.go).
const certTrustBackfillLockKey int64 = 0x7641_5343_0000_0006

const (
	// certTrustBackfillStartDelay keeps the first pass off the startup path.
	certTrustBackfillStartDelay = 3 * time.Minute
	// certTrustBackfillInterval is how often the backfill runs.
	certTrustBackfillInterval = 6 * time.Hour
	// certTrustBackfillPerTenant bounds each half of a tenant's pass.
	certTrustBackfillPerTenant = 2000
	// certTrustIncompleteRetry is the least time between two retries of a
	// tenant's incomplete chains: an AIA repository that was down at 02:00
	// is asked again tomorrow, not every six hours.
	certTrustIncompleteRetry = 24 * time.Hour
)

// CertTrustBackfillEnabled reports the operator's switch,
// CERT_TRUST_BACKFILL_ENABLED (default on; "false" turns it off).
func CertTrustBackfillEnabled() bool {
	return strings.TrimSpace(strings.ToLower(os.Getenv("CERT_TRUST_BACKFILL_ENABLED"))) != "false"
}

// CertTrustBackfillTenants lists the tenants that hold certificates — the
// only ones the backfill has anything to do for.
func CertTrustBackfillTenants(ctx context.Context, bypass *sql.DB) ([]uuid.UUID, error) {
	rows, err := bypass.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		 WHERE t.deleted_at IS NULL
		   AND EXISTS (SELECT 1 FROM certificates c WHERE c.tenant_id = t.id)
		 ORDER BY t.id`)
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

// StartCertTrustBackfillWorker evaluates certificate trust for what
// the request paths did not reach: every six hours, per tenant, up to 2,000
// certificates never evaluated (stored before trust evaluation existed, or
// whose evaluation failed), and — at most once per 24 hours per tenant — up to
// 2,000 whose chain was incomplete, with AIA chain completion allowed. Off
// with CERT_TRUST_BACKFILL_ENABLED=false.
//
// Same shape as StartClassFloorSweepWorker: tenants enumerated through the
// bypass connection, each tenant's work in its own RLS session, one replica at
// a time through a session advisory lock.
func StartCertTrustBackfillWorker(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), eval CertTrustBackfiller) {
	if bypass == nil || eval == nil {
		return
	}
	if !CertTrustBackfillEnabled() {
		log.Println("[CertTrustBackfill] disabled by CERT_TRUST_BACKFILL_ENABLED=false")
		return
	}
	timer := time.NewTimer(certTrustBackfillStartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(certTrustBackfillInterval)
	defer ticker.Stop()
	lastRetry := map[uuid.UUID]time.Time{}
	for {
		runCertTrustBackfillPass(ctx, bypass, tenants, eval, lastRetry, time.Now)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runCertTrustBackfillPass is one tick. lastRetry remembers, per tenant, when
// its incomplete chains were last retried (in memory: after a restart they are
// retried once on the first pass, which is the bound the 24 hours is for).
func runCertTrustBackfillPass(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), eval CertTrustBackfiller, lastRetry map[uuid.UUID]time.Time, now func() time.Time) {
	conn, err := bypass.Conn(ctx)
	if err != nil {
		log.Printf("[CertTrustBackfill] acquire a connection for the lock: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, certTrustBackfillLockKey).Scan(&got); err != nil {
		log.Printf("[CertTrustBackfill] try the advisory lock: %v", err)
		return
	}
	if !got {
		return
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, certTrustBackfillLockKey)
	}()

	ids, err := tenants(ctx, bypass)
	if err != nil {
		log.Printf("[CertTrustBackfill] enumerate tenants: %v", err)
		return
	}
	backfillTenants(ctx, ids, eval, lastRetry, now)
}

// backfillTenants is the per-tenant half of a pass, separate from the lock so
// a test can drive it without one.
func backfillTenants(ctx context.Context, ids []uuid.UUID, eval CertTrustBackfiller, lastRetry map[uuid.UUID]time.Time, now func() time.Time) {
	for _, tenant := range ids {
		if ctx.Err() != nil {
			return
		}
		n, err := eval.RecomputeUnevaluated(ctx, tenant, certTrustBackfillPerTenant)
		if err != nil {
			log.Printf("[CertTrustBackfill] tenant %s: unevaluated pass stopped after %d: %v", tenant, n, err)
			continue
		}
		retried := 0
		if last, ok := lastRetry[tenant]; !ok || now().Sub(last) >= certTrustIncompleteRetry {
			lastRetry[tenant] = now()
			if retried, err = eval.RetryIncomplete(ctx, tenant, certTrustBackfillPerTenant); err != nil {
				log.Printf("[CertTrustBackfill] tenant %s: incomplete retry stopped after %d: %v", tenant, retried, err)
				continue
			}
		}
		if n > 0 || retried > 0 {
			log.Printf("[CertTrustBackfill] tenant %s: evaluated %d never-evaluated certificate(s), retried %d incomplete chain(s)", tenant, n, retried)
		}
	}
}
