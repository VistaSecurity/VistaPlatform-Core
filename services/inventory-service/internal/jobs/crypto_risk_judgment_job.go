package jobs

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
)

// CryptoRiskJudger is the per-tenant pass (services.CryptoRisksService).
type CryptoRiskJudger interface {
	SweepJudgments(ctx context.Context, tenant uuid.UUID, limit int) (int, error)
}

// cryptoRiskJudgmentLockKey is the session advisory lock one replica holds while
// it runs a pass; distinct from its siblings (classFloorSweepLockKey …0005, certTrustBackfillLockKey …0006).
const cryptoRiskJudgmentLockKey int64 = 0x7641_5343_0000_0007

const (
	// cryptoRiskJudgmentStartDelay keeps the first pass off the startup path.
	cryptoRiskJudgmentStartDelay = 30 * time.Second
	// cryptoRiskJudgmentInterval: the Crypto Risks readers re-judge whatever is
	// stale themselves, so this only keeps the table warm (and back-fills the
	// rows a schema upgrade creates stale). Certificate lifecycle text changes
	// daily, so a pass well inside a day keeps requests free of judging.
	cryptoRiskJudgmentInterval = 5 * time.Minute
	// cryptoRiskJudgmentPerTenant bounds one tenant's work per pass; the rest
	// waits for the next tick, so a large backfill never monopolises the pool.
	cryptoRiskJudgmentPerTenant = 5000
)

// StartCryptoRiskJudgmentWorker keeps crypto_risk_judgments current for every
// live tenant, one replica at a time through a session advisory lock.
func StartCryptoRiskJudgmentWorker(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), judger CryptoRiskJudger) {
	if bypass == nil || judger == nil {
		return
	}
	timer := time.NewTimer(cryptoRiskJudgmentStartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(cryptoRiskJudgmentInterval)
	defer ticker.Stop()
	for {
		runCryptoRiskJudgmentPass(ctx, bypass, tenants, judger)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runCryptoRiskJudgmentPass(ctx context.Context, bypass *sql.DB, tenants func(context.Context, *sql.DB) ([]uuid.UUID, error), judger CryptoRiskJudger) {
	conn, err := bypass.Conn(ctx)
	if err != nil {
		log.Printf("[CryptoRiskJudgment] acquire a connection for the lock: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, cryptoRiskJudgmentLockKey).Scan(&got); err != nil || !got {
		if err != nil {
			log.Printf("[CryptoRiskJudgment] try the advisory lock: %v", err)
		}
		return
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, cryptoRiskJudgmentLockKey)
	}()
	ids, err := tenants(ctx, bypass)
	if err != nil {
		log.Printf("[CryptoRiskJudgment] enumerate tenants: %v", err)
		return
	}
	for _, tenant := range ids {
		if ctx.Err() != nil {
			return
		}
		if _, err := judger.SweepJudgments(ctx, tenant, cryptoRiskJudgmentPerTenant); err != nil {
			log.Printf("[CryptoRiskJudgment] tenant %s: %v (retried next tick)", tenant, err)
		}
	}
}
