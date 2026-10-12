package jobs

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// SuppressionExpirySweeper is the slice of *services.FindingsService the job
// uses.
type SuppressionExpirySweeper interface {
	ExpireSuppressions(ctx context.Context) ([]services.ExpiredSuppression, error)
}

// SuppressionExpiryJob reopens findings whose time-boxed suppression has run
// out, then asks each affected tenant to reconcile so framework scores and
// control state are recomputed from the reopened findings.
//
// enqueue may be nil (NATS unavailable at start-up); the reopened findings are
// still correct in the table and the next reconcile for that tenant picks them
// up.
type SuppressionExpiryJob struct {
	sweeper SuppressionExpirySweeper
	enqueue func(tenantID uuid.UUID, reason string)
}

// NewSuppressionExpiryJob creates the job.
func NewSuppressionExpiryJob(sweeper SuppressionExpirySweeper, enqueue func(uuid.UUID, string)) *SuppressionExpiryJob {
	return &SuppressionExpiryJob{sweeper: sweeper, enqueue: enqueue}
}

// Run performs one sweep.
func (j *SuppressionExpiryJob) Run(ctx context.Context) error {
	expired, err := j.sweeper.ExpireSuppressions(ctx)
	// A partial result is still acted on: rows already reopened need their
	// tenants reconciled even when a later batch failed.
	tenants := map[uuid.UUID]struct{}{}
	for _, e := range expired {
		tenants[e.TenantID] = struct{}{}
	}
	if len(expired) > 0 {
		log.Printf("[SuppressionExpiry] reopened %d finding(s) across %d tenant(s)", len(expired), len(tenants))
	}
	if j.enqueue != nil {
		for t := range tenants {
			j.enqueue(t, "suppression_expired")
		}
	}
	return err
}

// StartPeriodic runs the job now and then on every interval until ctx ends.
func (j *SuppressionExpiryJob) StartPeriodic(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := j.Run(ctx); err != nil {
			log.Printf("[SuppressionExpiry] sweep failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
