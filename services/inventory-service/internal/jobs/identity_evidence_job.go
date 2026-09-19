package jobs

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
)

type IdentityEvidenceSweeper interface {
	SweepIdentityEvidence(context.Context, uuid.UUID) (int, error)
}

// StartIdentityEvidenceWorker enumerates tenants through the explicit bypass
// connection; every evidence read/write then uses the tenant-scoped service.
type MergeEventSweeper interface {
	PublishPendingMergeEvents(context.Context, uuid.UUID) (int, error)
}

func StartIdentityEvidenceWorker(ctx context.Context, bypass *sql.DB, sweeper IdentityEvidenceSweeper, mergeSweepers ...MergeEventSweeper) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		rows, err := bypass.QueryContext(ctx, `SELECT tenant_id FROM identity_observations UNION SELECT tenant_id FROM asset_merge_audits WHERE events_published_at IS NULL AND pending_events <> '[]'::jsonb ORDER BY tenant_id`)
		if err != nil {
			log.Printf("[IdentityEvidence] enumerate tenants: %v", err)
		} else {
			var tenants []uuid.UUID
			for rows.Next() {
				var tenant uuid.UUID
				if err := rows.Scan(&tenant); err != nil {
					log.Printf("[IdentityEvidence] read tenant: %v", err)
					break
				}
				tenants = append(tenants, tenant)
			}
			if err := rows.Err(); err != nil {
				log.Printf("[IdentityEvidence] enumerate tenants: %v", err)
			}
			_ = rows.Close()
			for _, tenant := range tenants {
				if ctx.Err() != nil {
					return
				}
				for _, mergeSweeper := range mergeSweepers {
					if _, err := mergeSweeper.PublishPendingMergeEvents(ctx, tenant); err != nil {
						log.Printf("[IdentityEvidence] tenant %s merge publication: %v", tenant, err)
					}
				}
				if _, err := sweeper.SweepIdentityEvidence(ctx, tenant); err != nil {
					log.Printf("[IdentityEvidence] tenant %s: %v", tenant, err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
