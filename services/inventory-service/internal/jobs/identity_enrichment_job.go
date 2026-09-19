package jobs

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
)

func StartIdentityEnrichmentWorker(ctx context.Context, bypass *sql.DB, coordinator *identityenrichment.Coordinator) {
	if !coordinator.Enabled {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		// RLS: cross-tenant enumeration only; the coordinator scopes every read,
		// claim, dispatch authorization and write to the tenant separately.
		rows, err := bypass.QueryContext(ctx, `SELECT DISTINCT o.tenant_id FROM identity_observations o JOIN tenants t ON t.id=o.tenant_id WHERE t.status='active' ORDER BY o.tenant_id`)
		if err != nil {
			log.Printf("[IdentityEnrichment] enumerate tenants: %v", err)
		} else {
			var tenants []uuid.UUID
			for rows.Next() {
				var tenant uuid.UUID
				if err := rows.Scan(&tenant); err != nil {
					log.Printf("[IdentityEnrichment] tenant row: %v", err)
					break
				}
				tenants = append(tenants, tenant)
			}
			if err := rows.Err(); err != nil {
				log.Printf("[IdentityEnrichment] tenants: %v", err)
			}
			_ = rows.Close()
			for _, tenant := range tenants {
				if ctx.Err() != nil {
					return
				}
				if err := coordinator.Sweep(ctx, tenant); err != nil {
					log.Printf("[IdentityEnrichment] tenant %s: %v", tenant, err)
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
