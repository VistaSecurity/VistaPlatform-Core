package jobs

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
)

func identityEnrichmentTenants(ctx context.Context, bypass *sql.DB) ([]uuid.UUID, error) {
	rows, err := bypass.QueryContext(ctx, `
		SELECT DISTINCT o.tenant_id
		FROM identity_observations o
		JOIN tenants t ON t.id=o.tenant_id
		WHERE t.deleted_at IS NULL
		  AND COALESCE(t.payment_status, '') <> ALL($1)
		ORDER BY o.tenant_id`, pq.Array(unscannableTenantStates))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var tenants []uuid.UUID
	for rows.Next() {
		var tenant uuid.UUID
		if err := rows.Scan(&tenant); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}

func StartIdentityEnrichmentWorker(ctx context.Context, bypass *sql.DB, coordinator *identityenrichment.Coordinator) {
	if !coordinator.Enabled {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		// RLS: cross-tenant enumeration only; the coordinator scopes every read,
		// claim, dispatch authorization and write to the tenant separately.
		tenants, err := identityEnrichmentTenants(ctx, bypass)
		if err != nil {
			log.Printf("[IdentityEnrichment] enumerate tenants: %v", err)
		} else {
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
