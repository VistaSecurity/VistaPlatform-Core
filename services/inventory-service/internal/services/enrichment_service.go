// Package services: asset enrichment (segment + service identification backfill).
package services

import (
	"context"
	"database/sql"
	"log"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// EnrichAllAssets re-runs segment and service identification for all assets of a tenant (backfill).
//
// It walks ENDPOINTS, not assets: the port a service is identified from and the
// identified service itself both live on `asset_endpoints` now (DATA_MODEL §2).
// An asset with no endpoint — an at-rest cloud resource — still appears once,
// with a NULL endpoint, so its segment enrichment is not skipped.
func (s *AssetService) EnrichAllAssets(tenantID uuid.UUID) (updated int, err error) {
	if s.networkSegmentService == nil && s.serviceIdentificationSvc == nil {
		return 0, nil
	}
	const batchSize = 100
	offset := 0
	enriched := map[uuid.UUID]bool{}
	for {
		var batch []struct {
			AssetID    uuid.UUID     `db:"asset_id"`
			EndpointID uuid.NullUUID `db:"endpoint_id"`
			IP         sql.NullString
			Hostname   sql.NullString
			Port       sql.NullInt64
		}
		// RLS-scoped read over assets + asset_endpoints. Scoped per batch (not
		// around the whole loop) so the networkSegmentService /
		// serviceIdentificationSvc calls below open their own tenant
		// transactions rather than nesting inside this one.
		//
		// ORDER BY is over (asset, endpoint) so the LIMIT/OFFSET paging is
		// stable across batches.
		err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.Select(&batch, `
				SELECT a.id AS asset_id,
				       e.id AS endpoint_id,
				       host(COALESCE(e.address, a.primary_address)) AS ip,
				       a.hostname AS hostname,
				       e.port AS port
				FROM assets a
				LEFT JOIN asset_endpoints e ON e.tenant_id = a.tenant_id AND e.asset_id = a.id
				WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
				ORDER BY a.id, e.id NULLS FIRST LIMIT $2 OFFSET $3`,
				tenantID, batchSize, offset)
		})
		if err != nil {
			return updated, err
		}
		if len(batch) == 0 {
			break
		}
		for _, a := range batch {
			var ip, host *string
			if a.IP.Valid {
				ip = &a.IP.String
			}
			if a.Hostname.Valid {
				host = &a.Hostname.String
			}
			assetUpdated := false
			// Once per asset: the segment is a property of the host, and the
			// same asset appears once per endpoint in this batch.
			if s.networkSegmentService != nil && !enriched[a.AssetID] {
				enriched[a.AssetID] = true
				if e := s.networkSegmentService.EnrichAssetByID(tenantID, a.AssetID, ip, host); e == nil {
					assetUpdated = true
				}
			}
			if s.serviceIdentificationSvc != nil && a.EndpointID.Valid {
				port := 0
				if a.Port.Valid {
					port = int(a.Port.Int64)
				}
				protocol := "TLS"
				if port == 22 {
					protocol = "SSH"
				}
				hints := s.serviceIdentificationSvc.IdentifyService(tenantID, port, protocol, nil)
				if hints != nil {
					ver := hints.ServiceVersion
					// RLS-scoped write over asset_endpoints, which is where the
					// identified service lives.
					wErr := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
						_, e := tx.Exec(`
							UPDATE asset_endpoints SET service_name = $1, service_version = NULLIF($2, ''),
								service_confidence = $3, service_identification_method = $4, updated_at = NOW()
							WHERE id = $5 AND tenant_id = $6`,
							hints.ServiceName, ver, hints.Confidence, hints.IdentificationMethod,
							a.EndpointID.UUID, tenantID)
						return e
					})
					if wErr != nil {
						// Not fatal to the backfill, but it must not be counted
						// as an update: a write that failed did not enrich
						// anything, and reporting it as one is how a silent
						// no-op looks like success.
						log.Printf("[AssetService] EnrichAllAssets: writing the identified service to endpoint %s failed: %v", a.EndpointID.UUID, wErr)
					} else {
						assetUpdated = true
					}
				}
			}
			if assetUpdated {
				updated++
			}
		}
		offset += len(batch)
		if len(batch) < batchSize {
			break
		}
	}
	return updated, nil
}
