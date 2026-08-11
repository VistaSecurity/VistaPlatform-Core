// Package services: asset enrichment (segment + service identification backfill).
package services

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// EnrichAllAssets re-runs segment and service identification for all assets of a tenant (backfill).
func (s *AssetService) EnrichAllAssets(tenantID uuid.UUID) (updated int, err error) {
	if s.networkSegmentService == nil && s.serviceIdentificationSvc == nil {
		return 0, nil
	}
	const batchSize = 100
	offset := 0
	for {
		var batch []struct {
			ID       uuid.UUID
			IP       sql.NullString
			Hostname sql.NullString
			Port     sql.NullInt64
		}
		// RLS-scoped read over network_assets. Scoped per batch (not around the whole
		// loop) so the networkSegmentService / serviceIdentificationSvc calls below open
		// their own tenant transactions rather than nesting inside this one.
		err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.Select(&batch, `
				SELECT id, ip_address as ip, hostname, port FROM network_assets
				WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY id LIMIT $2 OFFSET $3`,
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
			if s.networkSegmentService != nil {
				if e := s.networkSegmentService.EnrichAssetByID(tenantID, a.ID, ip, host); e == nil {
					assetUpdated = true
				}
			}
			if s.serviceIdentificationSvc != nil {
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
					// RLS-scoped write over network_assets.
					_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
						_, e := tx.Exec(`
							UPDATE network_assets SET service_name = $1, service_version = NULLIF($2, ''),
								service_confidence = $3, service_identification_method = $4, updated_at = NOW()
							WHERE id = $5 AND tenant_id = $6`,
							hints.ServiceName, ver, hints.Confidence, hints.IdentificationMethod, a.ID, tenantID)
						return e
					})
					assetUpdated = true
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
