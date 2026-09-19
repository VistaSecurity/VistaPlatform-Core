package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
)

// processApprovedDiscoveryCryptoData rechecks the resolved asset after acquiring
// its lifecycle lock. A concurrent merge can change the target between identity
// resolution and materialization; follow its durable redirect before any writes.
// Already-protected retained/deferred replay calls processDiscoveryCryptoData
// directly, avoiding nested session locks while a writer is waiting.
func (s *AssetService) processApprovedDiscoveryCryptoData(tenant, asset uuid.UUID, f IngestFinding,
	risk *[]*events.AssetRiskChangedPayload, crypto *[]*events.CryptoConfigurationAddedPayload, certs *[]*events.CertificateExpiringPayload) error {
	return s.withResolvedAssetLifecycle(context.Background(), tenant, asset, func(current uuid.UUID, status string, deleted bool) error {
		if deleted || status != "monitoring" {
			return ErrAssetLifecycleConflict
		}
		return s.processDiscoveryCryptoData(tenant, current, f, risk, crypto, certs)
	})
}

// withResolvedAssetLifecycle protects every write that follows identity resolution,
// including placement, endpoint hints and pending evidence. Resolve commits before
// these writes, so a merge may have redirected its result in the intervening time.
// The callback must not acquire another lifecycle lock for the same asset.
func (s *AssetService) withResolvedAssetLifecycle(ctx context.Context, tenant, asset uuid.UUID, fn func(uuid.UUID, string, bool) error) error {
	for attempt := 0; attempt < 8; attempt++ {
		var redirect uuid.UUID
		err := withAssetLifecycleReadLock(ctx, s.db.DB.DB, tenant, asset, func() error {
			var status, mergedInto string
			var deleted bool
			if err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
				return tx.QueryRowContext(ctx, `SELECT asset_status,deleted_at IS NOT NULL,COALESCE(metadata->>'merged_into','')
     FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&status, &deleted, &mergedInto)
			}); err != nil {
				return err
			}
			if mergedInto != "" {
				var err error
				redirect, err = uuid.Parse(mergedInto)
				if err == nil && redirect == uuid.Nil {
					return fmt.Errorf("asset merge redirect has no survivor")
				}
				return err
			}
			return fn(asset, status, deleted)
		})
		if err != nil {
			return err
		}
		if redirect == uuid.Nil {
			return nil
		}
		asset = redirect
	}
	return fmt.Errorf("asset merge redirect chain requires reconciliation")
}
