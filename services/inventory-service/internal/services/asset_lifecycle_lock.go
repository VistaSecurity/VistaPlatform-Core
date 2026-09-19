package services

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

var ErrAssetLifecycleConflict = errors.New("archived or merged assets cannot change approval; merged sources cannot be restored")

// Call under lifecycle write locks, before any batch side effects. Reject the
// entire stale batch rather than claiming approval for a survivor tombstone.
func checkAssetLifecycleMutable(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, assets []uuid.UUID) error {
	var blocked bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id=$1 AND id=ANY($2)
	 AND (asset_status='archived' OR NULLIF(metadata->>'merged_into','') IS NOT NULL))`, tenant, pq.Array(assets)).Scan(&blocked); err != nil {
		return err
	}
	if blocked {
		return ErrAssetLifecycleConflict
	}
	return nil
}

func checkAssetRestoreMutable(ctx context.Context, tx *sqlx.Tx, tenant, asset uuid.UUID) error {
	var merged bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id=$1 AND id=$2 AND NULLIF(metadata->>'merged_into','') IS NOT NULL)`, tenant, asset).Scan(&merged); err != nil {
		return err
	}
	if merged {
		return ErrAssetLifecycleConflict
	}
	return nil
}

func assetLifecycleLockKey(tenant, asset uuid.UUID) string {
	return pgidentity.AssetLifecycleLockKey(tenant, asset)
}

func withAssetLifecycleWriteTx(ctx context.Context, db *database.DB, tenant uuid.UUID, assets []uuid.UUID, fn func(*sqlx.Tx) error) error {
	return pgidentity.WithAssetLifecycleWriteLocks(ctx, db.DB.DB, tenant, assets, func() error {
		return database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
			if err := pgidentity.LockAssetLifecycleRows(ctx, tx.Tx, tenant, assets); err != nil {
				return err
			}
			return fn(tx)
		})
	})
}

func withAssetLifecycleReadLock(ctx context.Context, db *sql.DB, tenant, asset uuid.UUID, fn func() error) error {
	return pgidentity.WithAssetLifecycleReadLock(ctx, db, tenant, asset, fn)
}
