package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/database"
)

// AssetLifecycleLockKey names the shared lifecycle lock for one tenant asset.
func AssetLifecycleLockKey(tenant, asset uuid.UUID) string {
	return "asset-lifecycle:" + tenant.String() + ":" + asset.String()
}

// LockAssetLifecycleRows locks parents before children are moved. Call within
// WithAssetLifecycleWriteLocks after any identifier ownership locks, so lock
// waiting never consumes a data-pool connection needed by ongoing replay.
func LockAssetLifecycleRows(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, assets []uuid.UUID) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM assets WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id FOR UPDATE`, tenant, pq.Array(assets))
	if err != nil {
		return fmt.Errorf("lock asset lifecycle rows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
	}
	return rows.Err()
}

// WithAssetLifecycleWriteLocks acquires exclusive lifecycle locks on the
// dedicated control pool BEFORE the callback opens any data transaction. The
// tenant snapshot key comes first because live host ingestion resolves its asset
// only after starting a multi-transaction snapshot.
func WithAssetLifecycleWriteLocks(ctx context.Context, db *sql.DB, tenant uuid.UUID, assets []uuid.UUID, fn func() error) error {
	locks := make([]database.SessionAdvisoryLock, 0, len(assets)+1)
	locks = append(locks, database.SessionAdvisoryLock{Key: HostSnapshotLockKey(tenant)})
	for _, asset := range assets {
		locks = append(locks, database.SessionAdvisoryLock{Key: AssetLifecycleLockKey(tenant, asset)})
	}
	return database.WithSessionAdvisoryLocks(ctx, db, locks, fn)
}

// WithAssetLifecycleReadLock protects multi-transaction materialization using
// the dedicated control pool. The callback rechecks current ownership and
// approval. Include other required session locks in one combined call to
// database.WithSessionAdvisoryLocks rather than nesting lock helpers.
func WithAssetLifecycleReadLock(ctx context.Context, db *sql.DB, tenant, asset uuid.UUID, fn func() error) error {
	return database.WithSessionAdvisoryLocks(ctx, db, []database.SessionAdvisoryLock{{Key: AssetLifecycleLockKey(tenant, asset), Shared: true}}, fn)
}
