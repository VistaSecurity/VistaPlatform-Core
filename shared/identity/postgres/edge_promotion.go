package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// PromoteEdgesForApproved activates the pending edges of newly approved
// assets whose OTHER end is already monitored — except inferred ones, which
// ADR-0003 D3 / ADR-0008 D3 send to a human as relationship proposals.
//
// It is the one implementation of "approving an asset approves what was
// observed about it". inventory-service's Approvals path calls it, and so does
// any intake that approves an asset itself — device-interrogation-service's
// cloud intake under an account-level auto-approval rule (asset-inventory
// ADR-0009 D5). Two copies of this statement would be two answers to when an
// edge is live.
//
// The `peer` join enforces the other end being approved, and is why this is
// one statement rather than a loop: approving several assets that reference
// each other promotes the edges BETWEEN them too, because the caller has
// already set all of them to monitoring.
func PromoteEdgesForApproved(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, assetIDs []uuid.UUID) error {
	if len(assetIDs) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE asset_relationships r
		   SET status = 'active', approved_at = NOW(), updated_at = NOW()
		  FROM assets peer
		 WHERE r.tenant_id = $1
		   AND r.status = 'pending'
		   AND r.source_kind <> 'inferred'
		   AND (
		        (r.from_asset_id = ANY($2) AND peer.id = r.to_asset_id)
		     OR (r.to_asset_id   = ANY($2) AND peer.id = r.from_asset_id)
		   )
		   AND peer.tenant_id = $1
		   AND peer.deleted_at IS NULL
		   AND peer.asset_status = 'monitoring'`,
		tenantID, pq.Array(assetIDs))
	if err != nil {
		return fmt.Errorf("failed to promote relationships for approved assets: %w", err)
	}
	return nil
}
