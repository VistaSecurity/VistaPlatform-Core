package services

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// assetChangeTracker decides, for one IngestFindings call, which of the assets
// it resolved get a `compliance.asset.changed` event.
//
// The rule (documented for readers of the event in
// docsv4/internal/developer/design/asset-inventory/ASSET_EVENTS.md): an ingest
// publishes asset.changed for an asset only when it changed something a
// compliance evaluator can read. A pure re-sighting - the same observation again,
// moving only last_seen / observation counters - publishes nothing, because the
// evaluation it would trigger can only reproduce the verdict already stored.
//
// An asset counts as changed when ANY of these holds:
//
//  1. it was created by this ingest (outcome created / conflict / provisional);
//  2. asset_history gained a row for it during the call - the same decision
//     that records identity, attribute, endpoint, class and approval/status
//     changes, reused rather than re-derived (see changedByHistory);
//  3. the crypto materialisation altered something an evaluator reads (a new or
//     enriched configuration, a moved leaf certificate, a new or content-changed
//     certificate, a moved risk score, a new or changed at-rest posture);
//  4. segment enrichment moved the asset's environment/location/segment/
//     business unit/site/tags, or service identification moved an endpoint's
//     service, or the TLS handshake outcome of an endpoint moved.
type assetChangeTracker struct {
	touched  []uuid.UUID
	seen     map[uuid.UUID]bool
	material map[uuid.UUID]bool
}

func newAssetChangeTracker() *assetChangeTracker {
	return &assetChangeTracker{seen: map[uuid.UUID]bool{}, material: map[uuid.UUID]bool{}}
}

// touch records that the ingest resolved the asset (it is a candidate, not yet
// a change).
func (t *assetChangeTracker) touch(id uuid.UUID) {
	if !t.seen[id] {
		t.seen[id] = true
		t.touched = append(t.touched, id)
	}
}

// changed records a material change to the asset (and that it was resolved).
func (t *assetChangeTracker) changed(id uuid.UUID) {
	t.touch(id)
	t.material[id] = true
}

// historyWatermark takes a position in asset_history's append order.
//
// asset_history.created_at cannot be the yardstick: the identification engine
// stamps its rows with the OBSERVATION's time, which is earlier than the moment
// the row is written, so a row this call wrote could predate a clock read taken
// before it. The `seq` column is the append counter and "the ONLY thing that
// can order this table" (schema.sql), so a value drawn from its sequence
// before any finding is resolved is strictly below the seq of every row this
// call then writes. (A drawn value is simply never used; the sequence has gaps
// already.)
func (s *AssetService) historyWatermark(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var mark int64
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT nextval('public.asset_history_seq_seq')`).Scan(&mark)
	})
	return mark, err
}

// assetsWithHistoryAfter returns which of ids gained an asset_history row after
// the watermark. This is the engine's own "something about this asset changed"
// record, so ingest does not keep a second opinion about it. A concurrent
// writer's row for the same asset can also match: that is a false positive
// (one extra evaluation of an asset that did change), never a miss.
func (s *AssetService) assetsWithHistoryAfter(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID, mark int64) (map[uuid.UUID]bool, error) {
	out := map[uuid.UUID]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryxContext(ctx, `
			SELECT DISTINCT asset_id FROM asset_history
			 WHERE tenant_id = $1 AND asset_id = ANY($2) AND seq > $3`,
			tenantID, pq.Array(ids), mark)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read asset history after seq %d: %w", mark, err)
	}
	return out, nil
}

// changedByHistory returns the resolved assets that changed, in resolution
// order. markOK is false when the batch-start watermark could not be read; every
// resolved asset is then reported, which is the old behaviour and the safe
// direction - an extra evaluation is cheap, a missed change is a stale verdict.
func (s *AssetService) changedByHistory(ctx context.Context, tenantID uuid.UUID, t *assetChangeTracker, mark int64, markOK bool) []uuid.UUID {
	if !markOK {
		return t.touched
	}
	var undecided []uuid.UUID
	for _, id := range t.touched {
		if !t.material[id] {
			undecided = append(undecided, id)
		}
	}
	withHistory, err := s.assetsWithHistoryAfter(ctx, tenantID, undecided, mark)
	if err != nil {
		log.Printf("[AssetService] IngestFindings: could not read asset history to decide which assets changed (publishing for all %d resolved): %v", len(t.touched), err)
		return t.touched
	}
	var out []uuid.UUID
	for _, id := range t.touched {
		if t.material[id] || withHistory[id] {
			out = append(out, id)
		}
	}
	return out
}
