package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
)

// PublishPendingMergeEvents drains a bounded tenant-scoped transactional outbox.
// SKIP LOCKED permits multiple workers; stable envelope IDs make delivery safe
// when publication succeeds but the database acknowledgement is interrupted.
func (s *MergeProposalService) PublishPendingMergeEvents(ctx context.Context, tenant uuid.UUID) (int, error) {
	if s.events == nil {
		return 0, fmt.Errorf("merge event publisher unavailable")
	}
	delivered := 0
	var publishErr error
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id,pending_events FROM asset_merge_audits WHERE tenant_id=$1 AND events_published_at IS NULL AND pending_events <> '[]'::jsonb AND events_next_attempt_at <= now() ORDER BY created_at,id LIMIT 20 FOR UPDATE SKIP LOCKED`, tenant)
		if err != nil {
			return err
		}
		type pending struct {
			id  uuid.UUID
			raw []byte
		}
		var pendingRows []pending
		for rows.Next() {
			var row pending
			if err := rows.Scan(&row.id, &row.raw); err != nil {
				_ = rows.Close()
				return err
			}
			pendingRows = append(pendingRows, row)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		for _, row := range pendingRows {
			var events []invevents.Envelope
			if err := json.Unmarshal(row.raw, &events); err != nil {
				return err
			}
			remaining := events
			for len(remaining) > 0 {
				event := remaining[0]
				if event.TenantID != tenant {
					return fmt.Errorf("merge event tenant mismatch")
				}
				publishCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := s.events.PublishMergeEvent(publishCtx, event)
				cancel()
				if err != nil {
					publishErr = err
					break
				}
				remaining = remaining[1:]
				delivered++
			}
			encoded, err := json.Marshal(remaining)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE asset_merge_audits SET pending_events=$3::jsonb,events_published_at=CASE WHEN $4 THEN now() ELSE NULL END,events_next_attempt_at=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, row.id, encoded, len(remaining) == 0); err != nil {
				return err
			}
			if publishErr != nil {
				break
			}
		}
		return nil
	})
	return delivered, errors.Join(err, publishErr)
}
