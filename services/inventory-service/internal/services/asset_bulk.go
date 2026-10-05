// Package services: bulk writes over a resolved asset selection.
//
// Each write reports how many assets it CHANGED, which is not how many it was
// given: archiving a selection that is half archived already changes half of
// it, and the person is told both numbers. Only a changed asset gets a history
// row — an `archived` entry on an asset that was already archived is a second
// decision nobody made.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// bulkChunk bounds one transaction of a bulk write, and the advisory locks a
// delete takes for it. A 5000-asset selection is ten short transactions rather
// than one that holds 5000 row locks while it writes 5000 history rows.
const bulkChunk = 500

func chunkIDs(ids []uuid.UUID, n int) [][]uuid.UUID {
	var out [][]uuid.UUID
	for len(ids) > 0 {
		k := min(n, len(ids))
		out = append(out, ids[:k])
		ids = ids[k:]
	}
	return out
}

// ArchiveAssets archives the given assets that are not archived already and
// returns how many it moved. It is the person-initiated counterpart of
// UpdateStaleStatus(…, "archived", …): the same column, the same `archived`
// history row and the same event — but only for the assets it actually moved.
func (s *AssetLifecycleService) ArchiveAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, actor uuid.UUID) (int, error) {
	var moved []uuid.UUID
	for _, chunk := range chunkIDs(assetIDs, bulkChunk) {
		err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			var ids []uuid.UUID
			if e := tx.Select(&ids, `
				UPDATE assets SET stale_status = 'archived', updated_at = NOW()
				 WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
				   AND stale_status IS DISTINCT FROM 'archived'
				RETURNING id`, tenantID, pq.Array(chunk)); e != nil {
				return e
			}
			for _, id := range ids {
				s.recordArchive(tx, tenantID, id, actor)
			}
			moved = append(moved, ids...)
			return nil
		})
		if err != nil {
			return len(moved), fmt.Errorf("archive assets: %w", err)
		}
	}
	if len(moved) > 0 && s.events != nil {
		decided := ""
		if actor != uuid.Nil {
			decided = actor.String()
		}
		if e := s.events.PublishAssetLifecycle(context.Background(), tenantID,
			invevents.EventTypeAssetArchived,
			&invevents.AssetLifecyclePayload{AssetIDs: moved, Status: "archived", DecidedBy: decided},
			"lifecycle"); e != nil {
			log.Printf("[AssetLifecycleService] archive committed but the event was not published: %v", e)
		}
	}
	return len(moved), nil
}

// UnarchiveAssets returns archived assets to active inventory and returns how
// many it moved. The staleness job still owns the column afterwards: an asset
// that stays unseen past the policy's archive threshold is archived again on
// its next sweep, which the UI says before the person confirms.
func (s *AssetLifecycleService) UnarchiveAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, actor uuid.UUID) (int, error) {
	var actorArg any
	if actor != uuid.Nil {
		actorArg = actor
	}
	moved := 0
	for _, chunk := range chunkIDs(assetIDs, bulkChunk) {
		err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			var ids []uuid.UUID
			if e := tx.Select(&ids, `
				UPDATE assets SET stale_status = 'active', updated_at = NOW()
				 WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
				   AND stale_status = 'archived'
				RETURNING id`, tenantID, pq.Array(chunk)); e != nil {
				return e
			}
			// An `updated` row, not a new action: asset_history_action_check
			// is a fixed vocabulary, and "the stale status went back to
			// active, by this person" is exactly what an update row says.
			for _, id := range ids {
				if _, e := tx.Exec(`
					INSERT INTO asset_history (asset_id, tenant_id, actor_user_id, source, action, changes_json)
					VALUES ($1, $2, $3, 'lifecycle', 'updated', $4::jsonb)`,
					id, tenantID, actorArg, `{"stale_status":"active","source_kind":"declared","bulk":true}`); e != nil {
					log.Printf("[AssetLifecycleService] history: recording un-archive for asset %s failed: %v", id, e)
				}
			}
			moved += len(ids)
			return nil
		})
		if err != nil {
			return moved, fmt.Errorf("restore assets: %w", err)
		}
	}
	return moved, nil
}

// DeleteAssets soft-deletes the given assets and returns how many it deleted.
// It does per chunk what DeleteAsset does per asset — under the lifecycle
// write locks, so a delete cannot interleave with an approval or a merge of
// the same asset — and publishes the same `asset.deleted` event per asset.
func (s *AssetService) DeleteAssets(tenantID uuid.UUID, assetIDs []uuid.UUID) (int, error) {
	ctx := context.Background()
	var deleted []uuid.UUID
	for _, chunk := range chunkIDs(assetIDs, bulkChunk) {
		err := withAssetLifecycleWriteTx(ctx, s.db, tenantID, chunk, func(tx *sqlx.Tx) error {
			var ids []uuid.UUID
			if e := tx.Select(&ids, `
				UPDATE assets SET deleted_at = NOW()
				 WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
				RETURNING id`, tenantID, pq.Array(chunk)); e != nil {
				return e
			}
			deleted = append(deleted, ids...)
			return nil
		})
		if err != nil {
			return len(deleted), fmt.Errorf("delete assets: %w", err)
		}
	}
	if s.eventPublisher != nil {
		for _, id := range deleted {
			if err := s.eventPublisher.PublishAssetDeleted(ctx, tenantID, id, "manual"); err != nil {
				log.Printf("[AssetService] Warning: Failed to publish asset deleted event: %v", err)
			}
		}
	}
	return len(deleted), nil
}

// BulkAssetChanges is a field edit applied to every asset in a selection.
//
// A nil field is left as it is. A field set to "" is CLEARED — the person
// ticked "Clear", which is a different instruction from not touching it. Tags
// are merged, never replaced: replacing would erase every tag a selection of
// different assets carried for the sake of adding one.
type BulkAssetChanges struct {
	OwnerEmail   *string
	Environment  *string
	BusinessUnit *string
	SupportGroup *string
	AddTags      map[string]string
	RemoveTags   []string
}

// ErrBulkChangesInvalid is a field edit that changes nothing or names a value
// the column cannot hold.
var ErrBulkChangesInvalid = errors.New("invalid changes")

// bulkEnvironments is `environment_type`.
var bulkEnvironments = map[string]bool{"production": true, "staging": true, "development": true, "test": true}

// maxBulkTags bounds the tags one edit adds or removes.
const maxBulkTags = 50

// Normalize trims and validates the edit in place. It is idempotent, so a
// handler can refuse a bad edit before resolving a large selection and the
// write can still call it.
func (c *BulkAssetChanges) Normalize() error {
	trim := func(p *string) *string {
		if p == nil {
			return nil
		}
		v := strings.TrimSpace(*p)
		return &v
	}
	c.OwnerEmail, c.Environment = trim(c.OwnerEmail), trim(c.Environment)
	c.BusinessUnit, c.SupportGroup = trim(c.BusinessUnit), trim(c.SupportGroup)
	if c.Environment != nil {
		v := strings.ToLower(*c.Environment)
		c.Environment = &v
		if v != "" && !bulkEnvironments[v] {
			return fmt.Errorf("%w: environment %q is not one of production, staging, development, test", ErrBulkChangesInvalid, v)
		}
	}
	if c.OwnerEmail != nil && *c.OwnerEmail != "" {
		if _, err := mail.ParseAddress(*c.OwnerEmail); err != nil {
			return fmt.Errorf("%w: owner email %q is not an email address", ErrBulkChangesInvalid, *c.OwnerEmail)
		}
	}
	add := map[string]string{}
	for k, v := range c.AddTags {
		k = strings.TrimSpace(k)
		if k == "" {
			return fmt.Errorf("%w: a tag needs a name", ErrBulkChangesInvalid)
		}
		add[k] = strings.TrimSpace(v)
	}
	c.AddTags = add
	var remove []string
	for _, k := range c.RemoveTags {
		if k = strings.TrimSpace(k); k != "" {
			remove = append(remove, k)
		}
	}
	c.RemoveTags = remove
	if len(c.AddTags)+len(c.RemoveTags) > maxBulkTags {
		return fmt.Errorf("%w: at most %d tags can be added or removed at once", ErrBulkChangesInvalid, maxBulkTags)
	}
	if c.OwnerEmail == nil && c.Environment == nil && c.BusinessUnit == nil && c.SupportGroup == nil &&
		len(c.AddTags) == 0 && len(c.RemoveTags) == 0 {
		return fmt.Errorf("%w: nothing to change", ErrBulkChangesInvalid)
	}
	return nil
}

// BulkUpdateAssets applies one field edit to every asset in the selection and
// returns how many assets it changed. An asset the edit would leave as it was
// is not written and gets no history row.
func (s *AssetService) BulkUpdateAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, changes BulkAssetChanges, actor uuid.UUID) (int, error) {
	if err := changes.Normalize(); err != nil {
		return 0, err
	}
	// $1 tenant, $2 ids; the edit's own parameters follow.
	args := []any{tenantID, nil}
	var sets, differs []string
	history := map[string]any{"bulk": true}
	column := func(col string, v *string, cast string) {
		if v == nil {
			return
		}
		var arg any
		if *v != "" {
			arg = *v
		}
		args = append(args, arg)
		p := fmt.Sprintf("$%d%s", len(args), cast)
		sets = append(sets, col+" = "+p)
		differs = append(differs, col+" IS DISTINCT FROM "+p)
		history[col] = *v
	}
	column("owner_email", changes.OwnerEmail, "::text")
	column("environment", changes.Environment, "::environment_type")
	column("business_unit", changes.BusinessUnit, "::text")
	column("support_group", changes.SupportGroup, "::text")
	if len(changes.AddTags) > 0 || len(changes.RemoveTags) > 0 {
		add, err := json.Marshal(changes.AddTags)
		if err != nil {
			return 0, fmt.Errorf("marshal tags: %w", err)
		}
		remove := changes.RemoveTags
		if remove == nil {
			remove = []string{}
		}
		args = append(args, string(add), pq.Array(remove))
		merged := fmt.Sprintf("((COALESCE(tags, '{}'::jsonb) || $%d::jsonb) - $%d::text[])", len(args)-1, len(args))
		sets = append(sets, "tags = "+merged)
		differs = append(differs, "COALESCE(tags, '{}'::jsonb) IS DISTINCT FROM "+merged)
		if len(changes.AddTags) > 0 {
			history["tags_added"] = changes.AddTags
		}
		if len(changes.RemoveTags) > 0 {
			history["tags_removed"] = changes.RemoveTags
		}
	}
	q := `UPDATE assets SET ` + strings.Join(sets, ", ") + `, updated_at = NOW()
		WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
		  AND (` + strings.Join(differs, " OR ") + `)
		RETURNING id`

	var changed []uuid.UUID
	for _, chunk := range chunkIDs(assetIDs, bulkChunk) {
		args[1] = pq.Array(chunk)
		err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			var ids []uuid.UUID
			if e := tx.Select(&ids, q, args...); e != nil {
				return e
			}
			// Every attribute change is attributable (ADR-0002 D4): a person,
			// declared, on the same transaction as the write. The map is
			// copied per asset because the history writer annotates it.
			for _, id := range ids {
				entry := make(map[string]any, len(history)+1)
				for k, v := range history {
					entry[k] = v
				}
				s.recordAssetHistoryBy(tx, tenantID, id, actor, identity.ActionUpdated,
					identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}, entry)
			}
			changed = append(changed, ids...)
			return nil
		})
		if err != nil {
			return len(changed), fmt.Errorf("update assets: %w", err)
		}
	}
	// The single-asset edit tells downstream consumers about an environment
	// change (compliance scoping reads it); a bulk one must too.
	if changes.Environment != nil && s.eventPublisher != nil {
		for _, id := range changed {
			if err := s.eventPublisher.PublishAssetChanged(context.Background(), tenantID, id, sharedevents.ChangeTypeUpdated, "manual"); err != nil {
				log.Printf("[AssetService] Warning: Failed to publish asset updated event: %v", err)
			}
		}
	}
	return len(changed), nil
}
