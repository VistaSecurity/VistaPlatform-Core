package services

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity/classproposal"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// The class floor sweep: re-ask "what is this?" for assets that are still on
// the unassigned floor and that nothing is observing any more.
//
// Intake promotes a floor asset when an observation MATCHES it
// (classOutcomeForResolution), over the evidence the asset has accumulated. An
// asset that is never observed again never gets that chance — and the evidence
// that would classify it can arrive WITHOUT an observation: the IEEE registry
// behind `oui_vendor` rules changes with a release, the curated rule table
// changes when an admin edits it, and the OUI vendor backfill writes vendors
// for assets nobody has seen since. This pass walks every live
// `unknown_host` / `external` asset whose class nobody declared, classifies its
// stored evidence alone, and offers the answer to [classproposal.Promote].
//
// # Promote only, never Record
//
// A sweep that raised proposals would put every unclassifiable or contested
// floor asset in the tenant into Approvals at once, every six hours, as a
// question nothing new prompted. Promote's five guards are what make a
// promotion safe without review — a rule, not a model; a decided class; never
// a declared asset; only from the floor; never a class a reviewer rejected —
// and an answer that fails them is simply left for the next observation to
// propose. A conflict is logged at debug with the asset id, so a curation bug
// is findable without being a queue item.

// classFloorSweepBatch is how many assets one transaction covers — the OUI
// vendor backfill's size, for the same reason (ouiVendorBackfillBatch).
const classFloorSweepBatch = 500

// classFloorCandidatesSQL pages, by asset id, through the tenant's live assets
// on the floor whose class nobody declared. Guard 3 and 4 of Promote, applied
// as a filter so the pass does not classify assets it could never move;
// Promote re-checks both on the row itself.
const classFloorCandidatesSQL = `
	SELECT a.id
	FROM assets a
	WHERE a.tenant_id = $1
	  AND a.deleted_at IS NULL
	  AND a.class_key = ANY($2)
	  AND a.class_source_kind IS DISTINCT FROM 'declared'
	  AND a.id > $3
	ORDER BY a.id
	LIMIT $4`

// ClassFloorSweepResult is what one tenant's pass did.
type ClassFloorSweepResult struct {
	Considered int
	Promoted   int
	Conflicts  int
}

// SweepClassFloor runs the class floor sweep for one tenant.
//
// Each batch is its own tenant-scoped transaction (RLS through
// pgidentity.RunInTx, the session every identity write uses), so a failure
// part-way loses at most one batch and the next pass picks it up. Idempotent: a
// promoted asset is no longer on the floor, so a second pass finds nothing to
// do for it. On success the counts and the time are recorded in
// class_floor_sweep_state.
func (s *AssetService) SweepClassFloor(ctx context.Context, tenantID uuid.UUID) (ClassFloorSweepResult, error) {
	var out ClassFloorSweepResult
	repo := pgidentity.New(s.db.DB.DB)
	tenant := tenantID.String()
	floor := []string{string(assetclass.KeyUnknownHost), string(assetclass.KeyExternal)}
	after := uuid.Nil
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		var batch []uuid.UUID
		var batchResult ClassFloorSweepResult
		err := repo.RunInTx(ctx, tenant, func(bound *pgidentity.Repository) error {
			batch = batch[:0]
			batchResult = ClassFloorSweepResult{}
			tx := bound.Tx()
			rows, err := tx.QueryContext(ctx, classFloorCandidatesSQL, tenantID, pq.Array(floor), after, classFloorSweepBatch)
			if err != nil {
				return fmt.Errorf("list floor assets: %w", err)
			}
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					_ = rows.Close()
					return fmt.Errorf("scan floor asset: %w", err)
				}
				batch = append(batch, id)
			}
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
			for _, id := range batch {
				promoted, conflict, err := s.sweepOneFloorAsset(ctx, tx, tenantID, id)
				if err != nil {
					return fmt.Errorf("asset %s: %w", id, err)
				}
				batchResult.Considered++
				if promoted {
					batchResult.Promoted++
				}
				if conflict {
					batchResult.Conflicts++
				}
			}
			return nil
		})
		if err != nil {
			return out, err
		}
		out.Considered += batchResult.Considered
		out.Promoted += batchResult.Promoted
		out.Conflicts += batchResult.Conflicts
		if len(batch) < classFloorSweepBatch {
			break
		}
		after = batch[len(batch)-1]
	}

	err := repo.RunInTx(ctx, tenant, func(bound *pgidentity.Repository) error {
		_, err := bound.Tx().ExecContext(ctx, `
			INSERT INTO class_floor_sweep_state (tenant_id, assets_considered, assets_promoted, conflicts, completed_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (tenant_id) DO UPDATE
			SET assets_considered = EXCLUDED.assets_considered,
			    assets_promoted = EXCLUDED.assets_promoted,
			    conflicts = EXCLUDED.conflicts,
			    completed_at = EXCLUDED.completed_at`,
			tenantID, out.Considered, out.Promoted, out.Conflicts)
		return err
	})
	if err != nil {
		return out, fmt.Errorf("record class floor sweep state: %w", err)
	}
	return out, nil
}

// sweepOneFloorAsset classifies one asset's stored evidence and offers the
// answer to Promote. It never calls Record.
func (s *AssetService) sweepOneFloorAsset(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID) (promoted, conflict bool, err error) {
	ev, err := storedClassEvidence(ctx, tx, tenantID, assetID)
	if err != nil {
		return false, false, err
	}
	prop := s.classifyEvidence(ctx, ev)
	if prop.Conflict {
		slog.Debug("class floor sweep: the rules disagree about this asset; leaving it on the floor",
			"tenant", tenantID, "asset", assetID, "classes", prop.ConflictingClasses)
		return false, true, nil
	}
	promoted, err = classproposal.Promote(ctx, tx, tenantID, assetID, prop)
	return promoted, false, err
}

// ClassFloorSweepTenants lists the live tenants the sweep walks: every one.
// The per-tenant pass is a single indexed query when a tenant has no floor
// asset, and walking them all is what keeps class_floor_sweep_state honest
// about when each tenant was last looked at. Reads across tenants, so it takes
// the BYPASS connection, like OUIVendorBackfillDueTenants.
func ClassFloorSweepTenants(ctx context.Context, bypass *sql.DB) ([]uuid.UUID, error) {
	rows, err := bypass.QueryContext(ctx, `SELECT id FROM tenants WHERE deleted_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
