package services

// Run provenance and run undo for a source (platform ADR-0002 D11 item 6).
//
// A system-of-record connector running outside this service (the CMDB sync)
// tags every asset one of its runs created or wrote to
// with that run's id, and can later undo the run — which ARCHIVES the assets
// the run created, never deletes them. Both are writes to the inventory's own
// data (the asset timeline and the lifecycle), so both happen here, behind the
// same HMAC-only, signed-tenant gate as every other source route: the
// connector never touches these tables.
//
// Undo archives an asset only when it is safe to say the run brought it in:
//
//   - the asset's timeline carries this source's tag that THIS run CREATED it
//     (RecordRun, below) — a caller's claim about an asset id is not enough;
//   - no other source has reported it: no identifier, fact or endpoint from a
//     sensor, an agent, an interrogation or another system of record. An asset
//     the platform itself has seen is kept, whatever the run did;
//   - it is not merged into another asset.
//
// Anything else is reported back as kept, with the reason, and left alone.

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// Run actions a source may tag an asset with.
const (
	SourceRunCreated = "created"
	SourceRunUpdated = "updated"
)

// SourceRunItem is one asset a source's run created or wrote to.
type SourceRunItem struct {
	AssetID uuid.UUID `json:"asset_id"`
	// Action is "created" (the run brought the asset in) or "updated" (the run
	// matched an asset and wrote to it).
	Action string `json:"action"`
}

// Outcomes of a run-undo item.
const (
	SourceUndoArchived        = "archived"
	SourceUndoAlreadyArchived = "already_archived"
	SourceUndoKept            = "kept"
)

// SourceUndoResult is what undo did to one asset.
type SourceUndoResult struct {
	AssetID uuid.UUID `json:"asset_id"`
	// Outcome is archived, already_archived, kept (Reason says why),
	// not_found (no asset of this tenant has that id) or error.
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// runArchiver archives assets the way a person does from the inventory
// (AssetLifecycleService.UpdateStaleStatus): the lifecycle's archive, its
// history entry and its event.
type runArchiver interface {
	UpdateStaleStatus(tenantID uuid.UUID, assetIDs []uuid.UUID, status string, actorUserID uuid.UUID) error
}

// WithArchiver wires the lifecycle archive undo uses. Without it undo refuses.
func (s *SourceImportService) WithArchiver(a runArchiver) *SourceImportService {
	s.archiver = a
	return s
}

// historyKeySourceRun is the asset_history changes key a run tag lives under.
const historyKeySourceRun = "source_run"

// RecordRun tags assets with the run that created or wrote to them: an
// `updated` entry on each asset's timeline, naming the source and the run.
// Only the tenant's assets; any other id is not_found.
func (s *SourceImportService) RecordRun(ctx context.Context, tenantID uuid.UUID, source identity.Source, runID uuid.UUID, items []SourceRunItem) ([]SourceItemResult, error) {
	ids := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.AssetID)
	}
	owned, err := s.tenantAssets(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("could not read the tenant's assets: %w", err)
	}
	out := make([]SourceItemResult, 0, len(items))
	for _, it := range items {
		if it.Action != SourceRunCreated && it.Action != SourceRunUpdated {
			out = append(out, SourceItemResult{Outcome: SourceOutcomeError, Error: fmt.Sprintf("action %q is not created or updated", it.Action)})
			continue
		}
		if !owned[it.AssetID] {
			out = append(out, SourceItemResult{Outcome: SourceItemNotFound})
			continue
		}
		err := s.identity.RecordHistory(ctx, identity.HistoryEntry{
			TenantID: tenantID.String(), AssetID: it.AssetID.String(), Action: identity.ActionUpdated,
			Source: source,
			Changes: map[string]any{historyKeySourceRun: map[string]any{
				"source": source.Ref, "run_id": runID.String(), "action": it.Action,
			}},
			At: time.Now().UTC(),
		})
		if err != nil {
			out = append(out, SourceItemResult{Outcome: SourceOutcomeError, Error: err.Error()})
			continue
		}
		out = append(out, SourceItemResult{Outcome: SourceItemRecorded})
	}
	return out, nil
}

// undoCandidate is one asset's standing for undo.
type undoCandidate struct {
	id              uuid.UUID
	archived        bool
	merged          bool
	createdByRun    bool
	otherEvidence   string
	otherEvidenceOK bool
}

// ArchiveRunAssets undoes a run on the inventory side: it archives the given
// assets that run created (see the package comment for the rule) and reports
// every other one as kept. Never a delete.
func (s *SourceImportService) ArchiveRunAssets(ctx context.Context, tenantID uuid.UUID, source identity.Source,
	runID uuid.UUID, actor uuid.UUID, reason string, ids []uuid.UUID) ([]SourceUndoResult, error) {

	if s.archiver == nil {
		return nil, fmt.Errorf("archiving is not configured")
	}
	cands, err := s.undoCandidates(ctx, tenantID, source, runID, ids)
	if err != nil {
		return nil, fmt.Errorf("could not read the assets: %w", err)
	}
	out := make([]SourceUndoResult, 0, len(ids))
	var archive []uuid.UUID
	for _, id := range ids {
		c, ok := cands[id]
		switch {
		case !ok:
			out = append(out, SourceUndoResult{AssetID: id, Outcome: SourceItemNotFound})
		case c.archived:
			out = append(out, SourceUndoResult{AssetID: id, Outcome: SourceUndoAlreadyArchived})
		case c.merged:
			out = append(out, SourceUndoResult{AssetID: id, Outcome: SourceUndoKept, Reason: "merged into another asset"})
		case !c.createdByRun:
			out = append(out, SourceUndoResult{AssetID: id, Outcome: SourceUndoKept, Reason: "this run did not create it"})
		case c.otherEvidenceOK:
			out = append(out, SourceUndoResult{AssetID: id, Outcome: SourceUndoKept, Reason: "also reported by " + c.otherEvidence})
		default:
			archive = append(archive, id)
			out = append(out, SourceUndoResult{AssetID: id, Outcome: SourceUndoArchived})
		}
	}
	if len(archive) == 0 {
		return out, nil
	}
	if err := s.archiver.UpdateStaleStatus(tenantID, archive, "archived", actor); err != nil {
		return nil, fmt.Errorf("could not archive: %w", err)
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	for _, id := range archive {
		// The lifecycle wrote its own `archived` entry (who, when). This one
		// says why: which run of which source was undone.
		if err := s.identity.RecordHistory(ctx, identity.HistoryEntry{
			TenantID: tenantID.String(), AssetID: id.String(), Action: identity.ActionUpdated,
			Source: source,
			Changes: map[string]any{"source_run_undone": map[string]any{
				"source": source.Ref, "run_id": runID.String(), "reason": reason,
			}},
			At: time.Now().UTC(),
		}); err != nil {
			// The archive stands; a lost annotation is not a failed undo.
			for i := range out {
				if out[i].AssetID == id {
					out[i].Reason = "archived; the timeline note was not recorded: " + err.Error()
				}
			}
		}
	}
	return out, nil
}

// undoCandidates reads, for each id that is an asset of this tenant, what undo
// needs to decide.
func (s *SourceImportService) undoCandidates(ctx context.Context, tenantID uuid.UUID, source identity.Source,
	runID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]undoCandidate, error) {

	out := map[uuid.UUID]undoCandidate{}
	if len(ids) == 0 {
		return out, nil
	}
	raw := make([]string, 0, len(ids))
	for _, id := range ids {
		raw = append(raw, id.String())
	}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT a.id,
			       COALESCE(a.deleted_at IS NOT NULL OR a.asset_status = 'archived' OR a.stale_status = 'archived', false) AS archived,
			       COALESCE(a.metadata->>'merged_into', '') <> '' AS merged,
			       EXISTS (
			         SELECT 1 FROM asset_history h
			          WHERE h.tenant_id = a.tenant_id AND h.asset_id = a.id AND h.source = $3
			            AND h.changes_json->'`+historyKeySourceRun+`'->>'run_id' = $4
			            AND h.changes_json->'`+historyKeySourceRun+`'->>'action' = 'created') AS created_by_run,
			       COALESCE((
			         SELECT e.who FROM (
			           SELECT COALESCE(NULLIF(i.source_ref, ''), i.source_kind) AS who FROM asset_identifiers i
			            WHERE i.tenant_id = a.tenant_id AND i.asset_id = a.id
			              AND COALESCE(i.source_ref, '') <> $3 AND i.source_kind IN ('measured', 'imported')
			           UNION ALL
			           SELECT COALESCE(NULLIF(f.source_ref, ''), f.source_kind) FROM asset_facts f
			            WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id
			              AND f.source_ref <> $3 AND f.source_kind IN ('measured', 'imported')
			           UNION ALL
			           SELECT COALESCE(NULLIF(ep.source_ref, ''), ep.source_kind) FROM asset_endpoints ep
			            WHERE ep.tenant_id = a.tenant_id AND ep.asset_id = a.id
			              AND COALESCE(ep.source_ref, '') <> $3 AND ep.source_kind IN ('measured', 'imported')
			         ) e LIMIT 1), '') AS other_evidence
			  FROM assets a
			 WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])`,
			tenantID, pq.Array(raw), source.Ref, runID.String())
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var c undoCandidate
			if err := rows.Scan(&c.id, &c.archived, &c.merged, &c.createdByRun, &c.otherEvidence); err != nil {
				return err
			}
			c.otherEvidenceOK = c.otherEvidence != ""
			out[c.id] = c
		}
		return rows.Err()
	})
	return out, err
}
