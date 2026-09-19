package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	identitypg "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// ExecuteMerge validates the server revision again under the ownership locks.
// The revision also makes an identical request replayable after sources archive.
func (s *MergeProposalService) ExecuteMerge(ctx context.Context, tenant, proposal, actor uuid.UUID, in MergeExecutionRequest) (*AssetMergeResult, error) {
	selection, ids, err := normalizeMergeSelection(in.MergeSelection)
	if err != nil {
		return nil, err
	}
	in.MergeSelection = selection
	if len(strings.TrimSpace(in.Reason)) < 3 || len(in.Reason) > 2000 || len(in.Revision) != 64 {
		return nil, ErrMergeSelection
	}
	var result AssetMergeResult
	err = identitypg.WithAssetLifecycleWriteLocks(ctx, s.db.DB.DB, tenant, ids, func() error {
		return database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
			if err := lockMergeEnrichmentPolicy(ctx, tx, tenant, true); err != nil {
				return err
			}
			if err := lockMergeSelection(ctx, tx, tenant, ids); err != nil {
				return err
			}
			var encoded []byte
			err := tx.QueryRowContext(ctx, `SELECT result FROM asset_merge_audits WHERE tenant_id=$1 AND revision=$2`, tenant, in.Revision).Scan(&encoded)
			if err == nil {
				if err := json.Unmarshal(encoded, &result); err != nil {
					return err
				}
				if result.SurvivorAssetID != in.SurvivorAssetID || fmt.Sprint(result.SourceAssetIDs) != fmt.Sprint(in.SourceAssetIDs) {
					return ErrMergePreviewChanged
				}
				result.Replayed = true
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			snap, err := readMergeSnapshot(ctx, tx, tenant, ids)
			if err != nil {
				return err
			}
			preview, err := buildMergePreview(in.MergeSelection, proposal, snap)
			if err != nil {
				return err
			}
			if preview.Revision != in.Revision {
				return ErrMergePreviewChanged
			}
			for _, conflict := range preview.Conflicts {
				if conflict.RequiresResolution {
					if _, ok := in.FieldResolutions[conflict.Field]; !ok {
						return ErrMergeFieldResolution
					}
				}
			}
			if err := preserveMergeEnrichmentPolicy(ctx, tx, tenant, in.SurvivorAssetID, actor, in.SourceAssetIDs, strings.TrimSpace(in.Reason)); err != nil {
				return err
			}
			if err := applyMergeManagement(ctx, tx, tenant, in.SurvivorAssetID, preview); err != nil {
				return err
			}
			if err := applyMergeFields(ctx, tx, tenant, in.SurvivorAssetID, preview, snap); err != nil {
				return err
			}
			_, managementSelected := preview.SelectedFields["management_profile"]
			for _, source := range in.SourceAssetIDs {
				if err := moveAssetChildren(ctx, tx, tenant, source, in.SurvivorAssetID, managementSelected); err != nil {
					return err
				}
				if err := recomputeAssetRiskTx(tx, tenant, source); err != nil {
					return err
				}
			}
			if err := recomputeMergePackageCounts(ctx, tx, tenant, in.SurvivorAssetID); err != nil {
				return err
			}
			if err := recomputeAssetRiskTx(tx, tenant, in.SurvivorAssetID); err != nil {
				return err
			}
			if err := reconcileMergeProposals(ctx, tx, tenant, actor, in.SourceAssetIDs, in.SurvivorAssetID, snap.Proposals); err != nil {
				return err
			}
			// Snapshot the committed dispositions before archiving the sources. No raw
			// secrets or opaque payloads are copied to the user-readable audit.
			after, err := readMergeSnapshot(ctx, tx, tenant, ids)
			if err != nil {
				return err
			}
			changes := mergeRecordChanges(snap.Records, after.Records)
			result = AssetMergeResult{ID: uuid.New(), SurvivorAssetID: in.SurvivorAssetID, SourceAssetIDs: in.SourceAssetIDs}
			if err := tx.QueryRowContext(ctx, `SELECT transaction_timestamp()`).Scan(&result.MergedAt); err != nil {
				return err
			}
			for _, source := range in.SourceAssetIDs {
				if _, err := tx.ExecContext(ctx, `UPDATE assets SET asset_status='archived',stale_status='archived',metadata=metadata||jsonb_build_object('merged_into',$3::text),updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, source, in.SurvivorAssetID.String()); err != nil {
					return err
				}
				if err := writeMergeHistory(ctx, tx, tenant, source, actor, "merged_into", map[string]any{"merge_id": result.ID, "merged_into": in.SurvivorAssetID, "reason": strings.TrimSpace(in.Reason)}); err != nil {
					return err
				}
			}
			history := map[string]any{"merge_id": result.ID, "proposal_id": proposal, "source_asset_ids": in.SourceAssetIDs, "reason": strings.TrimSpace(in.Reason), "source_snapshots": preview.Assets, "field_decisions": in.FieldResolutions, "selected_fields": preview.SelectedFields, "record_changes": changes, "revision": in.Revision, "management_profile_references": mergeManagementProfiles(snap), "enrichment_policy_before": snap.EnrichmentPolicy, "enrichment_policy_after": after.EnrichmentPolicy}
			if err := writeMergeHistory(ctx, tx, tenant, in.SurvivorAssetID, actor, "merged_from", history); err != nil {
				return err
			}
			// Preserve original child evidence for every moved/coalesced row. The
			// public audit lists identifiers only; secret-bearing rows stay internal.
			for table, records := range snap.Records {
				if table == "assets" {
					continue
				}
				for _, record := range records {
					if _, err := tx.ExecContext(ctx, `INSERT INTO asset_merge_record_snapshots(tenant_id,merge_id,record_table,record_key,record) VALUES($1,$2,$3,$4,$5::jsonb)`, tenant, result.ID, table, record.Key, []byte(record.Data)); err != nil {
						return err
					}
				}
			}
			pending := []invevents.Envelope{}
			for _, source := range in.SourceAssetIDs {
				pending = append(pending, invevents.Envelope{EventID: uuid.NewSHA1(result.ID, []byte(source.String())), EventType: invevents.EventTypeAssetMerged, TenantID: tenant, Timestamp: result.MergedAt, Source: "approvals", Payload: &invevents.AssetMergedPayload{SurvivorAssetID: in.SurvivorAssetID, MergedAssetID: source, ClassKey: mergeString(preview.SelectedFields["class_key"]), ProposalID: proposal, DecidedBy: actor.String()}})
			}
			pendingJSON, _ := json.Marshal(pending)
			audit, _ := json.Marshal(history)
			encoded, _ = json.Marshal(result)
			_, err = tx.ExecContext(ctx, `INSERT INTO asset_merge_audits(tenant_id,id,revision,actor_user_id,reason,survivor_asset_id,source_asset_ids,proposal_id,audit,result,pending_events) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb)`, tenant, result.ID, in.Revision, nullableUUID(actor), strings.TrimSpace(in.Reason), in.SurvivorAssetID, pq.Array(in.SourceAssetIDs), nullableUUID(proposal), audit, encoded, pendingJSON)
			return err
		})
	})
	if err != nil {
		return nil, err
	}
	if s.events != nil {
		if _, err := s.PublishPendingMergeEvents(ctx, tenant); err != nil {
			log.Printf("[MergeProposalService] merge %s committed; publication queued for retry: %v", result.ID, err)
		}
	}
	return &result, nil
}
func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func applyMergeFields(ctx context.Context, tx *sqlx.Tx, tenant, survivor uuid.UUID, preview *AssetMergePreview, snap mergeSnapshot) error {
	assignments := []string{}
	args := []any{tenant, survivor}
	for _, field := range mergeEditableFields {
		value := preview.selectedRaw[field]
		if field == "attributes" || field == "tags" {
			encoded, _ := json.Marshal(value)
			value = string(encoded)
		}
		args = append(args, value)
		assignments = append(assignments, fmt.Sprintf("%s=$%d", field, len(args)))
	}
	// Classification is a unit: never carry a selected class with another
	// asset's path, producer or confidence.
	selectedClass := survivor
	if choice, ok := preview.FieldResolutions["class_key"]; ok {
		selectedClass = choice
	}
	for _, a := range snap.Assets {
		if a["id"] != selectedClass.String() {
			continue
		}
		for _, field := range []string{"class_path", "class_source_kind", "class_source_ref", "class_confidence"} {
			args = append(args, a[field])
			assignments = append(assignments, fmt.Sprintf("%s=$%d", field, len(args)))
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET `+strings.Join(assignments, ",")+`,updated_at=now() WHERE tenant_id=$1 AND id=$2`, args...); err != nil {
		return err
	}
	// These are actual observation windows, never the time of this decision.
	_, err := tx.ExecContext(ctx, `UPDATE assets SET first_discovered_at=(SELECT min(first_discovered_at) FROM assets WHERE tenant_id=$1 AND id=ANY($3)),last_seen_at=(SELECT max(last_seen_at) FROM assets WHERE tenant_id=$1 AND id=ANY($3)) WHERE tenant_id=$1 AND id=$2`, tenant, survivor, pq.Array(append(append([]uuid.UUID{}, preview.SourceAssetIDs...), survivor)))
	if err != nil {
		return err
	}
	if provenance, changed := mergeNameProvenance(survivor, preview, snap); changed {
		_, err = tx.ExecContext(ctx, `UPDATE assets SET metadata=(metadata-'name_source_kind')||jsonb_build_object('name_source_kind',$3::text) WHERE tenant_id=$1 AND id=$2`, tenant, survivor, provenance)
	}
	return err
}

// Names share one provenance marker in the identity pipeline. Explicit name
// decisions are declarations; filling a missing name must retain the donor's
// protection without replacing the survivor's other metadata.
func mergeNameProvenance(survivor uuid.UUID, preview *AssetMergePreview, snap mergeSnapshot) (string, bool) {
	for _, field := range []string{"display_name", "hostname"} {
		if _, ok := preview.FieldResolutions[field]; ok {
			return "declared", true
		}
	}
	var current map[string]any
	for _, asset := range snap.Assets {
		if asset["id"] == survivor.String() {
			current = asset
			break
		}
	}
	if mergeDeclared(current, "display_name") {
		return "", false
	}
	provenance := ""
	changed := false
	for _, field := range []string{"display_name", "hostname"} {
		if mergeEmpty(preview.selectedRaw[field]) {
			continue
		}
		for _, donor := range snap.Assets {
			if donor["id"] == survivor.String() || donor[field] != preview.selectedRaw[field] {
				continue
			}
			if mergeDeclared(donor, field) {
				return "declared", true
			}
			if !changed && mergeEmpty(current["display_name"]) && mergeEmpty(current["hostname"]) {
				metadata, _ := donor["metadata"].(map[string]any)
				provenance, _ = metadata["name_source_kind"].(string)
				changed = true
			}
		}
	}
	return provenance, changed
}

type mergeRecordChange struct {
	Table       string `json:"table"`
	RecordID    string `json:"record_id"`
	Disposition string `json:"disposition"`
}

func mergeRecordChanges(before, after map[string][]mergeRecord) []mergeRecordChange {
	out := []mergeRecordChange{}
	for table, records := range before {
		if table == "assets" {
			continue
		}
		remaining := map[string]string{}
		for _, r := range after[table] {
			remaining[r.Key] = r.Digest
		}
		for _, r := range records {
			digest, ok := remaining[r.Key]
			disposition := "preserved"
			if !ok {
				disposition = "coalesced"
			} else if digest != r.Digest {
				disposition = "moved_or_reconciled"
			}
			out = append(out, mergeRecordChange{table, r.Key, disposition})
		}
	}
	for table, records := range after {
		seen := map[string]bool{}
		for _, r := range before[table] {
			seen[r.Key] = true
		}
		for _, r := range records {
			if !seen[r.Key] {
				out = append(out, mergeRecordChange{table, r.Key, "created_reconciliation_record"})
			}
		}
	}
	return out
}

// Refresh surviving questions; resolve only those whose explicit participants
// now identify the same asset. A third candidate remains an independent task.
func reconcileMergeProposals(ctx context.Context, tx *sqlx.Tx, tenant, actor uuid.UUID, sources []uuid.UUID, survivor uuid.UUID, proposals []json.RawMessage) error {
	moved := map[string]bool{}
	for _, id := range sources {
		moved[id.String()] = true
	}
	for _, raw := range proposals {
		var row struct {
			ID      uuid.UUID      `json:"id"`
			Changes map[string]any `json:"changes_json"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		if row.Changes["status"] != mergeStatusPending && row.Changes["status"] != mergeStatusKeptSeparate {
			continue
		}
		ids := map[string]bool{}
		if observation, ok := row.Changes["observation_asset_id"].(string); ok {
			if moved[observation] {
				observation = survivor.String()
				row.Changes["observation_asset_id"] = observation
			}
			ids[observation] = true
		}
		candidates := []any{}
		seen := map[string]bool{}
		if cs, ok := row.Changes["candidates"].([]any); ok {
			for _, c := range cs {
				v, ok := c.(map[string]any)
				if !ok {
					continue
				}
				id, _ := v["asset_id"].(string)
				if moved[id] {
					id = survivor.String()
					v["asset_id"] = id
				}
				ids[id] = true
				if !seen[id] {
					candidates = append(candidates, v)
					seen[id] = true
				}
			}
		}
		row.Changes["candidates"] = candidates
		if len(ids) <= 1 && row.Changes["status"] == mergeStatusPending {
			if err := resolveProposal(ctx, tx, tenant, row.ID, mergeStatusMerged, survivor, actor); err != nil {
				return err
			}
			continue
		}
		if row.Changes["status"] == mergeStatusPending {
			fingerprint := reconciledProposalFingerprint(row.Changes)
			var canonical uuid.UUID
			err := tx.QueryRowContext(ctx, `SELECT id FROM asset_history WHERE tenant_id=$1 AND id<>$2 AND action='merge_proposed' AND changes_json->>'kind'='merge_proposal' AND changes_json->>'status'='pending' AND changes_json->>'fingerprint'=$3 ORDER BY id LIMIT 1 FOR UPDATE`, tenant, row.ID, fingerprint).Scan(&canonical)
			if err == nil {
				row.Changes["status"] = "superseded"
				row.Changes["superseded_by"] = canonical.String()
				row.Changes["resolved_by"] = actor.String()
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			row.Changes["fingerprint"] = fingerprint
		}
		encoded, _ := json.Marshal(row.Changes)
		if _, err := tx.ExecContext(ctx, `UPDATE asset_history SET changes_json=$3::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, row.ID, encoded); err != nil {
			return err
		}
	}
	return nil
}

func reconciledProposalFingerprint(changes map[string]any) string {
	proposal := identity.MergeProposal{ObservationAssetID: mergeString(changes["observation_asset_id"])}
	candidates, _ := changes["candidates"].([]any)
	for _, raw := range candidates {
		candidate, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		matched, _ := json.Marshal(candidate["matched_identifiers"])
		var identifiers []identity.Identifier
		_ = json.Unmarshal(matched, &identifiers)
		proposal.Candidates = append(proposal.Candidates, identity.MergeCandidate{Ref: identity.AssetRef{ID: mergeString(candidate["asset_id"])}, MatchedIdentifiers: identifiers})
	}
	return identity.MergeProposalFingerprint(proposal)
}
