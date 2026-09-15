package services

// Asset context writes, and the history every one of them leaves behind
// (BUILD_PLAN workstream 0.6, folded into 1.2 because the engine is the first
// writer of the table and the two halves have to agree on its shape).
//
// The survey that opened this initiative found `asset_history` had NO writer at
// all — not a trigger, not Go, not the seed. The change history an inventory
// needs was a table with a read path and nothing else. Every attribute change
// below records one, with the provenance that made it, so "why is this asset
// like this?" has an answer.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// assetContextField is one column the context write may set. The list is fixed
// rather than built from the input map so a caller cannot reach a column this
// path has no business writing — class, identity and lifecycle all have their
// own owners.
type assetContextField struct {
	column string
	value  interface{}
	set    bool
}

// applyAssetContext writes the declared context of an asset — the fields a
// person or a system of record supplies — and records what changed.
//
// It writes only fields the caller actually supplied. "Empty never wins" (the
// discovery-envelope rule, ADR-0002 D4): a nil pointer is "not stated", not "set
// it to nothing", and letting a sparse import blank a tenant's carefully
// maintained owner_email is exactly the failure that rule exists to prevent.
// tx, when non-nil, is the transaction the identification engine is already
// running on, so the context write and its history row land with the identity
// rows or not at all (see AssetService.resolveObservationWith). Nil opens its
// own tenant-scoped transaction, which is what the paths that are not resolving
// an observation do.
func (s *AssetService) applyAssetContext(tx *sqlx.Tx, tenantID, assetID uuid.UUID, in models.AssetInput, source identity.Source, outcome identity.Outcome) error {
	fields := []assetContextField{
		{column: "environment", value: nullableEnum(in.Environment), set: in.Environment != nil},
		{column: "business_unit", value: in.BusinessUnit, set: in.BusinessUnit != nil},
		{column: "owner_email", value: in.OwnerEmail, set: in.OwnerEmail != nil},
		{column: "support_group", value: in.SupportGroup, set: in.SupportGroup != nil},
		{column: "description", value: in.Description, set: in.Description != nil},
		// Physical placement, as the supplying source names it (a NetBox site
		// and its region, a CMDB location). Same "empty never wins" rule as
		// every field above: nil is "not stated", so a later import that does
		// not carry a site cannot blank the one a tenant set by hand.
		{column: "site", value: in.Site, set: in.Site != nil},
		{column: "region", value: in.Region, set: in.Region != nil},
	}

	setClauses := []string{}
	args := []interface{}{}
	changes := map[string]any{}
	idx := 1
	for _, f := range fields {
		if !f.set {
			continue
		}
		clause := fmt.Sprintf("%s = $%d", f.column, idx)
		if f.column == "environment" {
			clause = fmt.Sprintf("environment = $%d::environment_type", idx)
		}
		setClauses = append(setClauses, clause)
		args = append(args, f.value)
		changes[f.column] = f.value
		idx++
	}

	// Tags and attributes MERGE rather than replace, for the same reason: an
	// import that carries one tag must not delete the other four.
	if len(in.Tags) > 0 {
		b, err := json.Marshal(in.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("tags = COALESCE(tags, '{}'::jsonb) || $%d::jsonb", idx))
		args = append(args, string(b))
		changes["tags"] = in.Tags
		idx++
	}
	if len(in.Attributes) > 0 {
		b, err := json.Marshal(in.Attributes)
		if err != nil {
			return fmt.Errorf("marshal attributes: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("attributes = COALESCE(attributes, '{}'::jsonb) || $%d::jsonb", idx))
		args = append(args, string(b))
		changes["attributes"] = in.Attributes
		idx++
	}
	if len(in.Metadata) > 0 {
		b, err := json.Marshal(in.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("metadata = COALESCE(metadata, '{}'::jsonb) || $%d::jsonb", idx))
		args = append(args, string(b))
		// Metadata is the only merged column the `changes` map used to omit, so
		// a change to it produced a history row saying nothing changed. The
		// discovery-source attribution the Approvals filters read travels in
		// here, which makes "which collector put this in front of me" one of
		// the questions the timeline could not answer about itself.
		changes["metadata"] = in.Metadata
		idx++
	}
	if in.AssetOwnership != nil {
		setClauses = append(setClauses, fmt.Sprintf("asset_ownership = $%d", idx))
		args = append(args, *in.AssetOwnership)
		changes["asset_ownership"] = *in.AssetOwnership
		idx++
	}
	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf(`UPDATE assets SET %s, updated_at = NOW() WHERE tenant_id = $%d AND id = $%d`,
		strings.Join(setClauses, ", "), idx, idx+1)
	args = append(args, tenantID, assetID)

	if err := s.exec(tx, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	}); err != nil {
		return fmt.Errorf("failed to apply asset context: %w", err)
	}
	if len(changes) == 0 {
		return nil
	}
	action := identity.ActionUpdated
	if outcome == identity.OutcomeCreated {
		action = identity.ActionCreated
	}
	s.recordAssetHistory(tx, tenantID, assetID, action, source, changes)
	return nil
}

// exec runs fn on the caller's transaction when there is one, and on a fresh
// tenant-scoped transaction otherwise. It is the one place that decision is
// made, so no write in this file can accidentally escape the engine's unit of
// work by opening a second transaction.
func (s *AssetService) exec(tx *sqlx.Tx, tenantID uuid.UUID, fn func(*sqlx.Tx) error) error {
	if tx != nil {
		return fn(tx)
	}
	return database.WithTenantTx(context.Background(), s.db, tenantID, fn)
}

// setAssetStatus moves an asset through the approval lifecycle and records it.
// tx as in applyAssetContext.
func (s *AssetService) setAssetStatus(tx *sqlx.Tx, tenantID, assetID uuid.UUID, status string, source identity.Source) error {
	// The UPDATE carries `asset_status <> $1`, so a poll that re-asserts the
	// status the asset already has changes NOTHING. The history entry was
	// written unconditionally anyway: a monitored host observed every fifteen
	// minutes accumulated ninety-six `approved` rows a day, each claiming an
	// approval that never happened, and the asset's timeline — the thing a
	// reviewer reads six months later to find out who accepted this — was
	// drowned in them.
	var moved int64
	if err := s.exec(tx, tenantID, func(tx *sqlx.Tx) error {
		res, err := tx.Exec(`
			UPDATE assets
			SET asset_status = $1, stale_status = NULL, updated_at = NOW()
			WHERE tenant_id = $2 AND id = $3 AND asset_status <> $1`,
			status, tenantID, assetID)
		if err != nil {
			return err
		}
		moved, err = res.RowsAffected()
		return err
	}); err != nil {
		return fmt.Errorf("failed to set asset status: %w", err)
	}
	if moved == 0 {
		// Nothing changed, so there is nothing to record. History is a log of
		// changes, not of attempts.
		return nil
	}
	action := identity.ActionUpdated
	switch status {
	case "monitoring":
		action = identity.ActionApproved
	case "denied":
		action = identity.ActionDenied
	case "archived":
		action = identity.ActionArchived
	}
	s.recordAssetHistory(tx, tenantID, assetID, action, source, map[string]any{"asset_status": status})
	return nil
}

// recordAssetHistory appends one asset_history row.
//
// It logs rather than returns an error on purpose: history is evidence of a
// change that already happened, and failing the caller after the change
// committed would report a failure that did not occur. A lost entry is a real
// loss, so it is logged loudly rather than swallowed.
func (s *AssetService) recordAssetHistory(tx *sqlx.Tx, tenantID, assetID uuid.UUID, action identity.HistoryAction, source identity.Source, changes map[string]any) {
	s.recordAssetHistoryBy(tx, tenantID, assetID, uuid.Nil, action, source, changes)
}

// recordAssetHistoryBy is recordAssetHistory with the PERSON who caused the
// change.
//
// `asset_history.actor_user_id` existed and had no writer in this service, so
// every human decision the timeline recorded was anonymous: "approved" with
// nothing saying by whom. uuid.Nil writes NULL, which is the honest value for a
// collector — empty is not "system", it is "no person was involved".
func (s *AssetService) recordAssetHistoryBy(tx *sqlx.Tx, tenantID, assetID, actor uuid.UUID, action identity.HistoryAction, source identity.Source, changes map[string]any) {
	if changes == nil {
		changes = map[string]any{}
	}
	if source.Kind != "" {
		changes["source_kind"] = string(source.Kind)
	}
	payload, err := json.Marshal(changes)
	if err != nil {
		log.Printf("[AssetService] history: marshalling %s for asset %s failed: %v", action, assetID, err)
		return
	}
	ref := strings.TrimSpace(source.Ref)
	if ref == "" {
		ref = string(source.Kind)
	}
	if ref == "" {
		// asset_history.source is NOT NULL and a change with no producer cannot
		// be audited. Recording "unknown" says that out loud instead of
		// pretending the row has provenance.
		ref = "unknown"
	}
	var actorArg any
	if actor != uuid.Nil {
		actorArg = actor
	}
	err = s.exec(tx, tenantID, func(tx *sqlx.Tx) error {
		return withSavepoint(tx, "asset_history", func() error {
			_, e := tx.Exec(`
				INSERT INTO asset_history (asset_id, tenant_id, actor_user_id, source, action, changes_json)
				VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
				assetID, tenantID, actorArg, ref, string(action), string(payload))
			return e
		})
	})
	if err != nil {
		log.Printf("[AssetService] history: recording %s for asset %s failed: %v", action, assetID, err)
	}
}

// withSavepoint runs fn inside a SAVEPOINT and rolls back to it on failure.
//
// This function is what makes "log rather than return" SAFE on a transaction the
// caller owns. Postgres aborts the whole transaction on any statement error, so
// swallowing a failed INSERT does not leave the caller where it was — it leaves
// the caller holding a poisoned transaction whose NEXT statement fails with
// "current transaction is aborted", several frames away from the statement that
// actually broke. The approval path found that immediately: a history row
// rejected by its actor foreign key aborted the deny that was writing it.
//
// A savepoint contains the damage to the one statement, so the log line is true
// — one lost entry — instead of a lie about a transaction that is already dead.
func withSavepoint(tx *sqlx.Tx, name string, fn func() error) error {
	if _, err := tx.Exec("SAVEPOINT " + name); err != nil {
		return err
	}
	if err := fn(); err != nil {
		if _, rbErr := tx.Exec("ROLLBACK TO SAVEPOINT " + name); rbErr != nil {
			return fmt.Errorf("%w (and rolling back to the savepoint failed: %v)", err, rbErr)
		}
		return err
	}
	_, err := tx.Exec("RELEASE SAVEPOINT " + name)
	return err
}

// nullableEnum turns an empty string into a NULL so an enum column is not handed
// "" — which is not a member of any enum and would abort the statement.
func nullableEnum(v *string) interface{} {
	if v == nil || strings.TrimSpace(*v) == "" {
		return nil
	}
	return *v
}
