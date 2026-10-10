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

// metadataProvenanceKeys are the metadata entries that name the WRITE rather
// than describe the asset: the batch an observation arrived in and the sensor
// that sent it. Every observation carries a fresh batch id, and a host two
// sensors can hear alternates its sensor id, so a timeline that counted them
// as changes wrote a row per observation of a host nothing had happened to.
// They are still stored (the merge below refreshes them, and the asset's
// metadata is shown and edited as a whole); they just never earn a row on
// their own.
//
// `host_observation_attributes` and `host_observation_sources` are the same
// kind of entry: they describe the SIGHTING (the capture interface, which mDNS
// service answered on which port, whether a reflector relayed it, which
// collector heard it), not the asset. The merge replaces each wholesale, so a
// host that announces two services, or is heard by both mDNS and ARP, flips
// them on every observation; one asset wrote ~100 `updated` rows an hour that
// way on a quiet install (840 of 861 in six hours were this alone).
var metadataProvenanceKeys = []string{
	"batch_id", "sensor_id",
	"host_observation_attributes", "host_observation_sources",
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
//
// An `updated` row is written only for what the write CHANGED, judged against
// the row as stored, not against the input: a sensor re-stating the ownership,
// tags and discovery source an asset already has, every coalescing window,
// changes nothing, and a timeline row per window buried the few that said
// something. On creation, everything the asset was created with is folded into
// the identification engine's own `created` row (foldIntoCreatedHistory), so a
// new asset has one `created` row, not two.
//
// Listing is not this function's to record. The first time an import or a
// declaration lists an asset is written by the identification engine
// (`listed_by`, shared/identity applyToAsset) on the same transaction, whether
// or not the listing changed any context, and the import-only scan-consent
// state is cleared off the resolution (createAssetResolved), not off a row
// here.
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

	// Every SET expression reads the target row as `a`, because the statement
	// also joins the pre-update copy `p` and an unqualified column would be
	// ambiguous between them. `changed` collects, per `changes` key, the
	// RETURNING predicate that says whether that key's stored value moved.
	setClauses := []string{}
	changed := []string{}
	keys := []string{}
	args := []interface{}{}
	changes := map[string]any{}
	idx := 1
	track := func(key, predicate string) {
		keys = append(keys, key)
		changed = append(changed, predicate)
	}
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
		track(f.column, fmt.Sprintf("p.%[1]s IS DISTINCT FROM a.%[1]s", f.column))
		idx++
	}

	// Tags and attributes MERGE rather than replace, for the same reason: an
	// import that carries one tag must not delete the other four.
	if len(in.Tags) > 0 {
		b, err := json.Marshal(in.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("tags = COALESCE(a.tags, '{}'::jsonb) || $%d::jsonb", idx))
		args = append(args, string(b))
		changes["tags"] = in.Tags
		track("tags", "COALESCE(p.tags, '{}'::jsonb) IS DISTINCT FROM a.tags")
		idx++
	}
	if len(in.Attributes) > 0 {
		b, err := json.Marshal(in.Attributes)
		if err != nil {
			return fmt.Errorf("marshal attributes: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("attributes = COALESCE(a.attributes, '{}'::jsonb) || $%d::jsonb", idx))
		args = append(args, string(b))
		changes["attributes"] = in.Attributes
		track("attributes", "COALESCE(p.attributes, '{}'::jsonb) IS DISTINCT FROM a.attributes")
		idx++
	}
	if len(in.Metadata) > 0 {
		b, err := json.Marshal(in.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("metadata = COALESCE(a.metadata, '{}'::jsonb) || $%d::jsonb", idx))
		args = append(args, string(b))
		// Metadata is the only merged column the `changes` map used to omit, so
		// a change to it produced a history row saying nothing changed. The
		// discovery-source attribution the Approvals filters read travels in
		// here, which makes "which collector put this in front of me" one of
		// the questions the timeline could not answer about itself.
		changes["metadata"] = in.Metadata
		// Compared WITHOUT the per-write provenance (metadataProvenanceKeys):
		// a new batch id is not news about the asset.
		track("metadata", fmt.Sprintf(
			"(COALESCE(p.metadata, '{}'::jsonb) - $%[1]d::text[]) IS DISTINCT FROM (a.metadata - $%[1]d::text[])", idx+1))
		args = append(args, pq.Array(metadataProvenanceKeys))
		idx += 2
	}
	if in.AssetOwnership != nil {
		setClauses = append(setClauses, fmt.Sprintf("asset_ownership = $%d", idx))
		args = append(args, *in.AssetOwnership)
		changes["asset_ownership"] = *in.AssetOwnership
		track("asset_ownership", "p.asset_ownership IS DISTINCT FROM a.asset_ownership")
		idx++
	}
	if len(setClauses) == 0 {
		return nil
	}

	// `prior` is the row as stored, locked, so the RETURNING list compares
	// what this write found with what it left — the same shape
	// identity/postgres LinkObservation uses for its own history. The lock
	// is the one the UPDATE takes anyway, taken a statement earlier.
	query := fmt.Sprintf(`
		WITH prior AS (
			SELECT * FROM assets WHERE tenant_id = $%[2]d AND id = $%[3]d FOR UPDATE
		)
		UPDATE assets a SET %[1]s, updated_at = NOW()
		  FROM prior p
		 WHERE a.tenant_id = p.tenant_id AND a.id = p.id
		RETURNING %[4]s`,
		strings.Join(setClauses, ", "), idx, idx+1, strings.Join(changed, ", "))
	args = append(args, tenantID, assetID)

	moved := make([]bool, len(keys))
	found := true
	if err := s.exec(tx, tenantID, func(tx *sqlx.Tx) error {
		dest := make([]any, len(moved))
		for i := range moved {
			dest[i] = &moved[i]
		}
		err := tx.QueryRow(query, args...).Scan(dest...)
		if errors.Is(err, sql.ErrNoRows) {
			// No such asset row: nothing was written, so there is nothing
			// to record either.
			found = false
			return nil
		}
		return err
	}); err != nil {
		return fmt.Errorf("failed to apply asset context: %w", err)
	}
	if !found {
		return nil
	}
	action := identity.ActionUpdated
	if outcome == identity.OutcomeCreated {
		// The asset did not exist a moment ago, so everything it was created
		// with is the record, whether or not the engine's insert happened to
		// default a column to the same value.
		action = identity.ActionCreated
	} else {
		// History is a log of changes, not of attempts (setAssetStatus).
		// Only the keys whose stored value moved are named.
		for i, k := range keys {
			if !moved[i] {
				delete(changes, k)
			}
		}
	}
	if len(changes) == 0 {
		return nil
	}
	if action == identity.ActionCreated && s.foldIntoCreatedHistory(tx, tenantID, assetID, source, changes) {
		return nil
	}
	s.recordAssetHistory(tx, tenantID, assetID, action, source, changes)
	return nil
}

// foldIntoCreatedHistory adds the context an asset was created with to the
// `created` row the identification engine wrote for it moments earlier on
// the same transaction, and reports whether it did ( F6).
//
// A new asset used to get TWO `created` rows: the engine's (class,
// identifiers, endpoints) and this file's (tags, attributes, metadata,
// ownership). The timeline showed the asset being created twice, and anything
// counting creations counted it twice. One creation is one row, carrying
// everything the asset was born with.
//
// It folds only into a row with the SAME producer (asset_history.source) this
// write would have recorded, so a context write from some other source is
// never misattributed to the engine's; the engine's own keys win a collision
// (its `source_kind` is the same value). It folds only into a row THIS
// transaction wrote (xmin = the current transaction id), so a caller that
// passes ActionCreated for an asset that already existed can never rewrite an
// older audit row. False — nothing folded — when there is no such row (a
// caller that created the asset some other way) or the
// UPDATE failed; the caller then writes its own row, which is the old
// behaviour.
func (s *AssetService) foldIntoCreatedHistory(tx *sqlx.Tx, tenantID, assetID uuid.UUID, source identity.Source, changes map[string]any) bool {
	payload, err := json.Marshal(changes)
	if err != nil {
		log.Printf("[AssetService] history: marshalling created context for asset %s failed: %v", assetID, err)
		return false
	}
	folded := false
	err = s.exec(tx, tenantID, func(tx *sqlx.Tx) error {
		return withSavepoint(tx, "asset_history_created_fold", func() error {
			res, e := tx.Exec(`
				UPDATE asset_history
				   SET changes_json = $4::jsonb || changes_json
				 WHERE id = (
					SELECT id FROM asset_history
					 WHERE tenant_id = $1 AND asset_id = $2 AND action = 'created' AND source = $3
					   AND xmin::text = pg_current_xact_id()::xid::text
					 ORDER BY seq DESC
					 LIMIT 1)`,
				tenantID, assetID, historySourceRef(source), string(payload))
			if e != nil {
				return e
			}
			n, e := res.RowsAffected()
			folded = e == nil && n == 1
			return e
		})
	})
	if err != nil {
		log.Printf("[AssetService] history: folding created context into asset %s's created row failed; recording it separately: %v", assetID, err)
		return false
	}
	return folded
}

// historySourceRef is the asset_history.source value for source — the same
// spelling the identification engine's history writer uses, so the two can be
// matched.
func historySourceRef(source identity.Source) string {
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
	return ref
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

// setStatusUnlessArchived applies a DISCOVERY-derived status, except to an
// asset the tenant has ARCHIVED.
//
// Archiving is a decision, and a re-discovery does not undo it — the same rule
// ingest already applies to `denied`, and for the same reason. Without this, a
// device the tenant deliberately archived and that later reappeared on a segment
// with an auto-approval rule was silently promoted back to `monitoring` (with an
// `approved` history entry naming no person), and its certificates and crypto
// configuration materialized on the next observation. An auto-approval rule
// matching the segment something reappeared on is not a person changing their
// mind.
//
// It reads inside the CALLER's transaction, so what it tests is the status this
// same unit of work will overwrite — not one another transaction may have moved
// since.
func (s *AssetService) setStatusUnlessArchived(tx *sqlx.Tx, tenantID, assetID uuid.UUID, status string, source identity.Source) error {
	var current string
	if err := s.exec(tx, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT asset_status FROM assets
			WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, assetID).Scan(&current)
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No such live asset. Nothing to move, and nothing to report: the
			// caller's own write would have matched no row either.
			return nil
		}
		return fmt.Errorf("reading asset status before applying %q: %w", status, err)
	}
	if current == identity.StatusArchived {
		log.Printf("[AssetService] asset %s is archived; a discovery does not restore it to %q", assetID, status)
		return nil
	}
	return s.setAssetStatus(tx, tenantID, assetID, status, source)
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
	ref := historySourceRef(source)
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
