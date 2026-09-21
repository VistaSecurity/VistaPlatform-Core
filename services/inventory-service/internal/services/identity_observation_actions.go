package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

var ErrObservationNotFound = errors.New("observation not found")
var ErrObservationChanged = errors.New("observation has conflicting ownership or a completed decision; refresh before deciding")
var ErrObservationAllowance = errors.New("asset allowance reached; observation remains available for resolution")

// ErrObservationProvisionalMerge refuses "link to asset E" on an observation
// that already produced a PROVISIONAL inventory item ( D6).
//
// Linking would attach the evidence to E and leave the provisional asset behind
// as a second row describing the same device — which is precisely the duplicate
// the provisional model exists to avoid. Combining two inventory items is merge
// review's job, and merge review is where the operator gets to see what would
// be lost. The handler maps this to 409 with the code the UI switches on.
var ErrObservationProvisionalMerge = errors.New("provisional_item_requires_merge_review")

type ObservationDecisionInput struct {
	Reason  string     `json:"reason" binding:"required,max=2000"`
	AssetID *uuid.UUID `json:"asset_id,omitempty"`
	Name    string     `json:"name,omitempty" binding:"max=255"`
}

// DecideIdentityObservation serializes decisions on the observation row. Identity
// confirmation records a declaration; it never updates monitoring approval or
// manufactures a new sighting. Repeated decisions return the committed result.
func (s *AssetService) DecideIdentityObservation(ctx context.Context, tenant, id, actor uuid.UUID, action string, input ObservationDecisionInput) (identity.IngestResult, error) {
	var result identity.IngestResult
	if actor == uuid.Nil || strings.TrimSpace(input.Reason) == "" || len(input.Reason) > 2000 {
		return result, fmt.Errorf("actor and a reason of at most 2000 characters are required")
	}
	if action != "confirmed" && action != "linked" && action != "dismissed" {
		return result, fmt.Errorf("invalid observation action")
	}
	if action == "linked" && (input.AssetID == nil || *input.AssetID == uuid.Nil) {
		return result, fmt.Errorf("link requires an asset")
	}
	engine, err := s.identityEngine()
	if err != nil {
		return result, err
	}
	err = s.identityRepo.RunInTx(ctx, tenant.String(), func(repo *pgidentity.Repository) error {
		tx := repo.Tx()
		var raw []byte
		var state string
		var linked sql.NullString
		var seen time.Time
		// Read the fingerprint's current identifiers first, then acquire the
		// same ownership locks as ingest BEFORE locking the observation row.
		if err := tx.QueryRowContext(ctx, `SELECT evidence FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrObservationNotFound
			}
			return err
		}
		var before identity.Observation
		if err := json.Unmarshal(raw, &before); err != nil {
			return err
		}
		if err := repo.LockIdentifiers(ctx, tenant.String(), before.Identifiers); err != nil {
			return err
		}
		lockedKeys := make(map[string]bool, len(before.Identifiers))
		for _, rawID := range before.Identifiers {
			ident, err := rawID.Normalized()
			if err != nil {
				return err
			}
			lockedKeys[ident.Key()] = true
		}
		if err := tx.QueryRowContext(ctx, `SELECT evidence,state,asset_id,last_seen_at FROM identity_observations WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&raw, &state, &linked, &seen); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrObservationNotFound
			}
			return err
		}
		result = identity.IngestResult{Outcome: state, ObservationID: id.String(), AssetID: linked.String}
		if action == "dismissed" && state == "dismissed" {
			return nil
		}
		if linked.Valid {
			if action == "linked" && linked.String == input.AssetID.String() {
				return nil
			}
			if action == "confirmed" {
				var prior bool
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_observation_decisions WHERE tenant_id=$1 AND observation_id=$2 AND action='confirmed')`, tenant, id).Scan(&prior); err != nil {
					return err
				}
				if prior {
					return nil
				}
			}
			// D6. An observation linked to a PROVISIONAL asset is not a
			// decided observation — the platform guessed, and the operator is
			// now answering. Every other linked observation still refuses,
			// because for those the link IS the decision.
			var identityStatus string
			err := tx.QueryRowContext(ctx, `SELECT identity_status FROM assets
				WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenant, linked.String).Scan(&identityStatus)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrObservationChanged
			}
			if err != nil {
				return err
			}
			if identityStatus != string(identity.IdentityProvisional) {
				return ErrObservationChanged
			}
			switch action {
			case "linked":
				return ErrObservationProvisionalMerge
			case "confirmed":
				return s.confirmProvisionalItem(ctx, repo, tenant, id, actor, input, linked.String, state, &result)
			case "dismissed":
				return s.dismissProvisionalItem(ctx, repo, tenant, id, actor, input, linked.String, state, raw, &result)
			}
			return ErrObservationChanged
		}
		if state == "conflict" {
			return ErrObservationChanged
		}
		var obs identity.Observation
		if err := json.Unmarshal(raw, &obs); err != nil {
			return err
		}
		obs.TenantID = tenant.String()
		if action != "dismissed" {
			for _, rawID := range obs.Identifiers {
				ident, err := rawID.Normalized()
				if err != nil {
					return err
				}
				// Fingerprints fold alternate hostname spellings. If a sighting
				// replaced the evidence while locks were acquired, refresh rather
				// than inspect ownership of an identifier we have not locked.
				if !lockedKeys[ident.Key()] {
					return ErrObservationChanged
				}
				owners, err := repo.FindByIdentifier(ctx, tenant.String(), ident.Kind, ident.Value, ident.Scope)
				if err != nil {
					return err
				}
				for _, owner := range owners {
					if action == "confirmed" || owner.ID != input.AssetID.String() {
						return ErrObservationChanged
					}
				}
			}
			links, err := repo.ConfirmedObservationLinks(ctx, obs, id.String())
			if err != nil {
				return err
			}
			for _, previous := range links {
				if action == "confirmed" || previous.Asset.ID != input.AssetID.String() || previous.Unavailable {
					return ErrObservationChanged
				}
			}
		}
		var assetID string
		switch action {
		case "confirmed":
			allowed, err := repo.CheckAdmissionAllowance(ctx, tenant.String())
			if err != nil {
				return err
			}
			if !allowed {
				return ErrObservationAllowance
			}
			// The observation UUID is server-issued and tenant-scoped. An
			// observed alias remains evidence, never a declaration identifier.
			declared := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceDeclared, Ref: "operator:" + actor.String()},
				ObservedAt: seen, ClassHint: assetclass.KeyUnknownHost, DisplayName: strings.TrimSpace(input.Name),
				Admission:   identity.AdmissionEvidence{OperatorConfirmed: true},
				Identifiers: []identity.Identifier{{Kind: identity.KindDeclarationID, Value: id.String(), Scope: tenant.String(), Confidence: 1}}}
			res, err := engine.WithAutoAcceptThreshold(0).WithRepository(repo).Resolve(ctx, declared)
			if err != nil {
				return err
			}
			if res.Asset.Zero() || res.Outcome == identity.OutcomeConflict {
				return ErrObservationChanged
			}
			assetID = res.Asset.ID
		case "linked":
			assetID = input.AssetID.String()
			var status string
			if err := tx.QueryRowContext(ctx, `SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenant, assetID).Scan(&status); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrObservationNotFound
				}
				return err
			}
			if status == "archived" || status == "denied" {
				return ErrObservationChanged
			}
		}
		if assetID != "" {
			if err := repo.LinkObservation(ctx, tenant.String(), id.String(), assetID, identity.IdentityOperatorConfirmed); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE identity_observations SET confirmed_by=$3,confirmation_reason=$4,confirmed_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, id, actor, strings.TrimSpace(input.Reason)); err != nil {
				return err
			}
			result.AssetID = assetID
			result.Outcome = "linked"
		} else {
			if _, err := tx.ExecContext(ctx, `UPDATE identity_observations SET state='dismissed',updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
				return err
			}
			result.Outcome = "dismissed"
		}
		decisionDetails := map[string]any{"previous_state": state, "asset_id": assetID}
		if action == "dismissed" {
			// Keep the baseline immutable even as future sightings update the
			// observation summary. Time, spelling and replay are not new proof.
			decisionDetails["dismissed_evidence"] = obs
		}
		details, _ := json.Marshal(decisionDetails)
		if _, err := tx.ExecContext(ctx, `INSERT INTO identity_observation_decisions(tenant_id,observation_id,actor_id,action,reason,details) VALUES($1,$2,$3,$4,$5,$6)`, tenant, id, actor, action, strings.TrimSpace(input.Reason), string(details)); err != nil {
			return err
		}
		if assetID != "" {
			changes, _ := json.Marshal(map[string]any{"kind": "identity_confirmation", "observation_id": id, "decision": action, "reason": strings.TrimSpace(input.Reason)})
			_, err := tx.ExecContext(ctx, `INSERT INTO asset_history(tenant_id,asset_id,actor_user_id,source,action,changes_json) VALUES($1,$2,$3,'declared','updated',$4)`, tenant, assetID, actor, string(changes))
			return err
		}
		return nil
	})
	return result, err
}

// confirmProvisionalItem answers "confirm identity" on an observation that
// already produced a provisional inventory item ( D6).
//
// It promotes THAT asset rather than resolving a declared observation through
// the engine. The engine path would see a declaration identifier nothing owns
// and create a second asset — a brand-new operator-confirmed row beside the
// provisional one the operator was looking at when they clicked confirm, both
// describing the same device, with the evidence on one and the confirmation on
// the other. Never a second asset is the whole point of the provisional model.
func (s *AssetService) confirmProvisionalItem(ctx context.Context, repo *pgidentity.Repository, tenant, id, actor uuid.UUID, input ObservationDecisionInput, assetID, state string, result *identity.IngestResult) error {
	tx := repo.Tx()
	if err := repo.LinkObservation(ctx, tenant.String(), id.String(), assetID, identity.IdentityOperatorConfirmed); err != nil {
		return err
	}
	var promoted string
	if err := tx.QueryRowContext(ctx, `SELECT identity_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, assetID).Scan(&promoted); err != nil {
		return err
	}
	if promoted == string(identity.IdentityProvisional) {
		// LinkObservation applied the allowance check ( D1) and declined
		// the promotion, recording `asset_allowance_exhausted`. Returning the
		// error rolls this transaction back, which loses that reason and loses
		// nothing else: the evidence attached when the provisional asset was
		// created, and an operator who clicked confirm gets the allowance
		// answer as a status code rather than having to find it on a row.
		return ErrObservationAllowance
	}
	// The decision is itself an identifier — the server-issued declaration id
	// is what makes this asset findable from this observation ever after, and
	// it is exactly what the engine attaches on the non-provisional path.
	if err := repo.AttachIdentifiers(ctx, identity.AssetRef{TenantID: tenant.String(), ID: assetID}, []identity.Identifier{{
		Kind:       identity.KindDeclarationID,
		Value:      id.String(),
		Scope:      tenant.String(),
		Confidence: 1,
		Source:     identity.Source{Kind: identity.SourceDeclared, Ref: "operator:" + actor.String()},
	}}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE identity_observations SET confirmed_by=$3,confirmation_reason=$4,confirmed_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, id, actor, strings.TrimSpace(input.Reason)); err != nil {
		return err
	}
	result.AssetID = assetID
	result.Outcome = "linked"
	if err := recordObservationDecision(ctx, tx, tenant, id, actor, "confirmed", input.Reason, map[string]any{"previous_state": state, "asset_id": assetID}); err != nil {
		return err
	}
	changes, _ := json.Marshal(map[string]any{"kind": "identity_confirmation", "observation_id": id, "decision": "confirmed",
		"reason": strings.TrimSpace(input.Reason), "promoted_provisional": true})
	_, err := tx.ExecContext(ctx, `INSERT INTO asset_history(tenant_id,asset_id,actor_user_id,source,action,changes_json) VALUES($1,$2,$3,'declared','updated',$4)`, tenant, assetID, actor, string(changes))
	return err
}

// dismissProvisionalItem dismisses an observation that produced a provisional
// inventory item, and archives that item when nothing else vouches for it
// ( D6).
//
// "Nothing else" is any other observation of this asset that is not itself
// dismissed or expired. A provisional asset exists only because some evidence
// implied it; dismissing the last such evidence leaves an inventory row
// asserting a device on no one's authority, and leaving it monitored would make
// dismissal look like it did nothing.
//
// The observation KEEPS its asset_id. The asset is archived, not deleted, and a
// reviewer reading either row needs the other one to understand what happened.
func (s *AssetService) dismissProvisionalItem(ctx context.Context, repo *pgidentity.Repository, tenant, id, actor uuid.UUID, input ObservationDecisionInput, assetID, state string, raw []byte, result *identity.IngestResult) error {
	tx := repo.Tx()
	if _, err := tx.ExecContext(ctx, `UPDATE identity_observations SET state='dismissed',updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
		return err
	}
	result.AssetID = assetID
	result.Outcome = "dismissed"
	var obs identity.Observation
	if err := json.Unmarshal(raw, &obs); err != nil {
		return err
	}
	// Keep the baseline immutable even as future sightings update the
	// observation summary. Time, spelling and replay are not new proof.
	if err := recordObservationDecision(ctx, tx, tenant, id, actor, "dismissed", input.Reason,
		map[string]any{"previous_state": state, "asset_id": assetID, "dismissed_evidence": obs}); err != nil {
		return err
	}
	var vouched bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_observations
		WHERE tenant_id=$1 AND asset_id=$2 AND id<>$3 AND state NOT IN ('dismissed','expired'))`, tenant, assetID, id).Scan(&vouched); err != nil {
		return err
	}
	if vouched {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET asset_status='archived',updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, tenant, assetID); err != nil {
		return err
	}
	changes, _ := json.Marshal(map[string]any{"reason": "dismissed_provisional", "observation_id": id})
	_, err := tx.ExecContext(ctx, `INSERT INTO asset_history(tenant_id,asset_id,actor_user_id,source,action,changes_json) VALUES($1,$2,$3,'identity_enrichment','archived',$4)`, tenant, assetID, actor, string(changes))
	return err
}

// recordObservationDecision writes the append-only reviewer decision row.
func recordObservationDecision(ctx context.Context, tx *sql.Tx, tenant, id, actor uuid.UUID, action, reason string, details map[string]any) error {
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_observation_decisions(tenant_id,observation_id,actor_id,action,reason,details) VALUES($1,$2,$3,$4,$5,$6)`,
		tenant, id, actor, action, strings.TrimSpace(reason), string(raw))
	return err
}
