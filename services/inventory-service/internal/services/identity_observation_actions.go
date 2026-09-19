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
