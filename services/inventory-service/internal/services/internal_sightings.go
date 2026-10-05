package services

// The internal sightings intake (platform ADR-0003 D3 step 2).
//
// One identity engine host: device-interrogation-service stops running engines
// of its own and posts what it saw — identity.Sighting, the same shape every
// adapter in this service builds — to POST
// /api/v1/inventory-service/internal/sightings. Each sighting goes through the
// SAME intake and the SAME engine configuration as a finding from
// discovery-processor: identity.Intake decides scope, dynamic scopes,
// admission and hygiene; resolveObservationWithRepo runs the engine on one
// transaction with the tenant's own auto-accept and auto-merge settings, and
// stores the durable observation receipt when the tenant's admission mode
// asks for one. Provisional creation and promotion therefore live in one
// process, and endpoints reach an asset only where the engine attaches them
// (ADR-0003 D2).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/attrlist"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// MaxSightingsPerCall bounds one internal sightings call, as MaxSourceBatch
// bounds a source import: a device run is chunked by the caller.
const MaxSightingsPerCall = 500

// Reasons a sighting is answered `rejected` without reaching the engine.
const (
	SightingReasonTenantMismatch     = "tenant_mismatch"
	SightingReasonInvalid            = "invalid_sighting"
	SightingReasonNoUsableIdentifier = "no_usable_identifier"
	SightingReasonAssetDenied        = "asset_denied"
	// A target_asset_id that names no live asset of the signed tenant.
	SightingReasonUnknownTarget = "unknown_target"
	// A declaration for a named asset that the engine refused. The result is
	// `conflict` on the named asset; the identifier case carries the merge
	// proposal opened against the other owner, exactly as the identifier edit.
	SightingReasonDeclaredIdentifierConflict = "declared_identifier_conflict"
	SightingReasonDeclaredSingletonConflict  = "declared_singleton_conflict"
)

// SightingItem is one entry of the route's body: the sighting's own fields,
// flattened, and an optional target.
//
// TargetAssetID names the asset a declared (or imported) sighting is ABOUT —
// an operator editing that device in device-interrogation's Devices form.
// Such an item does not ask the engine which asset it is: its identifiers are
// attached to the named asset by Engine.ResolveDeclaredFor through
// DeclareFor, the identifier edit's path (same locks, ownership re-check under
// them, singleton guard, history; a declared address stored static). An
// identifier another asset owns writes nothing, opens the edit's merge
// proposal and answers `conflict`. Omitted, the item is an ordinary sighting.
type SightingItem struct {
	identity.Sighting
	TargetAssetID string `json:"target_asset_id,omitempty"`
}

// SightingResult is one sighting's answer, mirroring identity.IngestResult
// plus the admission decision's reasons. Outcome is an engine outcome
// (matched, created, provisional, supporting, unresolved, conflict) or
// `rejected`; an absent id is absent, never a zero UUID.
type SightingResult struct {
	Outcome       string   `json:"outcome"`
	AssetID       string   `json:"asset_id,omitempty"`
	ObservationID string   `json:"observation_id,omitempty"`
	ProposalID    string   `json:"proposal_id,omitempty"`
	Reasons       []string `json:"reasons,omitempty"`
}

// IngestSightings resolves each sighting for tenantID, index-aligned.
//
// A sighting that names another tenant, that the intake cannot read, or that
// carries nothing usable is answered `rejected` with the reason and the batch
// continues. A store failure stops the batch and is returned: the caller
// retries it, and a resolution the engine already committed is recognised on
// the retry by its receipt id.
//
// As for a finding, a sighting of an asset the tenant DENIED does not reopen
// the decision: last-seen moves and nothing else does.
func (s *AssetService) IngestSightings(ctx context.Context, tenantID uuid.UUID, items []SightingItem) ([]SightingResult, error) {
	out := make([]SightingResult, len(items))
	for i, item := range items {
		sg := item.Sighting
		if sg.TenantID != "" && sg.TenantID != tenantID.String() {
			out[i] = SightingResult{Outcome: "rejected", Reasons: []string{SightingReasonTenantMismatch}}
			continue
		}
		sg.TenantID = tenantID.String()
		label := fmt.Sprintf("sighting %d (%s, receipt %q)", i, sg.Source.Ref, sg.ReceiptID)
		if item.TargetAssetID != "" {
			r, err := s.declareSightingFor(ctx, tenantID, item.TargetAssetID, label, sg)
			if err != nil {
				return out, err
			}
			out[i] = r
			continue
		}
		intake, err := s.assessSighting(ctx, label, sg)
		switch {
		case errors.Is(err, identity.ErrInvalidSighting):
			log.Printf("[AssetService] internal sightings: rejecting %s: %v", label, err)
			out[i] = SightingResult{Outcome: "rejected", Reasons: []string{SightingReasonInvalid}}
			continue
		case errors.Is(err, identity.ErrNoUsableIdentifier):
			out[i] = SightingResult{Outcome: "rejected", Reasons: []string{SightingReasonNoUsableIdentifier}}
			continue
		case err != nil:
			return out, err
		}
		obs := intake.Observation

		existingID, existingStatus, found, err := s.lookupExistingAsset(ctx, tenantID, obs)
		if err != nil {
			return out, fmt.Errorf("%s: looking up an existing asset: %w", label, err)
		}
		if found && existingStatus == identity.StatusDenied {
			if terr := s.identityRepo.Touch(ctx, identity.AssetRef{TenantID: tenantID.String(), ID: existingID.String()}, obs.ObservedAt); terr != nil {
				log.Printf("[AssetService] internal sightings: touching denied asset %s failed (batch continues): %v", existingID, terr)
			}
			out[i] = SightingResult{Outcome: "rejected", AssetID: existingID.String(), Reasons: []string{SightingReasonAssetDenied}}
			continue
		}

		// The segment's auto-approval, decided before the engine's transaction
		// opens (it reads the segment and the tenant's rules on their own
		// connections), applied inside it.
		approved := s.interrogationSightingApproved(tenantID, sg, obs)

		var reasons []string
		res, err := s.resolveObservationWithRepo(ctx, obs, func(repo *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error {
			if err := applySightingContext(ctx, repo, tx, sg, intake, res); err != nil {
				return err
			}
			if approved {
				if err := s.autoApproveInterrogated(ctx, tx, tenantID, obs, res); err != nil {
					return err
				}
			}
			if res.ObservationID == "" {
				return nil
			}
			// The admission decision's reasons, read on the transaction that
			// recorded them, so the caller sees why evidence was held.
			return tx.QueryRowContext(ctx, `SELECT admission_reasons FROM identity_observations WHERE tenant_id=$1 AND id=$2`,
				tenantID, res.ObservationID).Scan(pq.Array(&reasons))
		})
		if errors.Is(err, identity.ErrInvalidObservation) || errors.Is(err, identity.ErrNoUsableIdentifier) {
			log.Printf("[AssetService] internal sightings: rejecting %s: %v", label, err)
			out[i] = SightingResult{Outcome: "rejected", Reasons: []string{SightingReasonInvalid}}
			continue
		}
		if err != nil {
			return out, fmt.Errorf("%s: %w", label, err)
		}
		logIdentityDecisions(label, res)
		r := res.IngestResult()
		out[i] = SightingResult{Outcome: r.Outcome, AssetID: r.AssetID, ObservationID: r.ObservationID, ProposalID: r.ProposalID, Reasons: reasons}
	}
	return out, nil
}

// applySightingContext writes what a posted sighting's resolution owes the
// asset beyond the engine's own rows, on the engine's transaction — what
// device-interrogation-service's engines wrote before it posted here
//
//
//   - the values Intake withheld as identifiers but that have an attribute
//     home (synthetic names, temporary and unscoped link-local IPv6), via
//     attrlist.Record, as host-observation ingest records its own;
//   - a FIRST-HAND sighting's (authenticated_session: the host's own agent, a
//     session reading its own configuration) segment projected onto the
//     asset's placement, as host-observation ingest does for a sensor's
//     self-report. Hearsay places nothing: it never puts an asset into the
//     observation's segment. (Keeping an asset's location consistent with
//     the segment it is ALREADY in is not placement and happens for every
//     sighting, in resolveObservationWithRepo.)
//
// Nothing is written for a resolution that landed on no asset.
func applySightingContext(ctx context.Context, repo *pgidentity.Repository, tx *sqlx.Tx, sg identity.Sighting, intake identity.IntakeResult, res identity.Resolution) error {
	if res.Asset.Zero() {
		return nil
	}
	for _, key := range []string{attrlist.KeySyntheticNames, attrlist.KeyIPv6Temporary, attrlist.KeyLinkLocal} {
		values := intake.AttributeEvidence[key]
		if len(values) == 0 {
			continue
		}
		limit := attrlist.MaxAddressEvidence
		if key == attrlist.KeySyntheticNames {
			limit = hostnamequality.MaxSyntheticNames
		}
		if err := attrlist.Record(ctx, tx, sg.TenantID, res.Asset.ID, key, values, limit); err != nil {
			return err
		}
	}
	// A sighting of CLAIMED addresses (a gateway's own address on each network
	// it routes) is first-hand too, but it describes the networks the
	// device serves, not where it stands. It places nothing: projecting each
	// routed segment in turn would file a router under whichever network was
	// claimed first. Its home segment is set by the interrogation itself, from
	// the address it was reached at.
	if sg.Channel == identity.ChannelAuthenticatedSession && res.Outcome != identity.OutcomeConflict && !sg.ClaimsAddresses() {
		return repo.ProjectSegmentLocation(ctx, res.Asset, intake.Observation.Network.SegmentID, intake.Observation.Source)
	}
	return nil
}

// declareSightingFor is one item that names its asset (SightingItem): the
// identifier edit's declaration, answered in the route's result shape.
func (s *AssetService) declareSightingFor(ctx context.Context, tenantID uuid.UUID, target, label string, sg identity.Sighting) (SightingResult, error) {
	assetID, err := uuid.Parse(strings.TrimSpace(target))
	if err != nil {
		return SightingResult{Outcome: "rejected", Reasons: []string{SightingReasonUnknownTarget}}, nil
	}
	var live bool
	if err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL)`,
			tenantID, assetID).Scan(&live)
	}); err != nil {
		return SightingResult{}, fmt.Errorf("%s: reading the target asset: %w", label, err)
	}
	if !live {
		return SightingResult{Outcome: "rejected", Reasons: []string{SightingReasonUnknownTarget}}, nil
	}
	_, err = s.DeclareFor(ctx, tenantID, assetID, sg)
	var conflict *identity.DeclaredTargetConflict
	switch {
	case errors.As(err, &conflict) && conflict.Singleton:
		return SightingResult{Outcome: string(identity.OutcomeConflict), AssetID: assetID.String(),
			Reasons: []string{SightingReasonDeclaredSingletonConflict}}, nil
	case errors.As(err, &conflict):
		proposalID, perr := s.proposeIdentifierConflict(ctx, tenantID, assetID, conflict.Owner, conflict.Identifier, uuid.Nil)
		if perr != nil {
			return SightingResult{}, fmt.Errorf("%s: %w", label, perr)
		}
		return SightingResult{Outcome: string(identity.OutcomeConflict), AssetID: assetID.String(), ProposalID: proposalID.String(),
			Reasons: []string{SightingReasonDeclaredIdentifierConflict}}, nil
	case errors.Is(err, identity.ErrInvalidSighting), errors.Is(err, identity.ErrInvalidObservation), errors.Is(err, identity.ErrNoUsableIdentifier):
		log.Printf("[AssetService] internal sightings: rejecting %s: %v", label, err)
		return SightingResult{Outcome: "rejected", Reasons: []string{SightingReasonInvalid}}, nil
	case err != nil:
		return SightingResult{}, fmt.Errorf("%s: %w", label, err)
	}
	return SightingResult{Outcome: string(identity.OutcomeMatched), AssetID: assetID.String()}, nil
}

// interrogationSourcePrefix is the source ref every interrogation's sightings
// carry: `interrogation:<job>` (device-interrogation-service's
// interrogationSource).
const interrogationSourcePrefix = "interrogation:"

// interrogationSightingApproved reports whether the segment a sighting from an
// interrogation lands in auto-approves it ( D3: hosts a controller or a
// gateway reports auto-approve on such a segment, as sensor-sourced hosts do).
//
// It is the SAME evaluation manual create, spreadsheet import and the CMDB pull
// already run (evaluateAssetApproval): the segment's own rule in
// discovery_auto_approval_rules, evaluated by shared/approval, with no cloud
// source on the discovery. So `interrogation` is admitted wherever the
// segment's auto-approval covers the non-cloud discovery sources, which every
// segment does unless its sources were set to cloud only. That is the smaller
// of the two changes the spec allowed: no new value in `auto_approve_sources`,
// no rule regeneration for existing segments, no API change — and a tenant who
// turned auto-approval off still approves everything by hand.
//
// The address evaluated is the sighting's own first address in a real segment
// (Intake's sighting segment), else its first address, else its first name.
func (s *AssetService) interrogationSightingApproved(tenantID uuid.UUID, sg identity.Sighting, obs identity.Observation) bool {
	if sg.Source.Kind != identity.SourceMeasured || !strings.HasPrefix(sg.Source.Ref, interrogationSourcePrefix) {
		return false
	}
	var addr, firstAddr, name *string
	for i := range obs.Identifiers {
		id := obs.Identifiers[i]
		switch id.Kind {
		case identity.KindIPAddress:
			v := id.Value
			if firstAddr == nil {
				firstAddr = &v
			}
			if addr == nil && id.Scope == obs.Network.SegmentID && id.Scope != identity.ScopeTenantDefault {
				addr = &v
			}
		case identity.KindHostname, identity.KindFQDN:
			if name == nil {
				v := id.Value
				name = &v
			}
		}
	}
	if addr == nil {
		addr = firstAddr
	}
	if addr == nil && name == nil {
		return false
	}
	return s.evaluateAssetApproval(tenantID, addr, name) == identity.StatusMonitoring
}

// autoApproveInterrogated applies an auto-approval decided by
// interrogationSightingApproved to the asset the sighting resolved to, inside
// the engine's transaction: a created or matched asset still pending approval
// is promoted, exactly as a sensor-sourced host observation's is
// (setStatusUnlessArchived). Never a conflict's own pending asset (the merge is
// a reviewer's question), never an archived asset (archiving is a decision a
// re-discovery does not undo) and never a PROVISIONAL one: a guess does not
// consume the tenant's asset allowance until something promotes it ( D1).
func (s *AssetService) autoApproveInterrogated(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, obs identity.Observation, res identity.Resolution) error {
	if res.Asset.Zero() || (res.Outcome != identity.OutcomeCreated && res.Outcome != identity.OutcomeMatched) {
		return nil
	}
	assetID, err := uuid.Parse(res.Asset.ID)
	if err != nil {
		return fmt.Errorf("auto-approval: asset id %q: %w", res.Asset.ID, err)
	}
	var status, identityStatus string
	if err := tx.QueryRowContext(ctx, `SELECT asset_status, coalesce(identity_status, '') FROM assets WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`,
		tenantID, assetID).Scan(&status, &identityStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("auto-approval: reading asset %s: %w", assetID, err)
	}
	if status != identity.StatusPendingApproval || identityStatus == string(identity.IdentityProvisional) {
		return nil
	}
	return s.setStatusUnlessArchived(tx, tenantID, assetID, identity.StatusMonitoring, obs.Source)
}
