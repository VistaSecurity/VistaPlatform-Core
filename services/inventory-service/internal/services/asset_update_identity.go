package services

// UpdateAsset's identity half: what a person editing an asset may do to its
// identifiers, and what they may not.
//
// Before this, `PUT /infrastructure-assets/{id}` accepted an `identifiers`
// array and dropped it on the floor, while rewriting `hostname` and
// `primary_address` by raw SQL. Both halves of that were wrong in the same
// direction — the columns moved and the IDENTIFIERS did not — so the asset's
// new name was not something it could be matched on, its old name still was,
// and the next sighting of the renamed host minted a duplicate. An edit that
// silently changes nothing is the worse half: the form said "saved".
//
// The rules, stated once:
//
//   - Every identifier a person adds goes through the engine's
//     AttachIdentifiers, which is the only writer that respects the uniqueness
//     invariant of DATA_MODEL §2.
//   - An identifier that already belongs to ANOTHER asset is a merge question,
//     not an error: the edit is refused (409) and a merge proposal is opened so
//     the reviewer can answer it. The proposal COMMITS even though the edit
//     did not — a refusal that erased the proposal it told the operator to go
//     read is the failure gate 1 found in three other places.
//   - A person may retire only what a person declared. A collector-minted
//     identifier — an agent's installation id, a cloud resource id, anything a
//     sensor measured — is a fact about the world, and an edit form is not
//     where facts get deleted. Those are KEPT and the response says so, because
//     a kept identifier reported as removed is a lie the UI would repeat.
//   - Removal happens only when the request actually carries an `identifiers`
//     array. A partial update that never mentions identifiers must not delete
//     any.
//   - An asset is never left with no identifiers at all. The engine's floor
//     refuses to CREATE one (it could never be matched again); letting an edit
//     produce one by subtraction would be the same asset through a different
//     door.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// collectorMintedKinds are the kinds a person never types and therefore never
// retires, whatever `source_kind` happens to say on the row. An agent id is
// issued by us to a running agent; a cloud resource id is the provider's own
// name for the thing. Deleting either from an edit form would make the next
// sighting mint a duplicate of the asset being edited.
var collectorMintedKinds = map[identity.Kind]bool{
	identity.KindAgentID:         true,
	identity.KindSensorID:        true,
	identity.KindDeclarationID:   true,
	identity.KindCloudResourceID: true,
}

// IdentifierConflictError is returned when an edit tried to attach an
// identifier that already belongs to a different asset in the tenant.
//
// It carries the proposal id because the operator's next action is to open it.
// A 409 that said only "conflict" would leave them with the asset they were
// editing and no way to reach the one that disagreed.
type IdentifierConflictError struct {
	Kind         string
	Value        string
	Scope        string
	OwnerAssetID uuid.UUID
	ProposalID   uuid.UUID
}

func (e *IdentifierConflictError) Error() string {
	return fmt.Sprintf("identifier %s=%q already belongs to asset %s; merge proposal %s was opened for review",
		e.Kind, e.Value, e.OwnerAssetID, e.ProposalID)
}

// AsIdentifierConflict reports whether err is an identifier conflict.
func AsIdentifierConflict(err error) (*IdentifierConflictError, bool) {
	var c *IdentifierConflictError
	ok := errors.As(err, &c)
	return c, ok
}

// ErrIdentifierFloor is returned when an edit would leave the asset with no
// identifiers. See the package note: an asset with no identifiers can never be
// recognised again.
var ErrIdentifierFloor = errors.New("an asset must keep at least one identifier; it could never be matched again")

// declaredIdentifiers builds the identifier set an update request asks for,
// from the `identifiers` array AND from the columns that are really identifier
// aliases: hostname (or fqdn), ip_address, and — for the service branch — the
// display name.
//
// `name` is scoped by the CLASS KEY, not by the network segment. Two services
// may share a name only if they are different kinds of thing, and the class is
// what says so; scoping a name to a segment would make "payments api" in one
// segment a different service from the same one next door, which is not what a
// declared service is.
func (s *AssetService) declaredIdentifiers(tenantID uuid.UUID, classKey string, in models.AssetInput) ([]identity.Identifier, error) {
	segmentID, _ := s.observationScope(tenantID, in.IPAddress, in.Hostname)

	var out []identity.Identifier
	add := func(id identity.Identifier) error {
		n, err := id.Normalized()
		if err != nil {
			return err
		}
		for _, have := range out {
			if have.Key() == n.Key() {
				return nil
			}
		}
		out = append(out, n)
		return nil
	}

	for _, raw := range in.Identifiers {
		kind := identity.Kind(strings.TrimSpace(strings.ToLower(raw.Kind)))
		if !kind.Valid() {
			return nil, fmt.Errorf("identifier kind %q is not one of the known kinds", raw.Kind)
		}
		scope := strings.TrimSpace(derefString(raw.Scope))
		if kind.RequiresScope() && scope == "" {
			scope = defaultScopeForKind(kind, classKey, segmentID)
		}
		if err := add(identity.Identifier{
			Kind: kind, Value: strings.TrimSpace(raw.Value), Scope: scope, Confidence: 1,
		}); err != nil {
			return nil, err
		}
	}

	if host := strings.TrimSpace(derefString(in.Hostname)); host != "" {
		kind, scope := identity.KindHostname, segmentID
		if strings.Contains(strings.TrimSuffix(host, "."), ".") {
			kind, scope = identity.KindFQDN, ""
		}
		if err := add(identity.Identifier{Kind: kind, Value: host, Scope: scope, Confidence: 1}); err != nil {
			return nil, err
		}
	}
	if ip := strings.TrimSpace(derefString(in.IPAddress)); ip != "" {
		if err := add(identity.Identifier{
			Kind: identity.KindIPAddress, Value: ip, Scope: segmentID, Confidence: 1,
		}); err != nil {
			return nil, err
		}
	}
	if name := strings.TrimSpace(derefString(in.DisplayName)); name != "" &&
		assetclass.IsAncestor(assetclass.KeyService, classKey) {
		if err := add(identity.Identifier{
			Kind: identity.KindName, Value: name, Scope: classKey, Confidence: 1,
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// defaultScopeForKind is the scope a scoped kind carries when the caller
// supplied none: the class key for `name`, the resolved network segment for
// hostname and ip_address.
func defaultScopeForKind(kind identity.Kind, classKey, segmentID string) string {
	if kind == identity.KindName {
		return classKey
	}
	return segmentID
}

// updateAssetIdentifiers is the identity half of UpdateAsset, run on the
// engine's own transaction so the column update and the identifier writes land
// together.
//
// It returns the report the handler echoes, or an *IdentifierConflictError
// after opening a merge proposal.
func (s *AssetService) updateAssetIdentifiers(
	ctx context.Context,
	tenantID, assetID uuid.UUID,
	classKey string,
	in models.AssetInput,
	actorUserID uuid.UUID,
) (*models.IdentifierUpdateReport, error) {
	want, err := s.declaredIdentifiers(tenantID, classKey, in)
	if err != nil {
		return nil, err
	}
	existing, err := s.getAssetIdentifiers(tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if len(want) == 0 && in.Identifiers == nil {
		// Nothing to do and nothing asked: a partial update that never
		// mentioned identity.
		return &models.IdentifierUpdateReport{}, nil
	}

	if _, err := s.identityEngine(); err != nil {
		return nil, fmt.Errorf("identification engine unavailable: %w", err)
	}

	// 1. Ownership, BEFORE any write. The repository reports a taken identifier
	//    as a zero row count rather than a constraint violation, but finding out
	//    that way would mean the conflict surfaced mid-transaction with the
	//    column update already applied.
	haveKeys := map[string]models.Identifier{}
	for _, e := range existing {
		haveKeys[identifierKey(e)] = e
	}
	var attach []identity.Identifier
	for _, id := range want {
		if _, mine := haveKeys[id.Key()]; mine {
			continue // already this asset's; AttachIdentifiers would only refresh last-seen
		}
		if id.Kind == identity.KindDeclarationID {
			return nil, fmt.Errorf("declaration identifiers are issued only by identity confirmation")
		}
		owners, ferr := s.identityRepo.FindByIdentifier(ctx, tenantID.String(), id.Kind, id.Value, id.Scope)
		if ferr != nil {
			return nil, fmt.Errorf("look up identifier %s: %w", id.Kind, ferr)
		}
		for _, o := range owners {
			if o.ID == assetID.String() {
				continue
			}
			// Owned by SOMEBODY ELSE. The edit stops here — and the proposal is
			// opened on its own transaction first, so it survives the refusal.
			proposalID, perr := s.proposeIdentifierConflict(ctx, tenantID, assetID, o, id, actorUserID)
			if perr != nil {
				return nil, perr
			}
			ownerID, _ := uuid.Parse(o.ID)
			return nil, &IdentifierConflictError{
				Kind: string(id.Kind), Value: id.Value, Scope: id.Scope,
				OwnerAssetID: ownerID, ProposalID: proposalID,
			}
		}
		attach = append(attach, id)
	}

	// 2. What the edit retires. Only when the request carried the array at all,
	//    and only what a person declared.
	report := &models.IdentifierUpdateReport{}
	var remove []models.Identifier
	if in.Identifiers != nil {
		wantKeys := map[string]bool{}
		for _, id := range want {
			wantKeys[id.Key()] = true
		}
		for _, e := range existing {
			if wantKeys[identifierKey(e)] {
				continue
			}
			change := models.IdentifierChange{
				Kind: e.Kind, Value: e.Value, Scope: derefString(e.Scope), SourceKind: e.SourceKind,
			}
			switch {
			case collectorMintedKinds[identity.Kind(e.Kind)]:
				change.Reason = "issued by a collector, not by a person — an edit form does not retire it"
				report.Kept = append(report.Kept, change)
			case e.SourceKind != string(identity.SourceDeclared):
				change.Reason = "observed by " + e.SourceKind + " collection; only declared identifiers can be retired here"
				report.Kept = append(report.Kept, change)
			default:
				remove = append(remove, e)
				report.Removed = append(report.Removed, change)
			}
		}
	}

	if len(attach) == 0 && len(remove) == 0 {
		return report, nil
	}
	if len(existing)+len(attach)-len(remove) <= 0 {
		return nil, ErrIdentifierFloor
	}

	// 3. Write. One transaction: an attach that landed without its matching
	//    removal would leave the asset carrying both spellings with nothing
	//    saying which the operator meant.
	err = s.identityRepo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		if len(attach) > 0 {
			for i := range attach {
				attach[i].Source = identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}
			}
			if aerr := r.AttachIdentifiers(ctx,
				identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}, attach); aerr != nil {
				return aerr
			}
		}
		for _, e := range remove {
			if _, derr := r.Tx().ExecContext(ctx,
				`DELETE FROM public.asset_identifiers WHERE tenant_id = $1 AND asset_id = $2 AND id = $3`,
				tenantID, assetID, e.ID); derr != nil {
				return fmt.Errorf("retire identifier %s: %w", e.Kind, derr)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, id := range attach {
		report.Attached = append(report.Attached, models.IdentifierChange{
			Kind: string(id.Kind), Value: id.Value, Scope: id.Scope, SourceKind: string(identity.SourceDeclared),
		})
	}
	return report, nil
}

// proposeIdentifierConflict opens the merge proposal a refused edit points at.
//
// It runs in its OWN transaction, deliberately: the edit is about to be refused,
// and a proposal written on the refused unit of work would roll back with it —
// the operator would be told to go read something that does not exist. (Gate 1
// found that exact shape in CreateDevice and the cloud upsert.)
func (s *AssetService) proposeIdentifierConflict(
	ctx context.Context,
	tenantID, assetID uuid.UUID,
	owner identity.AssetRef,
	id identity.Identifier,
	actorUserID uuid.UUID,
) (uuid.UUID, error) {
	ref := "manual"
	if actorUserID != uuid.Nil {
		ref = "manual:" + actorUserID.String()
	}
	proposal, err := s.identityRepo.OpenMergeProposal(ctx, tenantID.String(), identity.MergeProposal{
		ObservationAssetID: assetID.String(),
		Candidates: []identity.MergeCandidate{{
			Ref:                owner,
			MatchedIdentifiers: []identity.Identifier{id},
			Reason:             "a person declared this identifier on another asset",
		}},
		Source: identity.Source{Kind: identity.SourceDeclared, Ref: ref},
		Reason: fmt.Sprintf("%s=%q was declared on this asset but already belongs to another", id.Kind, id.Value),
		// The edited asset was in service before the edit. One unverified
		// keystroke does not take it out — see PreserveObservationStatus.
		PreserveObservationStatus: true,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("open merge proposal for the conflicting identifier: %w", err)
	}
	pid, err := uuid.Parse(proposal.ID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("merge proposal id %q is unusable: %w", proposal.ID, err)
	}
	return pid, nil
}

// identifierKey spells the uniqueness key of a stored identifier the same way
// [identity.Identifier.Key] spells it for an observed one, so the two sets can
// be compared at all.
func identifierKey(e models.Identifier) string {
	return e.Kind + "|" + e.Value + "|" + derefString(e.Scope)
}
