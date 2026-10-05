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
//   - Every identifier a person adds is a DECLARATION resolved by the engine
//     for this asset (Engine.ResolveDeclaredFor): scoped by the one identity
//     intake like any other declaration, locked, ownership re-checked and the
//     history recorded — the only writer that respects the uniqueness
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
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
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
	// Validate what the form sent before anything is scoped: an edit is an
	// API call, and a kind or an assignment nobody can store is a 400, not a
	// row quietly left out.
	pinned := map[string]bool{} // kind|value of each address declared static
	for _, raw := range in.Identifiers {
		kind := identity.Kind(strings.TrimSpace(strings.ToLower(raw.Kind)))
		if !kind.Valid() {
			return nil, fmt.Errorf("identifier kind %q is not one of the known kinds", raw.Kind)
		}
		assignment := identity.AddressAssignment(strings.TrimSpace(strings.ToLower(raw.AddressAssignment)))
		switch {
		case assignment == "":
		case assignment != identity.AssignmentStatic:
			// A person pins an address; a lease is something only the host's
			// own agent can report, so "dynamic" is not a thing to declare.
			return nil, fmt.Errorf("address_assignment %q: only \"static\" can be declared", raw.AddressAssignment)
		case kind != identity.KindIPAddress:
			return nil, fmt.Errorf("address_assignment applies to ip_address identifiers only, not %s", kind)
		default:
			if v, err := identity.Normalize(kind, raw.Value); err == nil {
				pinned[string(kind)+"|"+v] = true
			}
		}
	}

	// The SAME declaration manualObservation makes of a create — one intake
	// for every path — so an edit scopes a hostname and an address exactly as
	// creating the asset with them would have. An identifier the form sent
	// with its own scope (every held one is sent back that way) keeps it.
	scoped := in
	scoped.ClassKey = classKey
	sg, explicit, err := declaredSighting(tenantID, scoped, identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}, "")
	if err != nil {
		return nil, err
	}
	res, err := s.assessSighting(context.Background(), "identifier edit", sg)
	if err != nil && !errors.Is(err, identity.ErrNoUsableIdentifier) {
		return nil, err
	}
	if len(res.Rejected) > 0 {
		r := res.Rejected[0]
		return nil, fmt.Errorf("identifier %s=%q: %w", r.Identifier.Kind, r.Identifier.Value, r.Err)
	}
	obs, rejected := withExplicitScopes(res, explicit)
	if len(rejected) > 0 {
		r := rejected[0]
		return nil, fmt.Errorf("identifier %s=%q: %w", r.Identifier.Kind, r.Identifier.Value, r.Err)
	}
	// In the order the form listed them, then the column aliases: the edit
	// refuses on the FIRST identifier another asset owns, and which one it
	// names should follow what the operator wrote, not the intake's internal
	// order (addresses first).
	order := map[string]int{}
	for i, raw := range in.Identifiers {
		kind := identity.Kind(strings.TrimSpace(strings.ToLower(raw.Kind)))
		if v, err := identity.Normalize(kind, raw.Value); err == nil {
			if _, seen := order[string(kind)+"|"+v]; !seen {
				order[string(kind)+"|"+v] = i
			}
		}
	}
	rank := func(id identity.Identifier) int {
		if i, ok := order[string(id.Kind)+"|"+id.Value]; ok {
			return i
		}
		return len(in.Identifiers)
	}
	sort.SliceStable(obs.Identifiers, func(i, j int) bool { return rank(obs.Identifiers[i]) < rank(obs.Identifiers[j]) })
	out := make([]identity.Identifier, 0, len(obs.Identifiers))
	for _, id := range obs.Identifiers {
		// What the edit compares and attaches is the identifier's KEY and its
		// declared assignment; the intake's markings (Pinned, derived
		// provenance) are re-derived by the engine from the declaration.
		id.Pinned = false
		id.Confidence = 1
		if id.Kind == identity.KindIPAddress && pinned[string(id.Kind)+"|"+id.Value] {
			id.Assignment = identity.AssignmentStatic
		}
		out = append(out, id)
	}
	return out, nil
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
		if held, mine := haveKeys[id.Key()]; mine {
			// Already this asset's, so AttachIdentifiers would only refresh
			// last-seen — except when the operator PINS an address the asset
			// holds unpinned. Re-declaring it is what upgrades a
			// measured row to declared and pins it. It is opt-in per row
			// because the form sends every identifier back on every save, and
			// pinning each address a sensor happened to see would turn every
			// save into a declaration.
			if id.Assignment == identity.AssignmentStatic && derefString(held.AddressAssignment) != string(identity.AssignmentStatic) {
				attach = append(attach, id)
			}
			continue
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
	//
	// The attach goes through the engine (platform ADR-0003): a
	//    declaration FOR this asset, resolved with ResolveDeclaredFor, which
	//    takes the identifier locks Resolve takes, re-checks ownership under
	//    them, runs the singleton guard and records the history entry. Step 1
	//    already refused a held identifier; one claimed by a concurrent ingest
	//    BETWEEN step 1 and here is refused by the engine instead, and gets the
	//    same proposal step 1 would have opened.
	engine, err := s.identityEngine()
	if err != nil {
		return nil, fmt.Errorf("identification engine unavailable: %w", err)
	}
	declared := identity.Observation{
		TenantID:    tenantID.String(),
		Source:      identity.Source{Kind: identity.SourceDeclared, Ref: "manual"},
		Identifiers: attach,
	}
	asset := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	err = s.identityRepo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		if len(attach) > 0 {
			if _, rerr := engine.WithRepository(r).ResolveDeclaredFor(ctx, declared, asset); rerr != nil {
				return rerr
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
	var conflict *identity.DeclaredTargetConflict
	if errors.As(err, &conflict) && !conflict.Singleton {
		proposalID, perr := s.proposeIdentifierConflict(ctx, tenantID, assetID, conflict.Owner, conflict.Identifier, actorUserID)
		if perr != nil {
			return nil, perr
		}
		ownerID, _ := uuid.Parse(conflict.Owner.ID)
		return nil, &IdentifierConflictError{
			Kind: string(conflict.Identifier.Kind), Value: conflict.Identifier.Value, Scope: conflict.Identifier.Scope,
			OwnerAssetID: ownerID, ProposalID: proposalID,
		}
	}
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
