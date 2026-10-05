package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// A declaration FOR a named asset (platform ADR-0003 D3).
//
// Two paths attach identifiers to an asset somebody already chose rather than
// one the engine is asked to find: an operator editing an asset's identifiers,
// and a connector attaching its record id to the asset it resolved (a source
// link). Both used to call Repository.AttachIdentifiers directly, outside the
// engine — so neither took the identifier locks the engine takes, neither ran
// the singleton guard, and neither left a history entry naming what was
// attached and by whom. ResolveDeclaredFor is the engine's entry point for
// them.
//
// It is deliberately NOT Resolve with a hint. Resolve answers "which asset is
// this?", and a declaration for a named asset has already answered it: running
// the precedence walk could only disagree with the person who chose, by
// matching another asset or creating a new one. Nor does it go through
// admission: admission decides whether EVIDENCE may establish or bind an
// asset, and an operator naming the asset is that decision, already taken.

// ErrDeclaredTargetConflict is the class of every [DeclaredTargetConflict]: a
// declaration named an identifier that belongs to a different asset, or a
// second value of a kind its target may hold only one of. Nothing was written.
var ErrDeclaredTargetConflict = errors.New("identity: declared identifier conflicts with another asset")

// DeclaredTargetConflict says which identifier stopped a declaration and who
// holds it. For a singleton disagreement the holder is the target itself and
// Held is the value it already carries.
type DeclaredTargetConflict struct {
	Identifier Identifier
	Owner      AssetRef
	Held       Identifier
	Singleton  bool
}

func (c *DeclaredTargetConflict) Error() string {
	if c.Singleton {
		return fmt.Sprintf("identity: %s=%q was declared on %s, which already holds %q and may hold only one %s",
			c.Identifier.Kind, c.Identifier.Value, c.Owner.ID, c.Held.Value, c.Identifier.Kind)
	}
	return fmt.Sprintf("identity: %s=%q was declared on another asset but already belongs to %s",
		c.Identifier.Kind, c.Identifier.Value, c.Owner.ID)
}

// Unwrap lets callers test errors.Is(err, ErrDeclaredTargetConflict).
func (c *DeclaredTargetConflict) Unwrap() error { return ErrDeclaredTargetConflict }

// ResolveDeclaredFor attaches a declaration's identifiers to target, the asset
// the declarer named, through the engine's rules:
//
//   - the observation must be DECLARED or IMPORTED: a measurement never names
//     its asset, it is matched;
//   - the identifiers are normalised, stamped with the observation's
//     provenance (a declared address is stored `address_assignment = static`,
//     owner decision 1) and locked exactly as Resolve locks them, so a
//     concurrent ingest cannot claim one between the check and the write;
//   - an identifier owned by ANOTHER asset, or a singleton kind whose value
//     disagrees with the one target already holds, stops the whole
//     declaration with a [*DeclaredTargetConflict] and writes NOTHING. What a
//     conflict means is the caller's to say — an edit opens a merge proposal,
//     a connector reports the item as failed;
//   - otherwise every identifier is attached (an already-held one is refreshed
//     and may be upgraded: declared > measured > inferred, and a declared
//     static assignment pins it) and one `updated` history entry names them.
//
// It does not touch last-seen, promote names or write endpoints: a person
// editing an asset is not a sighting of it.
//
// The caller runs it on a per-transaction repository ([Engine.WithRepository])
// together with its own writes.
func (e *Engine) ResolveDeclaredFor(ctx context.Context, obs Observation, target AssetRef) (Resolution, error) {
	if strings.TrimSpace(obs.TenantID) == "" {
		return Resolution{}, fmt.Errorf("%w: no tenant", ErrInvalidObservation)
	}
	if target.Zero() || target.TenantID != obs.TenantID {
		return Resolution{}, fmt.Errorf("%w: a declaration must name an asset of its own tenant", ErrInvalidObservation)
	}
	if k := obs.Source.Kind; k != SourceDeclared && k != SourceImported {
		return Resolution{}, fmt.Errorf("%w: only a declared or imported observation names its asset (source kind %q)", ErrInvalidObservation, k)
	}
	at := obs.ObservedAt
	if at.IsZero() {
		at = e.now().UTC()
	}
	ids := make([]Identifier, 0, len(obs.Identifiers))
	for _, raw := range obs.Identifiers {
		if raw.Kind == KindDeclarationID {
			return Resolution{}, fmt.Errorf("%w: declaration identifiers are issued only by an operator's confirmation", ErrInvalidObservation)
		}
		n, err := raw.Normalized()
		if err != nil {
			return Resolution{}, fmt.Errorf("%w: %w", ErrInvalidObservation, err)
		}
		n.Source = identifierSource(raw, obs.Source)
		if n.SeenAt.IsZero() {
			n.SeenAt = at
		}
		ids = append(ids, n)
	}
	ids = dedupeIdentifiers(ids)
	if len(ids) == 0 {
		return Resolution{Outcome: OutcomeMatched, Asset: target, DecidedBy: KindDeclarationID}, nil
	}
	if locker, ok := e.repo.(interface {
		LockIdentifiers(context.Context, string, []Identifier) error
	}); ok {
		if err := locker.LockIdentifiers(ctx, obs.TenantID, ids); err != nil {
			return Resolution{}, err
		}
	}
	for _, id := range ids {
		refs, err := e.repo.FindByIdentifier(ctx, obs.TenantID, id.Kind, id.Value, id.Scope)
		if err != nil {
			return Resolution{}, fmt.Errorf("identity: looking up %s=%q: %w", id.Kind, id.Value, err)
		}
		for _, r := range refs {
			if r.ID != target.ID {
				return Resolution{}, &DeclaredTargetConflict{Identifier: id, Owner: r}
			}
		}
	}
	if observed, held, disagrees, err := e.singletonConflict(ctx, ids, target); err != nil {
		return Resolution{}, err
	} else if disagrees {
		return Resolution{}, &DeclaredTargetConflict{Identifier: observed, Owner: target, Held: held, Singleton: true}
	}
	added, err := e.repo.AttachIdentifiers(ctx, target, ids)
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: attaching declared identifiers to %s: %w", target.ID, err)
	}
	if err := e.recordIfChanged(ctx, target, obs, at, ActionUpdated, map[string]any{
		"decided_by":  string(KindDeclarationID),
		"identifiers": identifierKeys(ids),
	}, added > 0); err != nil {
		return Resolution{}, err
	}
	return Resolution{Outcome: OutcomeMatched, Asset: target, DecidedBy: KindDeclarationID}, nil
}
