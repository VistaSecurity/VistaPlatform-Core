package identity

import (
	"context"
	"fmt"
)

// OwnerSnapshot is who owned each of one observation's identifiers, read ONCE,
// under the identifier locks, on the transaction the observation is then
// resolved on ( F5).
//
// An intake path has questions to answer before it resolves — is this thing
// already an asset the tenant denied, an elevated vendor asset, or nothing we
// know yet — and the engine needs the same owners for its precedence walk.
// They used to be read twice: the intake looked every identifier up on its
// own connection, then [Engine.Resolve] looked every one up again. Reading
// them once and handing the answer to the engine ([Engine.WithOwnerSnapshot])
// makes the decision the intake took and the decision the engine takes rest
// on the SAME read, which two reads on two connections never guaranteed.
//
// The snapshot is valid only for the transaction it was taken on and only
// until something writes an identifier. The engine therefore consults it for
// the reads it makes before its first write, and a resolution that re-runs its
// walk after writing (the hearsay-yield and operator-scan re-runs) reads
// afresh.
type OwnerSnapshot struct {
	tenantID string
	// ids are the observation's normalised identifiers, deduplicated, in
	// observation order — the order an intake reads "the first owner" in.
	ids    []Identifier
	owners map[string][]AssetRef
}

// IdentifierOwners is one identifier and the assets that carry it.
type IdentifierOwners struct {
	Identifier Identifier
	Owners     []AssetRef
}

// Owners returns the snapshot's identifiers and their owners, in observation
// order. An identifier nobody owns is listed with no owners.
func (s *OwnerSnapshot) Owners() []IdentifierOwners {
	if s == nil {
		return nil
	}
	out := make([]IdentifierOwners, 0, len(s.ids))
	for _, id := range s.ids {
		out = append(out, IdentifierOwners{Identifier: id, Owners: s.owners[id.Key()]})
	}
	return out
}

// lookup answers from the snapshot when it covers this identifier in this
// tenant.
func (s *OwnerSnapshot) lookup(tenantID string, id Identifier) ([]AssetRef, bool) {
	if s == nil || s.tenantID != tenantID {
		return nil, false
	}
	refs, ok := s.owners[id.Key()]
	return refs, ok
}

// SnapshotOwners takes the identifier locks for obs and reads the owner of
// every identifier it carries, on the engine's repository.
//
// It locks exactly as [Engine.Resolve] does (Resolve re-takes the same locks,
// which a transaction-scoped advisory lock allows), so the owners it returns
// cannot be changed by another locking writer before this transaction ends.
// It writes nothing.
func (e *Engine) SnapshotOwners(ctx context.Context, obs Observation) (*OwnerSnapshot, error) {
	obs = canonicalSensorIdentity(obs)
	ids, err := normalizedIdentifiers(obs)
	if err != nil {
		return nil, err
	}
	if err := e.lockObservationIdentifiers(ctx, obs); err != nil {
		return nil, err
	}
	ids = dedupeIdentifiers(ids)
	snap := &OwnerSnapshot{tenantID: obs.TenantID, ids: ids, owners: make(map[string][]AssetRef, len(ids))}
	for _, id := range ids {
		refs, err := e.repo.FindByIdentifier(ctx, obs.TenantID, id.Kind, id.Value, id.Scope)
		if err != nil {
			return nil, fmt.Errorf("identity: looking up %s=%q: %w", id.Kind, id.Value, err)
		}
		snap.owners[id.Key()] = refs
	}
	return snap, nil
}

// WithOwnerSnapshot returns a copy of the engine whose next resolution reads
// identifier owners from snap instead of the repository, for the identifiers
// snap covers. snap must have been taken by [Engine.SnapshotOwners] on the
// same transaction the copy resolves on; a nil snap is no snapshot.
func (e *Engine) WithOwnerSnapshot(snap *OwnerSnapshot) *Engine {
	cp := *e
	cp.ownerSnapshot = snap
	return &cp
}

// ownersOf is the engine's one read of "who carries this identifier" before
// it writes: the snapshot when the caller supplied one that covers it, the
// repository otherwise.
func (e *Engine) ownersOf(ctx context.Context, tenantID string, id Identifier) ([]AssetRef, error) {
	if refs, ok := e.ownerSnapshot.lookup(tenantID, id); ok {
		return refs, nil
	}
	return e.repo.FindByIdentifier(ctx, tenantID, id.Kind, id.Value, id.Scope)
}

// normalizedIdentifiers normalises every identifier of obs, failing on the
// first that does not normalise — the same refusal Resolve makes.
func normalizedIdentifiers(obs Observation) ([]Identifier, error) {
	ids := make([]Identifier, 0, len(obs.Identifiers))
	for _, raw := range obs.Identifiers {
		id, err := raw.Normalized()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidObservation, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// lockObservationIdentifiers takes the repository's identifier locks for
// every identifier obs carries, when the repository has them. obs must
// already be canonical (canonicalSensorIdentity).
func (e *Engine) lockObservationIdentifiers(ctx context.Context, obs Observation) error {
	locker, ok := e.repo.(interface {
		LockIdentifiers(context.Context, string, []Identifier) error
	})
	if !ok {
		return nil
	}
	ids, err := normalizedIdentifiers(obs)
	if err != nil {
		return err
	}
	return locker.LockIdentifiers(ctx, obs.TenantID, ids)
}
