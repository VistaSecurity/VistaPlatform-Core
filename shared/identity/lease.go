package identity

// "The address follows the MAC" ( 1b, owner decision D2).
//
// On a DHCP segment an address is a lease: it names whoever holds it today.
// ADR-0002 D3 already stops such an address from DECIDING a match
// ([Engine.kindVotes]). What it did not do is let the address move. A device
// matched by its own MAC at an address still owned by the previous lease holder
// left that address on the previous holder for ever, reported as unattached on
// every sighting — so the inventory said the departed device still held the
// lease, and the device that actually held it never showed it.
//
// The rule moves the address, and only when every one of five conditions
// holds (plus the refusals about the previous holder below). Each is there because
// its absence is a way to move an address to the wrong device:
//
//  1. the match was decided by a DEVICE-BINDING kind ranked above
//     `ip_address` in the effective precedence. A name is not enough: a DHCP
//     client's hostname is as much a thing somebody chose as the lease is, and
//     two phones both called "iphone" are two phones. And the deciding
// identifier must have been OBSERVED, not derived ( Phase 2): a MAC
//     worked out from an EUI-64 address or a serial says which device the
//     record describes, not which device holds this lease now;
//  2. the observation met the device directly and was not relayed, or it is
//     an authoritative inventory (a controller's client table) — and it is a
//     MEASUREMENT. Hearsay about who holds a lease, or an import of what some
//     system of record believed last week, is not evidence of who holds it now;
//  3. the address is in a dynamic scope. A static address that the walk let
//     vote would have made this a cross-kind conflict or a floating address
//     instead, and moving a static address is a merge by another name;
//  4. the observation is NEWER than the last time the previous holder was
//     seen with the address ([Repository.IdentifierLastSeen]). This is what
//     keeps a replayed or late-arriving sighting from moving an address back
//     to a device that has since lost the lease;
//  5. the store can move an identifier atomically ([IdentifierReassigner]).
//     Without it the move would be a detach and an attach with a window in
//     which the value belongs to nobody.
//
// And the previous holder must not be a record a person made about that
// address: an operator who typed an address onto a record has said something
// about it that a sensor does not get to overwrite (guard rail §A.5, owner
// decision D4). That is a DECLARED identifier, a declared record
// (`declaration_id`), or an operator-confirmed identity.
//
// And the previous holder must be a DEVICE THAT LOST THE LEASE, not a VIP. An
// ARP frame cannot tell the two apart — "address X is-at MAC of node A" is
// exactly what a node announcing a MetalLB/keepalived VIP sends, and in a
// dynamic scope the address never votes, so the floating-address rule's
// two-candidate shape never forms and the frame arrives here as a match on the
// node. The discriminator is therefore the HOLDER ([holderLostALease]): it
// must carry a device-binding identifier of its own, or nothing but addresses
// (the IP-only record C2 describes, which the move then empties and, when
// provisional, archives). A holder with a name but no device binding is a
// service or VIP record and keeps its address; so does any holder the
// floating-address rule has EVER recorded that address as announced for
// ([Repository.AddressAnnounced]) — a record that already has a VIP's history
// is a VIP, whatever else it carries.
//
// The move goes through [IdentifierReassigner.ReassignIdentifier] only (guard
// rail §A.2), is recorded as `identifier_reassigned` with reason
// [ReasonLeaseMoved] on BOTH assets, and a PROVISIONAL previous holder the move
// left with no identifier is archived ([Engine.archiveIfEmptied]).

import (
	"context"
	"fmt"
	"time"
)

// leaseMove is one address the lease rule decided to move, and from whom.
type leaseMove struct {
	id       Identifier
	from     AssetRef
	lastSeen time.Time
}

// decidedAboveAddress reports whether a match decided by `decidedBy` may move
// an address: condition 1 of the lease rule.
//
// Both halves are required. Device-binding alone would let a tenant's
// precedence override that puts `ip_address` FIRST still move addresses on a
// MAC match — the tenant has said the address is the stronger evidence for that
// class. Rank alone would let a hostname move an address, because hostname and
// fqdn sit above ip_address in the default order.
//
// An `ip_address` absent from the precedence ranks below everything present:
// the class does not identify by address at all.
func decidedAboveAddress(precedence []Kind, decidedBy Kind) bool {
	if !deviceBindingKinds[decidedBy] {
		return false
	}
	decidedRank, addressRank := -1, len(precedence)
	for i, k := range precedence {
		if k == decidedBy && decidedRank < 0 {
			decidedRank = i
		}
		if k == KindIPAddress && i < addressRank {
			addressRank = i
		}
	}
	return decidedRank >= 0 && decidedRank < addressRank
}

// metDirectly is condition 2 of the lease rule: the observation is a
// measurement that met the device on the wire — directly and not relayed — or
// an authoritative inventory of it.
func metDirectly(obs Observation) bool {
	if obs.Source.Kind != SourceMeasured {
		return false
	}
	return (obs.Admission.Direct && !obs.Admission.Relayed) || obs.Admission.Authoritative
}

// holderDeclaredAddress reports whether the previous holder is a record a
// person made about this address, which the lease rule never takes an address
// from: the holder's own copy of the identifier was declared, the holder is a
// declared record, or its identity was confirmed by an operator.
func holderDeclaredAddress(holder AssetSummary, addr Identifier) bool {
	if holder.IdentityStatus == string(IdentityOperatorConfirmed) {
		return true
	}
	for _, held := range holder.Identifiers {
		if held.Kind == KindDeclarationID {
			return true
		}
		if held.Key() == addr.Key() && held.Source.Kind == SourceDeclared {
			return true
		}
	}
	return false
}

// holderLostALease reports whether the previous holder is the kind of record
// a lease can move away from: a device (it carries a device-binding identifier
// of its own — necessarily a different one from the announcer's, since the
// match went elsewhere), or a record of nothing but addresses. Anything else —
// a hostname, fqdn, name, CMDB id and no device binding — describes a service
// or a VIP, whose address is not a lease.
func holderLostALease(holder AssetSummary) bool {
	onlyAddresses := true
	for _, held := range holder.Identifiers {
		if deviceBindingKinds[held.Kind] {
			return true
		}
		if held.Kind != KindIPAddress {
			onlyAddresses = false
		}
	}
	return onlyAddresses
}

// leaseMoves decides which of a match's unattached addresses move to the
// matched asset. It writes nothing; [Engine.applyLeaseMoves] does.
//
// `unattached` is what [splitByOwner] left foreign after the match. The
// returned `remaining` is `unattached` without the addresses that will move.
func (e *Engine) leaseMoves(
	ctx context.Context,
	obs Observation,
	precedence []Kind,
	decider Identifier,
	decidedBy Kind,
	owners map[string][]AssetRef,
	unattached []Identifier,
) (moves []leaseMove, remaining []Identifier, err error) {
	remaining = unattached
	if len(unattached) == 0 {
		return nil, remaining, nil
	}
	// Conditions that are about the observation, not the address: checked once.
	// A derived decider is not direct evidence of who holds the lease (the
	// second half of condition 1), however directly the observation met the
	// device.
	if !decidedAboveAddress(precedence, decidedBy) || decider.Inferred() || !metDirectly(obs) {
		return nil, remaining, nil
	}
	if _, ok := e.repo.(IdentifierReassigner); !ok {
		return nil, remaining, nil
	}

	moved := map[string]bool{}
	holders := map[string]AssetSummary{}
	for _, id := range unattached {
		if id.Kind != KindIPAddress {
			continue
		}
		// Condition 3. It also keeps this rule off the hearsay-yields path's
		// addresses: those are muted because they VOTED for the provisional
		// asset, and an address votes only outside a dynamic scope.
		if !e.dynamic[id.Scope] && !obs.DynamicScopes[id.Scope] {
			continue
		}
		// Exactly one previous holder. An address the store says two assets
		// hold is the lost-invariant case; moving "it" would pick one of them.
		// (It is never the matched asset: splitByOwner put it in unattached
		// because somebody ELSE owns it.)
		refs := owners[id.Key()]
		if len(refs) != 1 {
			continue
		}
		from := refs[0]

		holder, ok := holders[from.ID]
		if !ok {
			sums, err := e.repo.LoadSummaries(ctx, obs.TenantID, []string{from.ID})
			if err != nil {
				return nil, unattached, fmt.Errorf("identity: reading %s, the previous holder of %s: %w", from.ID, id.Value, err)
			}
			if len(sums) != 1 {
				continue
			}
			holder = sums[0]
			holders[from.ID] = holder
		}
		if holderDeclaredAddress(holder, id) || !holderLostALease(holder) {
			continue
		}
		announced, err := e.repo.AddressAnnounced(ctx, from, id.Value)
		if err != nil {
			return nil, unattached, fmt.Errorf("identity: reading whether %s's %s was ever announced: %w", from.ID, id.Value, err)
		}
		if announced {
			continue
		}

		lastSeen, held, err := e.repo.IdentifierLastSeen(ctx, obs.TenantID, id)
		if err != nil {
			return nil, unattached, fmt.Errorf("identity: reading when %s last held %s: %w", from.ID, id.Value, err)
		}
		// Condition 4, strictly newer. The observation's OWN time, not the
		// engine's "now": a sighting that did not say when it was made has a
		// zero ObservedAt, which is after nothing, so it moves nothing.
		if !held || !obs.ObservedAt.After(lastSeen) {
			continue
		}
		moves = append(moves, leaseMove{id: id, from: from, lastSeen: lastSeen})
		moved[id.Key()] = true
	}
	if len(moves) == 0 {
		return nil, remaining, nil
	}
	return moves, withoutKeys(unattached, moved), nil
}

// applyLeaseMoves executes the moves [Engine.leaseMoves] decided, and records
// them on both assets. The caller then attaches the moved addresses to the
// matched asset in the ordinary way, which is what advances their last-seen to
// this observation.
func (e *Engine) applyLeaseMoves(ctx context.Context, obs Observation, at time.Time, decidedBy Kind, to AssetRef, moves []leaseMove) error {
	reassigner, ok := e.repo.(IdentifierReassigner)
	if !ok {
		// leaseMoves never proposes a move without one; restated so the write
		// half cannot be reached around the decision half.
		return fmt.Errorf("identity: a lease move needs a store that can reassign identifiers")
	}
	for _, m := range moves {
		if err := reassigner.ReassignIdentifier(ctx, m.id, m.from, to); err != nil {
			return fmt.Errorf("identity: moving the lease %s=%q from %s to %s: %w",
				m.id.Kind, m.id.Value, m.from.ID, to.ID, err)
		}
		changes := map[string]any{
			"identifiers":           []string{m.id.Key()},
			"from":                  m.from.ID,
			"to":                    to.ID,
			"reason":                ReasonLeaseMoved,
			"decided_by":            string(decidedBy),
			"previous_last_seen_at": m.lastSeen.UTC().Format(time.RFC3339Nano),
		}
		if e.observationID != "" {
			changes["observation_id"] = e.observationID
		}
		// On BOTH assets, as the hearsay-yields move does: each timeline has
		// to say where the address went or came from.
		for _, ref := range []AssetRef{m.from, to} {
			if err := e.history(ctx, ref, obs, at, ActionIdentifierReassigned, cloneChanges(changes)); err != nil {
				return err
			}
		}
	}
	return nil
}

// retireEmptiedLeaseHolders archives each PROVISIONAL previous holder a lease
// move left holding no identifier. An established or legacy record is left as
// it is, emptied or not: it is something a collector met or a person approved,
// and retiring it is not this rule's decision.
func (e *Engine) retireEmptiedLeaseHolders(ctx context.Context, obs Observation, at time.Time, moves []leaseMove) error {
	seen := map[string]bool{}
	for _, m := range moves {
		if seen[m.from.ID] {
			continue
		}
		seen[m.from.ID] = true
		sums, err := e.repo.LoadSummaries(ctx, m.from.TenantID, []string{m.from.ID})
		if err != nil {
			return fmt.Errorf("identity: re-reading %s after a lease move: %w", m.from.ID, err)
		}
		if len(sums) != 1 || sums[0].IdentityStatus != string(IdentityProvisional) {
			continue
		}
		if err := e.archiveIfEmptied(ctx, obs, at, m.from); err != nil {
			return err
		}
	}
	return nil
}
