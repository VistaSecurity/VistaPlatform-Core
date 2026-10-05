package identity

// Claimed addresses ("gateway owns its networks").
//
// A gateway reports its own address on every network it routes. That is the
// device reading its own interface configuration over a session the platform
// opened to it: first-hand, direct evidence about whose address this is, and
// stronger than any sighting of the address in use. Before this rule the
// address was only ever attached where nobody else held it, so a router known
// to the sensor on two of its four networks stayed known on two, and a stray
// record created from one of its addresses kept that address for good.
//
// A claimed address is pinned (identifier.go), and the engine settles who else
// holds it, before the precedence walk:
//
//   - nobody, or the claimant itself: nothing special. It attaches like any
//     other identifier, pinned.
// - a PROVISIONAL asset (: built from hearsay), or an asset that holds
//     nothing but addresses, and that shares nothing else with the
//     observation: the address RE-HOMES. It is muted for the walk, and once
//     the walk has decided the claimant it moves there through
//     [IdentifierReassigner], with an `identifier_reassigned` entry on both
//     assets (reason [ReasonClaimedByDevice]). A provisional holder the move
//     empties is archived, as the hearsay-yields rule archives one.
//   - anything else — an established asset holding it together with stronger
//     identifiers, an operator's declaration, an address the holder's own agent
//     pinned, an address the floating-address rule has seen announced as a
//     VIP: the holder KEEPS it. The address votes even inside a dynamic scope,
//     so the walk sees two assets and the conflict path opens a merge proposal
//     naming both; the claimant does not take it.
//
// Two rules this must not break, both pinned by tests:
//
//   - Decision 3, the floating-address rule: a router answering ARP for its
//     own addresses is not announcing another asset. Once its addresses are
//     its own, the MAC and the address name one asset and there is no pair.
// -, the mDNS reflector: a router repeating another device's name
//     from its own address must not absorb the name. A relayed sighting votes
//     with nothing but a direct MAC, and supporting evidence on an established
//     asset attaches nothing, whatever the address now belongs to.

import (
	"context"
	"fmt"
	"time"
)

// ReasonClaimedByDevice — an address the device reported as its own
// configured interface address moved to it from a provisional or address-only
// holder. Written on BOTH assets' `identifier_reassigned` history entries.
const ReasonClaimedByDevice = "claimed_by_device"

// addressClaim is one claimed address the engine will move after the walk.
type addressClaim struct {
	id     Identifier
	holder AssetRef
}

// addressClaims is the per-resolution decision about an observation's claimed
// addresses.
type addressClaims struct {
	// rehome: identifier key → the claim to execute once the walk decides.
	// These addresses do not vote.
	rehome map[string]addressClaim
	// contest: identifier keys that vote even inside a dynamic scope, so a
	// holder that keeps the address becomes a merge proposal.
	contest map[string]bool
}

// claimsFirstHand reports whether an observation with this source and
// admission evidence may claim an address: a measurement, taken directly and
// authoritatively (an authenticated session), not relayed. Intake refuses a
// claim on anything else; the engine re-checks so a hand-built observation
// cannot reach the rule around Intake.
func claimsFirstHand(src Source, a AdmissionEvidence) bool {
	return src.Kind == SourceMeasured && a.Direct && a.Authoritative && !a.Relayed
}

// decideAddressClaims looks at each claimed address of the observation and
// decides whether it re-homes, is contested, or is ordinary. It reads one
// summary per distinct holder and writes nothing.
func (e *Engine) decideAddressClaims(ctx context.Context, obs Observation, ids []Identifier, owners map[string][]AssetRef) (addressClaims, error) {
	var out addressClaims
	if !claimsFirstHand(obs.Source, obs.Admission) {
		return out, nil
	}
	_, canMove := e.repo.(IdentifierReassigner)
	summaries := map[string]*AssetSummary{}
	for _, id := range ids {
		if id.Kind != KindIPAddress || !id.Claimed || id.Inferred() {
			continue
		}
		refs := owners[id.Key()]
		if len(refs) != 1 {
			// Nobody holds it (it simply attaches), or the store has lost the
			// one-owner invariant, which the walk reports as corruption.
			continue
		}
		holder := refs[0]
		if !otherIdentifierOwned(ids, owners, id) {
			// Nothing else in the observation names any asset: there is no
			// claimant for the address to move TO, and muting it would leave
			// the walk with nothing at all. An ordinary identifier.
			continue
		}
		if sharesOtherIdentifier(ids, owners, id, holder.ID) {
			// The holder is linked to this observation by something besides
			// the address: it is the claimant itself (an interrogation carries
			// the device's known identifiers), or a device the walk has to
			// weigh on its own evidence. Never stripped; the address votes, so
			// the claimant's own copy decides for it and anyone else's is a
			// conflict a reviewer settles.
			out.contestKey(id)
			continue
		}
		sum, loaded := summaries[holder.ID]
		if !loaded {
			sums, err := e.repo.LoadSummaries(ctx, obs.TenantID, []string{holder.ID})
			if err != nil {
				return addressClaims{}, fmt.Errorf("identity: reading %s, the holder of the claimed address %s: %w", holder.ID, id.Value, err)
			}
			if len(sums) == 1 {
				sum = &sums[0]
			}
			summaries[holder.ID] = sum
		}
		if sum == nil {
			continue
		}
		yields, err := e.holderYieldsClaim(ctx, *sum, holder, id)
		if err != nil {
			return addressClaims{}, err
		}
		if yields && canMove {
			if out.rehome == nil {
				out.rehome = map[string]addressClaim{}
			}
			out.rehome[id.Key()] = addressClaim{id: id, holder: holder}
			continue
		}
		out.contestKey(id)
	}
	return out, nil
}

// contestKey marks a claimed address as one its holder keeps.
func (c *addressClaims) contestKey(id Identifier) {
	if c.contest == nil {
		c.contest = map[string]bool{}
	}
	c.contest[id.Key()] = true
}

// holderYieldsClaim reports whether the holder of a claimed address gives it
// up: a provisional asset, or one whose identity is addresses and nothing
// else. Never an address a person declared or confirmed, one the holder's own
// agent pinned (holderDeclaredAddress), or one the floating-address rule has
// recorded as announced — that holder is a VIP record.
func (e *Engine) holderYieldsClaim(ctx context.Context, sum AssetSummary, holder AssetRef, id Identifier) (bool, error) {
	if holderDeclaredAddress(sum, id) {
		return false, nil
	}
	if sum.IdentityStatus != string(IdentityProvisional) && !holdsOnlyAddresses(sum) {
		return false, nil
	}
	announced, err := e.repo.AddressAnnounced(ctx, holder, id.Value)
	if err != nil {
		return false, fmt.Errorf("identity: reading whether %s's %s was ever announced: %w", holder.ID, id.Value, err)
	}
	return !announced, nil
}

// sharesOtherIdentifier reports whether any identifier of the observation
// other than `claimed` is owned by assetID.
func sharesOtherIdentifier(ids []Identifier, owners map[string][]AssetRef, claimed Identifier, assetID string) bool {
	for _, other := range ids {
		if other.Key() == claimed.Key() {
			continue
		}
		for _, r := range owners[other.Key()] {
			if r.ID == assetID {
				return true
			}
		}
	}
	return false
}

// otherIdentifierOwned reports whether any identifier of the observation other
// than `claimed` is owned by some asset.
func otherIdentifierOwned(ids []Identifier, owners map[string][]AssetRef, claimed Identifier) bool {
	for _, other := range ids {
		if other.Key() != claimed.Key() && len(owners[other.Key()]) > 0 {
			return true
		}
	}
	return false
}

// claimMuted reports whether this identifier is a claimed address that will
// re-home, and so does not vote.
func (o Observation) claimMuted(id Identifier) bool {
	_, ok := o.claims.rehome[id.Key()]
	return ok
}

// claimContested reports whether this identifier is a claimed address whose
// holder keeps it, and so votes even in a dynamic scope.
func (o Observation) claimContested(id Identifier) bool {
	return id.Kind == KindIPAddress && o.claims.contest[id.Key()]
}

// applyAddressClaims moves the re-homing claims to the decided asset and
// returns the moved identifiers, which the caller attaches like any other.
// `unattached` comes back without them.
func (e *Engine) applyAddressClaims(ctx context.Context, obs Observation, at time.Time, to AssetRef, unattached []Identifier) (moved, remaining []Identifier, err error) {
	if len(obs.claims.rehome) == 0 {
		return nil, unattached, nil
	}
	reassigner, ok := e.repo.(IdentifierReassigner)
	if !ok {
		// decideAddressClaims re-homes nothing without one; restated so the
		// write half cannot be reached around the decision half.
		return nil, unattached, fmt.Errorf("identity: re-homing a claimed address needs a store that can reassign identifiers")
	}
	movedKeys := map[string]bool{}
	for _, id := range unattached {
		claim, ok := obs.claims.rehome[id.Key()]
		if !ok || claim.holder.ID == to.ID {
			continue
		}
		if err := reassigner.ReassignIdentifier(ctx, claim.id, claim.holder, to); err != nil {
			return nil, unattached, fmt.Errorf("identity: moving the claimed address %s=%q from %s to %s: %w",
				claim.id.Kind, claim.id.Value, claim.holder.ID, to.ID, err)
		}
		changes := map[string]any{
			"identifiers": []string{id.Key()},
			"from":        claim.holder.ID,
			"to":          to.ID,
			"reason":      ReasonClaimedByDevice,
		}
		if e.observationID != "" {
			changes["observation_id"] = e.observationID
		}
		// On BOTH assets, as every other reassignment: each timeline says
		// where the address went or came from.
		for _, ref := range []AssetRef{claim.holder, to} {
			if err := e.history(ctx, ref, obs, at, ActionIdentifierReassigned, cloneChanges(changes)); err != nil {
				return nil, unattached, err
			}
		}
		moved = append(moved, id)
		movedKeys[id.Key()] = true
	}
	return moved, withoutKeys(unattached, movedKeys), nil
}

// retireClaimedHolders archives each PROVISIONAL holder a claim left holding
// no identifier. An address-only established record is left as it is, emptied
// or not: something met it or a person approved it, and retiring it is not
// this rule's decision (the lease rule's answer, for the same reason).
func (e *Engine) retireClaimedHolders(ctx context.Context, obs Observation, at time.Time, moved []Identifier) error {
	seen := map[string]bool{}
	for _, id := range moved {
		holder := obs.claims.rehome[id.Key()].holder
		if seen[holder.ID] {
			continue
		}
		seen[holder.ID] = true
		sums, err := e.repo.LoadSummaries(ctx, obs.TenantID, []string{holder.ID})
		if err != nil {
			return fmt.Errorf("identity: re-reading %s after a claimed address moved: %w", holder.ID, err)
		}
		if len(sums) != 1 || sums[0].IdentityStatus != string(IdentityProvisional) {
			continue
		}
		if err := e.archiveIfEmptied(ctx, obs, at, holder); err != nil {
			return err
		}
	}
	return nil
}
