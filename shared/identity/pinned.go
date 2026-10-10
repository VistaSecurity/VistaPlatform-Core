package identity

import (
	"context"
	"fmt"
	"strings"
)

// A pinned address (owner decision 1; ADR-0002 D3 erratum
// "a pinned address votes in a dynamic segment").
//
// ADR-0002 D3 says an ip_address never decides a match inside a scope flagged
// dynamic: today's lease is tomorrow's other host. The flag is per SEGMENT, and
// a segment is flagged as soon as anything there hands out a lease — including
// the router whose own LAN address is a static configuration nobody will ever
// lease to anything else. Under the bare rule that router's address could never
// decide a match on its own LAN, so every scan of it came back `unresolved`.
//
// The rule now: an `ip_address` inside a dynamic scope still decides a match
// when the asset that already OWNS that identifier holds it as
// [AssignmentStatic] — pinned by an operator's declaration, or by the host's
// own agent reporting the interface as statically configured. The segment keeps
// its DHCP flag; only that one address of that one owner is exempt.
//
// Three consequences, each deliberate:
//
//   - The incoming observation does not have to say anything. A plain sensor
//     scan of a pinned address matches, because the pin is a fact about the
//     OWNER's copy, not about the sighting.
//   - A pin helps only its owner. The identifier key is unique per tenant, so
//     the only asset a pinned address can vote for is the one holding it; a
//     pin on A never helps an observation onto B, and an observation whose MAC
//     names B while A's pinned address is also present is a conflict, not a
//     match for either.
//   - A pinned address is not a lease, so "the address follows the MAC"
//     (lease.go) never moves it to another device.

// pinnedAddresses returns the keys of the observation's `ip_address`
// identifiers that sit in a dynamic scope and whose single owner holds them as
// [AssignmentStatic]. Addresses outside a dynamic scope are not listed — they
// vote anyway — and an address with no owner, or with several (the
// lost-invariant case), is not pinned.
//
// It costs one ownership lookup per dynamic-scope address and one summary load
// per distinct owner, and nothing at all for an observation with no address in
// a dynamic scope, which is most of them.
func (e *Engine) pinnedAddresses(ctx context.Context, obs Observation) (map[string]bool, error) {
	if strings.TrimSpace(obs.TenantID) == "" {
		// Resolve refuses a tenantless observation itself, with the error
		// that says why; asking the store first would answer a different one.
		return nil, nil
	}
	var pinned map[string]bool
	summaries := map[string]*AssetSummary{}
	for _, raw := range obs.Identifiers {
		if raw.Kind != KindIPAddress {
			continue
		}
		id, err := raw.Normalized()
		if err != nil {
			// The resolution itself reports the malformed identifier.
			continue
		}
		if !e.dynamic[id.Scope] && !obs.DynamicScopes[id.Scope] {
			continue
		}
		owners, err := e.ownersOf(ctx, obs.TenantID, id)
		if err != nil {
			return nil, fmt.Errorf("identity: looking up the owner of %s=%q: %w", id.Kind, id.Value, err)
		}
		if len(owners) != 1 {
			continue
		}
		owner := owners[0].ID
		sum, loaded := summaries[owner]
		if !loaded {
			sums, err := e.repo.LoadSummaries(ctx, obs.TenantID, []string{owner})
			if err != nil {
				return nil, fmt.Errorf("identity: reading %s, the owner of %s, for its address assignment: %w", owner, id.Value, err)
			}
			if len(sums) == 1 {
				sum = &sums[0]
			}
			summaries[owner] = sum
		}
		if sum == nil {
			continue
		}
		for _, held := range sum.Identifiers {
			if held.Key() == id.Key() && held.Assignment == AssignmentStatic {
				if pinned == nil {
					pinned = map[string]bool{}
				}
				pinned[id.Key()] = true
				break
			}
		}
	}
	return pinned, nil
}

// addressPinned reports whether this `ip_address` identifier's owner holds it
// pinned ([Engine.pinnedAddresses], computed once per observation by
// [Engine.Resolve]).
func (o Observation) addressPinned(id Identifier) bool {
	return id.Kind == KindIPAddress && o.pinned[id.Key()]
}

// dynamicAddress is the ADR-0002 D3 test every voting rule shares: an
// `ip_address` in a scope flagged dynamic — by the engine's configuration or by
// the observation — whose owner has not pinned it.
func (e *Engine) dynamicAddress(obs Observation, id Identifier) bool {
	if id.Kind != KindIPAddress {
		return false
	}
	if !e.dynamic[id.Scope] && !obs.DynamicScopes[id.Scope] {
		return false
	}
	// A claimed address its holder keeps (claimed.go) is not a lease
	// either: the device reported it as its own, so it votes and the two
	// holders become a merge proposal.
	return !obs.addressPinned(id) && !obs.claimContested(id)
}
