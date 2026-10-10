package identity

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// The lease-fresh address (ADR-0002 D3 erratum; owner decision.
//
// ADR-0002 D3 says an `ip_address` never decides a match inside a scope
// flagged dynamic: today's lease is tomorrow's other host. Pinning (pinned.go,
// decision 1) exempts an address a person or the host's own agent
// declared static. Everything else was a lease to the vote, however recently
// the platform had itself confirmed WHICH device held it — and on a sensored
// DHCP network that is constantly: the sensor sees the device's MAC at its
// address every few minutes, and then refuses to believe an SSH probe of the
// same address an hour later is the same device. Every such probe became an
// Observations row for a person to link by hand.
//
// The rule: an `ip_address` in a dynamic scope decides a match for its single
// owner when all of the following hold. Each condition is there because its
// absence is a way to attach one device's sighting to another device's record.
//
//  1. The owner's copy of the address is DEVICE-CONFIRMED within the lease
//     window: a resolution decided by an observed (not derived) device-binding
//     kind, from a direct measurement, attached or re-attached the address to
//     that asset ([Identifier.DeviceConfirmedAt]). A sighting that touched the
//     row by name confirmed nothing about the device.
//  2. The window is measured from the sighting's OWN clock, ObservedAt, as the
//     lease rule's condition 4 is (lease.go): a replayed or late-arriving
//     sighting cannot look fresher than it is.
//  3. Exactly one asset owns the address, and it can be linked. Several is the
//     lost-invariant case and stays a conflict.
//  4. The owner carries an observed device binding of its own. An address-only
//     or name-only record is a service or VIP record: nothing ever confirmed a
//     DEVICE there. The same holder guard lease.go applies.
//  5. The incoming sighting is a direct, non-relayed measurement. Hearsay about
//     who holds a lease — an advertisement, flow traffic, an import — proves
//     nothing about now.
//  6. The sighting carries no observed `mac_address` the owner does not hold.
//     A different NIC at a fresh address is a different device, or the lease
//     has moved; the MAC is the stronger evidence and decides, and lease.go
//     moves the address — instead of the cross-kind conflict a PINNED address
//     would form ("a pin helps only its owner").
//
// What a lease-fresh address is not:
//
//   - Not a pin. It expires, and the lease rule still moves it: only the three
//     VOTE sites read it ([AssessAdmission], [Engine.kindVotes],
//     [Engine.leaseOnlyLink]), through [Engine.addressDecides]; the MOVE sites
//     (lease.go, floating.go, claimed.go) keep reading [Engine.dynamicAddress]
//     and see a lease. Folding it into dynamicAddress would have blocked the
//     move for the whole window — the previous holder's copy is by definition
//     fresh when a new MAC shows up at it.
//   - Not a licence to write other device bindings. A match the address
//     decided still passes the walk's guards: interfaceBindingConflict (a MAC
//     the asset does not know), classifyDrift (a replaced host key goes to
// review; a key of a new algorithm is attached, decision 4).
//   - Not a change to what is probed. It changes what a probe's answer is
//     matched to, nothing about consent (shared/probeconsent).

// DefaultLeaseWindow is how long a device confirmation keeps an address
// deciding when [Config.LeaseWindow] is zero. A live device's confirmation is
// refreshed by every passive sighting of its MAC, so the window matters only
// for a device that has gone quiet — and a DHCP server keeps a quiet client's
// lease reserved for at least its lease time, which is a day on most home and
// office networks and longer on most enterprise ones.
const DefaultLeaseWindow = 24 * time.Hour

// leaseFreshAddresses returns the keys of the observation's `ip_address`
// identifiers that sit in a dynamic scope and satisfy every condition above.
// Addresses outside a dynamic scope are not listed — they vote anyway — and
// so is nothing at all when the rule is off (a negative window) or the
// sighting is not a direct measurement (condition 5), which costs no lookup.
//
// Like [Engine.pinnedAddresses] it is computed once per observation by
// [Engine.Resolve], under the identifier locks, so admission and every voting
// rule decide on the same answer; and like it, it costs one ownership lookup
// per dynamic-scope address and one summary load per distinct owner.
func (e *Engine) leaseFreshAddresses(ctx context.Context, obs Observation) (map[string]bool, error) {
	if e.leaseWindow < 0 || strings.TrimSpace(obs.TenantID) == "" || !directMeasurement(obs) {
		return nil, nil
	}
	at := obs.ObservedAt
	if at.IsZero() {
		at = e.now().UTC()
	}
	// Condition 6 needs the observed MACs once, not per address.
	observedMACs := map[string]bool{}
	for _, raw := range obs.Identifiers {
		if raw.Kind != KindMACAddress || raw.Inferred() {
			continue
		}
		if id, err := raw.Normalized(); err == nil {
			observedMACs[id.Value] = true
		}
	}
	var fresh map[string]bool
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
		if len(owners) != 1 { // condition 3
			continue
		}
		owner := owners[0].ID
		sum, loaded := summaries[owner]
		if !loaded {
			sums, err := e.repo.LoadSummaries(ctx, obs.TenantID, []string{owner})
			if err != nil {
				return nil, fmt.Errorf("identity: reading %s, the owner of %s, for its device confirmation: %w", owner, id.Value, err)
			}
			if len(sums) == 1 {
				sum = &sums[0]
			}
			summaries[owner] = sum
		}
		if sum == nil || !ownerLeaseFreshAt(*sum, id, at, e.leaseWindow, observedMACs) {
			continue
		}
		if fresh == nil {
			fresh = map[string]bool{}
		}
		fresh[id.Key()] = true
	}
	return fresh, nil
}

// ownerLeaseFreshAt is conditions 1, 2, 3 (linkable), 4 and 6 over the owner's
// summary, for one address, at the sighting's own time.
func ownerLeaseFreshAt(sum AssetSummary, id Identifier, at time.Time, window time.Duration, observedMACs map[string]bool) bool {
	if sum.Status == StatusArchived || sum.Status == StatusDenied { // condition 3: linkable
		return false
	}
	confirmed, bound := time.Time{}, false
	heldMACs := map[string]bool{}
	for _, held := range sum.Identifiers {
		if held.Key() == id.Key() {
			confirmed = held.DeviceConfirmedAt
		}
		if deviceBindingKinds[held.Kind] && !held.Inferred() { // condition 4
			bound = true
		}
		if held.Kind == KindMACAddress {
			heldMACs[held.Value] = true
		}
	}
	for mac := range observedMACs { // condition 6: a MAC the owner holds is not foreign
		if !heldMACs[mac] {
			return false
		}
	}
	if confirmed.IsZero() || !bound { // conditions 1, 4
		return false
	}
	// A confirmation is evidence from its own observation time forward. Letting
	// it decide an earlier sighting would use knowledge from the future to join
	// historical DHCP evidence, which can attach a former lease holder to the
	// current device. The upper bound then keeps the normal expiry behavior.
	return !at.Before(confirmed) && at.Sub(confirmed) <= window // condition 2
}

// addressLeaseFresh reports whether this `ip_address` identifier's owner was
// device-confirmed at it within the window ([Engine.leaseFreshAddresses],
// computed once per observation by [Engine.Resolve]).
func (o Observation) addressLeaseFresh(id Identifier) bool {
	return id.Kind == KindIPAddress && o.leaseFresh[id.Key()]
}

// addressDecides is the test the VOTE sites share — [Engine.kindVotes],
// [Engine.leaseOnlyLink] and, through [Observation.addressLeaseFresh],
// [AssessAdmission]: an address decides unless it is a lease to the vote, and a
// lease-fresh address is not. The MOVE sites read [Engine.dynamicAddress]
// instead, deliberately: see the file comment.
func (e *Engine) addressDecides(obs Observation, id Identifier) bool {
	return !e.dynamicAddress(obs, id) || obs.addressLeaseFresh(id)
}

// directMeasurement is condition 5, and the half of "device-confirmed" that is
// about the sighting: a measured observation that met the device directly
// (an L2 frame, an L3 probe, an authenticated session) and was not relayed.
func directMeasurement(obs Observation) bool {
	return obs.Source.Kind == SourceMeasured && obs.Admission.Direct && !obs.Admission.Relayed
}

// deviceDecided reports whether a match confirms the device at the addresses
// it attaches: decided by an observed (not derived) device-binding kind, in a
// direct measurement.
func deviceDecided(obs Observation, decidedBy Kind, decider Identifier) bool {
	return deviceBindingKinds[decidedBy] && !decider.Inferred() && directMeasurement(obs)
}

// deviceMet is deviceDecided for a creation, where nothing decided: the
// observation met a device directly and carries an observed device binding
// among the identifiers the record is created with.
func deviceMet(obs Observation, ids []Identifier) bool {
	if !directMeasurement(obs) {
		return false
	}
	for _, id := range ids {
		if deviceBindingKinds[id.Kind] && !id.Inferred() {
			return true
		}
	}
	return false
}

// stampDeviceConfirmation marks every `ip_address` in ids as device-confirmed
// at `at` when confirmed is true, and returns ids unchanged otherwise. The
// stores keep the newest confirmation ([UpsertIdentifier] and the SQL upsert's
// GREATEST), so stamping an attach that re-sights an already-confirmed address
// advances it and a stamp that is older than the stored one changes nothing.
func stampDeviceConfirmation(at time.Time, ids []Identifier, confirmed bool) []Identifier {
	if !confirmed {
		return ids
	}
	out := make([]Identifier, len(ids))
	copy(out, ids)
	for i := range out {
		if out[i].Kind == KindIPAddress {
			out[i].DeviceConfirmedAt = at
		}
	}
	return out
}
