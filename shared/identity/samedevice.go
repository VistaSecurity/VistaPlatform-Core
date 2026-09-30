package identity

import (
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
)

// RuleVerdictSameDevice is the `rule_verdict` a merge proposal carries when
// [SameDeviceVerdict] held for it ( Phase 4, owner decision D1): the
// platform is sure the two records are one device and the rule-merge executor
// in inventory-service may merge them — through the audited merge path, never
// inside Resolve (guard rail 2).
const RuleVerdictSameDevice = "same_device"

// SameDeviceLink is what [SameDeviceVerdict] needs to know about the sighting
// that linked the two records beyond its identifiers.
type SameDeviceLink struct {
	// Direct is condition 3's evidence half: the sighting met the device on
	// the wire, directly and not relayed, or is an authoritative inventory of
	// it ([DirectEvidence]). The engine reads it off the observation; the
	// executor re-evaluating a stored verdict passes true, because a verdict is
	// only ever stamped for such a sighting and what a sighting was does not
	// change afterwards.
	Direct bool
	// KeptSeparate is condition 7: a reviewer resolved a proposal naming both
	// records `kept_separate`. ANY such decision, whatever evidence it was
	// taken on — guard rail 4 says a human's "no" is never overridden by a
	// rule, and a rule is not a new question the way new evidence for a human
	// is.
	KeptSeparate bool
}

// DirectEvidence reports whether an observation is the kind of evidence the
// same-device rule may act on: it met the device directly and was not relayed
// (`Admission.Direct && !Admission.Relayed`), or it is an authoritative
// inventory (`Admission.Authoritative` — a controller's or system of record's
// own list).
func DirectEvidence(obs Observation) bool {
	return (obs.Admission.Direct && !obs.Admission.Relayed) || obs.Admission.Authoritative
}

// SameDeviceVerdict is the same-device rule ( Phase 4, owner decision
// D1): the fixed conditions under which the platform merges two EXISTING
// records without asking. It is a rule — no score is consulted — so it sits on
// the "a rule or a human approves" side of ADR-0008 D5.
//
// `candidates` are the proposal's candidates with the observation's
// identifiers that matched each; `summaries` are those candidates as the
// store holds them now, keyed by asset id. It returns true only when ALL of
// these hold:
//
//  1. exactly two LIVE candidates (in `summaries`, not archived or denied);
//  2. the observation carries at least one identifier matched to each of
//     them — it is the sighting that links them;
//  3. at least one of those matched identifiers binds a device ([bindsDevice]:
//     an observed MAC, SSH host key, serial, agent, sensor or cloud resource
//     id, or a MAC derived from an EUI-64 address or a serial — no other
//     derived kind), and the sighting is direct or authoritative
//     ([SameDeviceLink.Direct]);
//     3a. a record the sighting reached by ADDRESSES ALONE must itself hold
//     nothing but addresses (the IP-only record a NIC should absorb) — an
//     address is a lease, and a named record that held it before is another
// device ( C1);
//     3b. a record the sighting did not reach through a device binding must
//     not carry a device-binding identifier of its own that the sighting did
//     not match — that is a reused lease or a re-imaged box;
//  4. no singleton disagreement between the two: the same singleton kind in
//     the same scope with two different values is two things;
//  5. both are in the same real segment, or at least one of them has none (a
//     declared record may not have been placed);
//  6. both are `monitoring`, or one is `monitoring` and the other
//     `pending_approval` (a pending duplicate of an approved asset is still a
//     duplicate) — never two pending records, because admitting a record and
//     merging two are two decisions;
//  7. no reviewer ever kept the pair separate ([SameDeviceLink.KeptSeparate]);
//  8. neither candidate's only link is a generic or synthetic name.
//
// The evidence is human-readable, in the order the rule established it, and
// becomes the merge's audit reason and the "Merged automatically" row's
// explanation. It is runtime data about the tenant's own records. On false the
// evidence is nil.
func SameDeviceVerdict(obs Observation, candidates []MergeCandidate, summaries map[string]AssetSummary, link SameDeviceLink) (bool, []string) {
	// 1. Exactly two live candidates.
	var live []MergeCandidate
	for _, c := range candidates {
		s, ok := summaries[c.Ref.ID]
		if !ok || s.Status == StatusArchived || s.Status == StatusDenied {
			continue
		}
		live = append(live, c)
	}
	if len(live) != 2 {
		return false, nil
	}
	a, b := live[0], live[1]
	sa, sb := summaries[a.Ref.ID], summaries[b.Ref.ID]

	// 2. The sighting links them: something it carried matched each.
	if len(a.MatchedIdentifiers) == 0 || len(b.MatchedIdentifiers) == 0 {
		return false, nil
	}

	// 3. A device-binding identifier, met directly or reported authoritatively.
	if !link.Direct {
		return false, nil
	}
	binding, bindingOn, ok := firstDeviceBinding(a, b)
	if !ok {
		return false, nil
	}

	// 3a. An address is a lease, not an identity ( C1). A record the
	// sighting reached by ADDRESSES ALONE is the same device only when the
	// record is itself nothing but addresses — the IP-only record a device's
	// NIC should absorb. A record with a name (or anything else) that merely
	// held the lease before is a different device.
	// 3b. A record the sighting did not reach through a device binding, but
	// which carries a device binding of its OWN that the sighting did not
	// match, is another device: a reused lease, a re-imaged or renamed box.
	onlyAddressesA, onlyAddressesB := false, false
	for _, side := range []struct {
		c    MergeCandidate
		s    AssetSummary
		only *bool
	}{{a, sa, &onlyAddressesA}, {b, sb, &onlyAddressesB}} {
		if addressOnlyLink(side.c.MatchedIdentifiers) {
			if !holdsOnlyAddresses(side.s) {
				return false, nil
			}
			*side.only = true
		}
		if !linksADevice(side.c.MatchedIdentifiers) && holdsAnUnmatchedDevice(side.s, side.c.MatchedIdentifiers) {
			return false, nil
		}
	}

	// 4. No singleton disagreement between the two records.
	if _, disagree := summariesDisagree(sa, sb); disagree {
		return false, nil
	}

	// 5. The same real segment, or one of them has none.
	segA, segB := realSegment(sa.NetworkSegment), realSegment(sb.NetworkSegment)
	if segA != "" && segB != "" && segA != segB {
		return false, nil
	}

	// 6. Monitoring + monitoring, or monitoring + pending. Never pending + pending.
	if !pairStatusMergeable(sa.Status, sb.Status) {
		return false, nil
	}

	// 7. A human's "keep separate" is never overridden by a rule (guard rail 4).
	if link.KeptSeparate {
		return false, nil
	}

	// 8. Neither record is linked by a generic or synthetic name alone.
	if weakNamesOnly(a.MatchedIdentifiers) || weakNamesOnly(b.MatchedIdentifiers) {
		return false, nil
	}

	holder, other, otherLink := sa, sb, b.MatchedIdentifiers
	if bindingOn == b.Ref.ID {
		holder, other, otherLink = sb, sa, a.MatchedIdentifiers
	}
	bindingLabel := kindLabel(binding.Kind) + " " + binding.Value
	if binding.Inferred() {
		bindingLabel += " (derived from " + derivedFrom(binding) + ")"
	}
	evidence := []string{
		fmt.Sprintf("%s, held by %s, %s", bindingLabel, recordLabel(holder), sightingLabel(obs)),
		fmt.Sprintf("the same sighting carried %s, which belongs to %s", describeIdentifiers(otherLink), recordLabel(other)),
	}
	switch {
	case segA != "" && segA == segB:
		evidence = append(evidence, "same segment")
	case segA == "" && segB == "":
		evidence = append(evidence, "no segment on either record")
	default:
		evidence = append(evidence, "one of the records has no segment")
	}
	if onlyAddressesA || onlyAddressesB {
		evidence = append(evidence, "the record reached by address holds nothing but addresses")
	}
	evidence = append(evidence, "no one-per-asset identifier disagrees")
	return true, evidence
}

// firstDeviceBinding is the first device-binding identifier the sighting
// matched to either candidate, and the candidate it matched. An observed one is
// preferred to a derived one, so the evidence names what was actually seen
// when both are there.
func firstDeviceBinding(cs ...MergeCandidate) (Identifier, string, bool) {
	var (
		derived   Identifier
		derivedOn string
		found     bool
	)
	for _, c := range cs {
		for _, id := range c.MatchedIdentifiers {
			if !bindsDevice(id) {
				continue
			}
			if !id.Inferred() {
				return id, c.Ref.ID, true
			}
			if !found {
				derived, derivedOn, found = id, c.Ref.ID, true
			}
		}
	}
	return derived, derivedOn, found
}

// bindsDevice is condition 3's list: an OBSERVED device-binding identifier
// ([deviceBindingKinds]), or a MAC the intake DERIVED from an EUI-64 address or
// a serial ( Phase 2, [Identifier.Inferred]) — the spec names the inferred
// MAC explicitly, and no other derived kind.
func bindsDevice(id Identifier) bool {
	if !deviceBindingKinds[id.Kind] {
		return false
	}
	return !id.Inferred() || id.Kind == KindMACAddress
}

// addressOnlyLink reports whether a link consists of nothing but ip_address
// identifiers. An empty link is not one (condition 2 refuses it).
func addressOnlyLink(link []Identifier) bool {
	if len(link) == 0 {
		return false
	}
	for _, id := range link {
		if id.Kind != KindIPAddress {
			return false
		}
	}
	return true
}

// holdsOnlyAddresses reports whether a record carries no identifier but
// addresses — the IP-only record (the same test as the lease rule's
// [holderLostALease] "nothing but addresses" arm).
func holdsOnlyAddresses(s AssetSummary) bool {
	if len(s.Identifiers) == 0 {
		return false
	}
	for _, id := range s.Identifiers {
		if id.Kind != KindIPAddress {
			return false
		}
	}
	return true
}

// linksADevice reports whether the sighting reached this record through a
// device-binding identifier.
func linksADevice(link []Identifier) bool {
	for _, id := range link {
		if bindsDevice(id) {
			return true
		}
	}
	return false
}

// holdsAnUnmatchedDevice reports whether the record carries a device-binding
// identifier (observed or derived) the sighting did not match.
func holdsAnUnmatchedDevice(s AssetSummary, link []Identifier) bool {
	matched := make(map[string]bool, len(link))
	for _, id := range link {
		matched[id.Key()] = true
	}
	for _, held := range s.Identifiers {
		if deviceBindingKinds[held.Kind] && !matched[held.Key()] {
			return true
		}
	}
	return false
}

// summariesDisagree reports the first singleton kind the two records both hold
// in the same scope with different values.
func summariesDisagree(a, b AssetSummary) (Kind, bool) {
	held := map[string]string{}
	for _, id := range a.Identifiers {
		if id.Kind.Singleton() {
			held[string(id.Kind)+"\x00"+id.Scope] = id.Value
		}
	}
	for _, id := range b.Identifiers {
		if !id.Kind.Singleton() {
			continue
		}
		if v, ok := held[string(id.Kind)+"\x00"+id.Scope]; ok && v != id.Value {
			return id.Kind, true
		}
	}
	return "", false
}

// realSegment is the segment a record is placed in, "" for none. The
// tenant-wide default scope is not a segment.
func realSegment(s string) string {
	s = strings.TrimSpace(s)
	if s == ScopeTenantDefault {
		return ""
	}
	return s
}

func pairStatusMergeable(a, b string) bool {
	switch {
	case a == StatusMonitoring && b == StatusMonitoring:
		return true
	case a == StatusMonitoring && b == StatusPendingApproval, a == StatusPendingApproval && b == StatusMonitoring:
		return true
	default:
		return false
	}
}

// weakNamesOnly reports whether a link consists of nothing but names that do
// not identify a device: generic ones ([Identifier.Generic], marked at ingest)
// and synthetic ones ([hostnamequality.IsIdentityName] false — a rotating
// UUID-form instance name, a lease written as a name). An empty link is not a
// weak one; condition 2 refuses it on its own terms.
func weakNamesOnly(link []Identifier) bool {
	if len(link) == 0 {
		return false
	}
	for _, id := range link {
		switch id.Kind {
		case KindHostname, KindFQDN, KindName:
			if id.Generic || !hostnamequality.IsIdentityName(id.Value) {
				continue
			}
		}
		return false
	}
	return true
}

func kindLabel(k Kind) string {
	switch k {
	case KindMACAddress:
		return "MAC address"
	case KindSSHHostKeyFingerprint:
		return "SSH host key"
	case KindSerialNumber:
		return "serial number"
	case KindAgentID:
		return "agent id"
	case KindSensorID:
		return "sensor id"
	case KindCloudResourceID:
		return "cloud resource id"
	case KindIPAddress:
		return "address"
	case KindHostname:
		return "hostname"
	case KindFQDN:
		return "FQDN"
	default:
		return strings.ReplaceAll(string(k), "_", " ")
	}
}

// derivedFrom renders a derived identifier's evidence ref
// ("derived:eui64:<addr>", "derived:serial:<serial>") for a sentence.
func derivedFrom(id Identifier) string {
	ref := strings.TrimPrefix(strings.TrimSpace(id.Source.Ref), "derived:")
	switch {
	case strings.HasPrefix(ref, "eui64:"):
		return "the IPv6 address " + strings.TrimPrefix(ref, "eui64:")
	case strings.HasPrefix(ref, "serial:"):
		return "the serial number " + strings.TrimPrefix(ref, "serial:")
	case ref == "":
		return "other evidence"
	default:
		return ref
	}
}

func sightingLabel(obs Observation) string {
	who := strings.TrimSpace(obs.Source.Ref)
	if who == "" {
		who = string(obs.Source.Kind)
	}
	if who == "" {
		who = "a collector"
	}
	if obs.Admission.Authoritative && (!obs.Admission.Direct || obs.Admission.Relayed) {
		return "reported by " + who + ", an authoritative inventory"
	}
	return "seen directly by " + who
}

func describeIdentifiers(ids []Identifier) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, kindLabel(id.Kind)+" "+id.Value)
	}
	return strings.Join(parts, ", ")
}

func recordLabel(s AssetSummary) string {
	if n := strings.TrimSpace(s.DisplayName); n != "" {
		return "the record " + n
	}
	return "the record " + s.Ref.ID
}
