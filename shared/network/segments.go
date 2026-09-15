package network

import (
	"net"
	"sort"
)

// Which tenant network segment does this address belong to?
//
// The answer is load-bearing twice over. It supplies an asset's environment,
// site and business unit (inventory-service's segment enrichment), and it is
// the SCOPE that lets a hostname or an IP decide an identity match at all
// (ADR-0002 D3: "printer-2" and 10.0.0.5 are answers to a question only once
// you say where you were standing).
//
// The rule lives here, rather than in the one service that first needed it,
// because two intake paths now ask it — inventory-service for a discovery
// finding and device-interrogation-service for a managed device — and two
// implementations of "which segment is this in" would silently put the same
// host in two segments and therefore under two identities, which is exactly
// the duplication the identification engine exists to end.
//
// Loading the segments stays with the caller: each service already has its own
// row type and its own RLS-scoped read. What is shared is the part that can
// drift meaningfully — the order segments are considered in, and what counts
// as a match.

// Segment is the minimum of a tenant network segment this rule needs. Callers
// project their own row type onto it.
type Segment struct {
	// ID is the caller's identifier for the segment, returned untouched. It is
	// a string rather than a uuid so this package stays free of a uuid
	// dependency for one field.
	ID string
	// Type is "cidr", "ip_range", "domain" or "cloud_vpc".
	Type string
	// Value is the segment's literal: a CIDR, a "start-end" range, or a domain
	// pattern.
	Value string
}

// segmentTypeOrder ranks the segment types. CIDR before ip_range before
// domain before cloud_vpc: an address inside a declared subnet is a stronger
// statement than a name matching a domain pattern, and cloud_vpc carries no
// address predicate at all so it can never match here.
var segmentTypeOrder = map[string]int{"cidr": 0, "ip_range": 1, "domain": 2, "cloud_vpc": 3}

// MatchSegment returns the segment an address belongs to, and whether one was
// found.
//
// Order of consideration:
//
//  1. By segment type (cidr, ip_range, domain, cloud_vpc), and within `cidr` by
//     prefix length descending — the MOST SPECIFIC subnet wins, so a /28
//     carve-out beats the /16 it sits inside. Ties keep the caller's order.
//  2. The IP is matched first, against cidr and ip_range segments.
//  3. Only if the IP matched nothing (or there was no IP) is the hostname
//     matched, against domain segments.
//
// An empty ip and hostname, or no segment that matches, returns false. "No
// segment" is a real answer: the identifiers it would have scoped are still
// recorded, they simply do not vote.
func MatchSegment(segments []Segment, ip, hostname string) (Segment, bool) {
	if len(segments) == 0 {
		return Segment{}, false
	}
	ordered := make([]Segment, len(segments))
	copy(ordered, segments)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Type != ordered[j].Type {
			return segmentTypeOrder[ordered[i].Type] < segmentTypeOrder[ordered[j].Type]
		}
		if ordered[i].Type != "cidr" {
			return false
		}
		return cidrPrefixLen(ordered[i].Value) > cidrPrefixLen(ordered[j].Value)
	})

	if ip != "" {
		for _, seg := range ordered {
			switch seg.Type {
			case "cidr":
				if IsIPInCIDR(ip, seg.Value) {
					return seg, true
				}
			case "ip_range":
				start, end, err := ParseIPRange(seg.Value)
				if err == nil && IsIPInRange(ip, start, end) {
					return seg, true
				}
			}
		}
	}

	if hostname != "" {
		for _, seg := range ordered {
			if seg.Type == "domain" && MatchesDomainPattern(hostname, seg.Value) {
				return seg, true
			}
		}
	}
	return Segment{}, false
}

// cidrPrefixLen returns a CIDR's mask length, or -1 when it does not parse.
//
// -1 rather than 0 so an unparseable segment sorts LAST among cidr segments
// instead of tying with 0.0.0.0/0 and possibly winning the comparison. A
// segment whose value is not a CIDR cannot match anything anyway
// (IsIPInCIDR returns false), so its only effect is on ordering.
func cidrPrefixLen(cidr string) int {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil || n == nil {
		return -1
	}
	ones, _ := n.Mask.Size()
	return ones
}
