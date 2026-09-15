// Package relationships is the canonical vocabulary of asset relationship
// types — the ten paired types of asset-inventory ADR-0003 D2.
//
// `asset_relationships.type` deliberately carries no CHECK constraint: the
// schema comment says the vocabulary "is registry-validated in Go, not by a
// CHECK — the vocabulary is owned by the relationship registry, and a CHECK
// here would be a second copy". This package is that registry.
//
// Edges are stored ONCE, in the canonical direction. The reverse label is
// derived by [Type.Reverse] and never stored: storing both directions doubles
// writes and invites asymmetry bugs (ADR-0003, alternatives rejected).
//
// It is deliberately free of dependencies — every producer of edges imports it,
// including the collectors vendored into the standalone agent binary, so it
// must stay pure Go with nothing behind it.
package relationships

import "sort"

// Type is one relationship type. A defined type rather than a bare string so a
// typo is a compile error at every producer.
type Type string

// The ten canonical types, in the order of the ADR-0003 D2 table. Canonical
// means from → to: `runs_on` reads "the from-asset runs on the to-asset".
const (
	// RunsOn — application → server, container → virtual machine.
	RunsOn Type = "runs_on"
	// HostedOn — virtual machine → hypervisor, cloud resource → account or
	// region.
	HostedOn Type = "hosted_on"
	// VirtualizedBy — virtual machine → hypervisor or cluster.
	VirtualizedBy Type = "virtualized_by"
	// DependsOn — application → database instance, service → application.
	DependsOn Type = "depends_on"
	// ConnectsTo — any endpoint's asset → any asset or external. The type an
	// observed flow, an active probe, or an LLDP/CDP neighbour produces.
	ConnectsTo Type = "connects_to"
	// MemberOf — server → cluster, access point → wireless controller, asset →
	// group. The type an adoption record or an uplink produces.
	MemberOf Type = "member_of"
	// Contains — virtual network → subnet, cluster → node.
	Contains Type = "contains"
	// Manages — controller → access point, orchestrator → node.
	Manages Type = "manages"
	// SendsDataTo — application → application, declared data flows.
	SendsDataTo Type = "sends_data_to"
	// Impacts — any → business service. Declared, or derived by the impact
	// traversal (ADR-0003 D5); never measured by a collector.
	Impacts Type = "impacts"
)

// reverseLabels is the reverse-direction label of each type — what the edge
// reads as from the other end. It is a display label, not a second type: an
// edge is never stored in this direction.
var reverseLabels = map[Type]string{
	RunsOn:        "runs",
	HostedOn:      "hosts",
	VirtualizedBy: "virtualizes",
	DependsOn:     "used_by",
	ConnectsTo:    "connected_from",
	MemberOf:      "members",
	Contains:      "contained_by",
	Manages:       "managed_by",
	SendsDataTo:   "receives_data_from",
	Impacts:       "impacted_by",
}

// canonical is the vocabulary in ADR-0003 D2 table order.
var canonical = []Type{
	RunsOn, HostedOn, VirtualizedBy, DependsOn, ConnectsTo,
	MemberOf, Contains, Manages, SendsDataTo, Impacts,
}

// All returns the ten canonical types in ADR-0003 D2 order. The slice is a
// copy; mutating it changes nothing.
func All() []Type {
	out := make([]Type, len(canonical))
	copy(out, canonical)
	return out
}

// Strings returns the vocabulary as sorted strings, for a producer that has to
// hand the list to something untyped (an API enum, a test, a SQL IN list).
func Strings() []string {
	out := make([]string, 0, len(canonical))
	for _, t := range canonical {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}

// Valid reports whether t is one of the ten canonical types.
//
// This is the enforcement point a producer calls before writing an edge. An
// unknown type is not a new kind of edge — it is a producer and a consumer
// disagreeing about the vocabulary, which is how one column ends up meaning
// two things.
func (t Type) Valid() bool {
	_, ok := reverseLabels[t]
	return ok
}

// Reverse returns the label the edge reads as from the to-asset's side, or ""
// for an unknown type.
func (t Type) Reverse() string {
	return reverseLabels[t]
}

// Measurable reports whether a collector may ever emit this type as a MEASURED
// observation.
//
// Two cannot be. `impacts` is derived by the impact traversal or declared by a
// user (ADR-0003 D5): a collector emitting one would be asserting a business
// consequence it has no way to observe. `sends_data_to` is a declared data
// flow, and a collector that believes it measured one has mistaken a
// configured destination for an actual flow.
//
// `depends_on` IS measurable — ADR-0004 D1 (5) has an F5 virtual server's pool
// membership producing one — but a dependency inferred from the *pattern* of
// observed flows is inferred, not measured, and enters as a proposal
// (ADR-0003 D3). This predicate bounds the vocabulary, not the provenance.
func (t Type) Measurable() bool {
	switch t {
	case Impacts, SendsDataTo:
		return false
	default:
		return t.Valid()
	}
}

// ImpactDirection says which way along a type's canonical direction the
// DOWNSTREAM impact walk ("what breaks if this asset dies") travels.
//
// It is per type, and it has to be — see [impactDirections].
type ImpactDirection string

const (
	// ImpactReverse — the edge points from the DEPENDENT to the thing it rests
	// on, so the downstream walk follows it BACKWARDS: from the to-end to the
	// from-end. An application `runs_on` a server; take the server down and the
	// application goes with it.
	ImpactReverse ImpactDirection = "reverse"
	// ImpactForward — the edge points from the CONTAINER or MANAGER to the
	// thing contained or managed, so the downstream walk follows it FORWARDS:
	// from the from-end to the to-end. A virtual network `contains` a subnet;
	// delete the network and the subnet goes with it.
	ImpactForward ImpactDirection = "forward"
)

// impactDirections is the vocabulary the impact traversal walks and the
// direction it walks each type (ADR-0003 D5, as amended.
//
// D5 originally specified ONE uniform rule — every impact-bearing type walked
// in reverse — and that is wrong for two of them, because the vocabulary is not
// uniformly oriented. Six types point dependent → depended-upon, so reverse is
// right. `contains` and `manages` point the other way, container → contained
// and manager → managed, so a uniform reverse walk inverts them: asking "what
// breaks if this wireless controller dies" returned NOTHING while asking it of
// an access point returned the controller. That is the ops persona's headline
// question (ADR-0006) answered backwards.
//
// One type is still excluded entirely. `connects_to` is an OBSERVED FLOW, not a
// dependency: two hosts that exchanged packets tell you nothing about whether
// one stops working when the other does, and because it is the highest-volume
// measured type by a wide margin (every external connection upserts one),
// including it would make the closure of almost any node the whole tenant. An
// impact answer that names everything is the same as no answer.
//
// UPSTREAM is the exact mirror: every direction here flips. That is a property
// the tests assert rather than a second table to maintain.
var impactDirections = map[Type]ImpactDirection{
	// Dependent → depended-upon.
	RunsOn:        ImpactReverse,
	HostedOn:      ImpactReverse,
	VirtualizedBy: ImpactReverse,
	DependsOn:     ImpactReverse,
	MemberOf:      ImpactReverse,
	SendsDataTo:   ImpactReverse,
	// Container → contained, manager → managed.
	Contains: ImpactForward,
	Manages:  ImpactForward,
	// Asset → business service. Forward for the same reason: the service is
	// what is affected when the asset it depends on changes.
	Impacts: ImpactForward,
}

// impactTerminal is the set of types the walk may cross ONCE and not continue
// past.
//
// Only `impacts`. It names a BUSINESS SERVICE, which is the end of the sentence
// a blast-radius answer is trying to finish: "taking this down affects the
// payroll service". Continuing through it would walk whatever else that service
// happens to touch and turn a specific answer into a vague one. It is also what
// the traversal DERIVES for the cache (D5), so following a derived edge back
// into the computation that fills it would let a stale one perpetuate itself —
// crossing it once, as a user's own assertion, does not.
var impactTerminal = map[Type]bool{Impacts: true}

// ImpactBearing reports whether the impact traversal follows this type.
func (t Type) ImpactBearing() bool {
	_, ok := impactDirections[t]
	return ok
}

// ImpactDirectionOf returns the direction the DOWNSTREAM walk follows this type
// in, and whether the type is impact-bearing at all.
func (t Type) ImpactDirectionOf() (ImpactDirection, bool) {
	d, ok := impactDirections[t]
	return d, ok
}

// ImpactTerminal reports whether the walk stops at the far end of this type
// rather than continuing through it.
func (t Type) ImpactTerminal() bool { return impactTerminal[t] }

// ImpactBearingStrings returns the impact-bearing vocabulary as sorted strings,
// for the API to echo so a caller can see which edges an impact answer was
// computed over.
//
// Echoed rather than assumed: "what depends on this" over nine types and over
// ten are different questions, and a consumer that cannot see which was asked
// will eventually quote one as the other.
func ImpactBearingStrings() []string {
	return impactStrings(func(Type) bool { return true })
}

// ImpactReverseStrings and ImpactForwardStrings are the two halves the
// recursive CTE filters its join arms on, as sorted SQL-ready strings.
//
// The DOWNSTREAM walk passes them as (reverse, forward); the UPSTREAM walk
// passes them swapped, and that swap is the whole of what "upstream is the
// mirror" means in code. Two calls rather than one direction-aware helper,
// because the swap is then visible at the call site instead of buried in a
// branch nobody re-reads.
func ImpactReverseStrings() []string {
	return impactStrings(func(t Type) bool { return impactDirections[t] == ImpactReverse })
}

// ImpactForwardStrings — see [ImpactReverseStrings].
func ImpactForwardStrings() []string {
	return impactStrings(func(t Type) bool { return impactDirections[t] == ImpactForward })
}

// ImpactTerminalStrings is the terminal set, for the same SQL.
func ImpactTerminalStrings() []string {
	return impactStrings(func(t Type) bool { return impactTerminal[t] })
}

func impactStrings(keep func(Type) bool) []string {
	out := make([]string, 0, len(impactDirections))
	for _, t := range canonical {
		if _, ok := impactDirections[t]; ok && keep(t) {
			out = append(out, string(t))
		}
	}
	sort.Strings(out)
	return out
}
