// Package cablepath computes cable paths (asset-inventory ADR-0010 D6; DCIM
// DATA_MODEL §4 `cable_paths`; BUILD_PLAN row 3.2).
//
// A path starts at an origin (an interface, console port, console server
// port, power port, power outlet or circuit termination) and follows NetBox's
// cable-path algorithm (dcim/models/cables.py CablePath.from_origin):
//
//   - From the near-end termination(s), follow their cable(s) to the far-end
//     terminations.
//   - A far-end FRONT port continues through its rear port; when the rear port
//     has more than one position (or the far end is several front ports on
//     several rear ports) the front ports' positions are pushed on a stack.
//   - A far-end REAR port continues through its front port(s): a one-position
//     rear port to the front port at position 1; otherwise the positions popped
//     off the stack select the front port(s). A multi-position rear port with
//     nothing on the stack is a split: the path cannot say which strand it
//     takes, so it stops there with IsSplit.
//   - A far-end CIRCUIT termination continues to the circuit's other side. A
//     peer on a provider network completes the path there; a peer with no
//     cable ends it; several far-end circuit terminations are a split.
//   - Any other far end (an interface, console or power endpoint) completes
//     the path: that is the destination.
//   - No cable on the near end ends the path (and an origin with no cable has
//     no path at all).
//
// IsActive is false as soon as any cable on the path is not `connected`. A
// near-end group where only some terminations are cabled is asymmetric: the
// path is marked split and incomplete (NetBox step 3).
//
// The walk is capped at MaxHops segments (DATA_MODEL §4: 64), which is also
// the cycle guard: a loop through patch panels ends at the cap, incomplete.
//
// The walker is pure: it reads the topology through Graph, so the same code
// runs over Postgres (PGGraph, in the service's transaction) and over an
// in-memory topology (MemGraph: the table tests and the scale fixture).
package cablepath

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// MaxHops caps the number of cable segments a path may cross (DATA_MODEL §4).
const MaxHops = 64

// KindCable is the node kind of a cable in a path.
const KindCable = dcim.ObjectKindCable

// Node is one object on a path. It marshals as [kind, id], the hop shape
// cable_paths.path stores.
type Node struct {
	Kind dcim.ObjectKind
	ID   uuid.UUID
}

// N is shorthand for a Node.
func N(kind dcim.ObjectKind, id uuid.UUID) Node { return Node{Kind: kind, ID: id} }

func (n Node) String() string { return string(n.Kind) + ":" + n.ID.String() }

// MarshalJSON writes [kind, id].
func (n Node) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]string{string(n.Kind), n.ID.String()})
}

// UnmarshalJSON reads [kind, id].
func (n *Node) UnmarshalJSON(b []byte) error {
	var pair [2]string
	if err := json.Unmarshal(b, &pair); err != nil {
		return err
	}
	id, err := uuid.Parse(pair[1])
	if err != nil {
		return fmt.Errorf("cablepath: node id: %w", err)
	}
	n.Kind, n.ID = dcim.ObjectKind(pair[0]), id
	return nil
}

// TerminationKinds are the object kinds a cable may terminate on (DATA_MODEL
// §4; the keys of the compatibility matrix).
var TerminationKinds = []dcim.ObjectKind{
	dcim.ObjectKindInterface, dcim.ObjectKindFrontPort, dcim.ObjectKindRearPort, dcim.ObjectKindConsolePort,
	dcim.ObjectKindConsoleServerPort, dcim.ObjectKindCircuitTermination, dcim.ObjectKindPowerPort,
	dcim.ObjectKindPowerOutlet,
}

// IsTermination reports whether k is a cable termination kind.
func IsTermination(k dcim.ObjectKind) bool {
	for _, t := range TerminationKinds {
		if t == k {
			return true
		}
	}
	return false
}

// IsOrigin reports whether a path is computed (and cached) from objects of
// kind k: every termination kind except the pass-through front and rear
// ports, whose trace is the set of paths running through them.
func IsOrigin(k dcim.ObjectKind) bool {
	return IsTermination(k) && k != dcim.ObjectKindFrontPort && k != dcim.ObjectKindRearPort
}

// Cable is a cable as the walker sees it.
type Cable struct {
	ID uuid.UUID
	// Status is cables.operational_status.
	Status string
}

// Link is the cable a termination is on and which end of it.
type Link struct {
	Cable Cable
	End   string // "A" or "B"
}

// Peer is the other side of a circuit.
type Peer struct {
	ID uuid.UUID
	// Cabled: the peer termination is on a cable.
	Cabled bool
	// ProviderNetwork is set when the peer lands on a provider network (the
	// path completes there).
	ProviderNetwork *uuid.UUID
}

// Graph is the topology the walker reads. Every method answers for the
// tenant the implementation is scoped to.
type Graph interface {
	// Cable returns a cable.
	Cable(ctx context.Context, id uuid.UUID) (Cable, error)
	// FarEnd returns the cable n is on, the end n is on, and the terminations
	// on the cable's other end (empty for a cable with a dangling far end).
	// ok is false when n is on no cable.
	FarEnd(ctx context.Context, n Node) (link Link, far []Node, ok bool, err error)
	// RearPort returns the rear port a front port maps to and its position.
	// ok is false when the front port does not exist.
	RearPort(ctx context.Context, frontID uuid.UUID) (rearID uuid.UUID, position int, ok bool, err error)
	// Positions returns a rear port's number of positions.
	Positions(ctx context.Context, rearID uuid.UUID) (int, error)
	// FrontPorts returns the front ports mapped to rearID at position.
	FrontPorts(ctx context.Context, rearID uuid.UUID, position int) ([]uuid.UUID, error)
	// CircuitPeer returns the termination on the circuit's other side. ok is
	// false when the circuit has no other side.
	CircuitPeer(ctx context.Context, termID uuid.UUID) (peer Peer, ok bool, err error)
}

// Path is one computed path.
type Path struct {
	Origin Node
	// Nodes are the hops, grouped: a group of near-end terminations, then
	// the group of cables, then the group of far-end terminations, and so on
	// (NetBox's _nodes). Every group holds one kind.
	Nodes [][]Node
	// Destinations are the far endpoints of a complete path.
	Destinations []Node
	IsComplete   bool
	IsActive     bool
	IsSplit      bool
	// Truncated: the walk hit MaxHops (a loop, or an absurd chain).
	Truncated bool
}

// Destination is the first destination, or nil.
func (p *Path) Destination() *Node {
	if len(p.Destinations) == 0 {
		return nil
	}
	return &p.Destinations[0]
}

// Contains reports whether n is a hop of the path.
func (p *Path) Contains(n Node) bool {
	for _, g := range p.Nodes {
		for _, x := range g {
			if x == n {
				return true
			}
		}
	}
	return false
}

// Segment is one cable crossing of a path as the trace presents it.
type Segment struct {
	Near  []Node `json:"near_end"`
	Cable []Node `json:"cables"`
	Far   []Node `json:"far_end"`
}

// Segments groups Nodes into (near, cables, far) triples. A trailing group
// with no cable (a path ending at an uncabled pass-through port, or a
// circuit's far side) is a segment with only a near end.
func Segments(nodes [][]Node) []Segment {
	var out []Segment
	for i := 0; i < len(nodes); i += 3 {
		s := Segment{Near: nodes[i]}
		if i+1 < len(nodes) {
			s.Cable = nodes[i+1]
		}
		if i+2 < len(nodes) {
			s.Far = nodes[i+2]
		}
		out = append(out, s)
	}
	return out
}

// Walk computes the path from origin. It returns nil, nil when origin is on
// no cable (NetBox: no path).
func Walk(ctx context.Context, g Graph, origin Node) (*Path, error) {
	p := &Path{Origin: origin, IsActive: true, IsComplete: false}
	terms := []Node{origin}
	var stack [][]int
	for hops := 0; len(terms) > 0; hops++ {
		if hops >= MaxHops {
			p.Truncated = true
			p.IsComplete = false
			break
		}
		// Step 1: the near end.
		p.Nodes = append(p.Nodes, terms)

		// Step 2: the cables on it.
		var cables []Cable
		var far []Node
		seenCable := map[uuid.UUID]bool{}
		seenFar := map[Node]bool{}
		unlinked := 0
		for _, t := range terms {
			link, f, ok, err := g.FarEnd(ctx, t)
			if err != nil {
				return nil, err
			}
			if !ok {
				unlinked++
				continue
			}
			if !seenCable[link.Cable.ID] {
				seenCable[link.Cable.ID] = true
				c, err := g.Cable(ctx, link.Cable.ID)
				if err != nil {
					return nil, err
				}
				cables = append(cables, c)
			}
			for _, n := range f {
				if !seenFar[n] {
					seenFar[n] = true
					far = append(far, n)
				}
			}
		}
		if len(cables) == 0 {
			if len(p.Nodes) == 1 {
				return nil, nil // the origin is not cabled: no path
			}
			break // the path ends at an uncabled port
		}
		// Step 3: an asymmetric near end (some terminations uncabled).
		if unlinked > 0 {
			p.IsComplete = false
			p.IsSplit = true
		}
		// Steps 4-5: the cables, and whether all are connected.
		cg := make([]Node, 0, len(cables))
		for _, c := range cables {
			cg = append(cg, N(KindCable, c.ID))
			if c.Status != "connected" {
				p.IsActive = false
			}
		}
		p.Nodes = append(p.Nodes, cg)

		// Steps 6-7: the far end.
		sortNodes(far)
		p.Nodes = append(p.Nodes, far)
		if len(far) == 0 {
			break // a dangling cable
		}

		// Step 8: the next hop.
		switch far[0].Kind {
		case dcim.ObjectKindFrontPort:
			var rears []Node
			seen := map[uuid.UUID]bool{}
			var positions []int
			multi := false
			for _, fp := range far {
				rear, pos, ok, err := g.RearPort(ctx, fp.ID)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
				positions = append(positions, pos)
				if !seen[rear] {
					seen[rear] = true
					rears = append(rears, N(dcim.ObjectKindRearPort, rear))
					n, err := g.Positions(ctx, rear)
					if err != nil {
						return nil, err
					}
					if n > 1 {
						multi = true
					}
				}
			}
			if len(rears) > 1 || multi {
				stack = append(stack, positions)
			}
			sortNodes(rears)
			terms = rears

		case dcim.ObjectKindRearPort:
			var fronts []Node
			single := false
			if len(far) == 1 {
				n, err := g.Positions(ctx, far[0].ID)
				if err != nil {
					return nil, err
				}
				single = n == 1
			}
			var positions []int
			switch {
			case single:
				positions = []int{1}
			case len(stack) > 0:
				positions = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			default:
				// No position to follow: the path splits here.
				p.IsSplit = true
				p.IsComplete = false
				return finish(p), nil
			}
			for _, r := range far {
				for _, pos := range positions {
					ids, err := g.FrontPorts(ctx, r.ID, pos)
					if err != nil {
						return nil, err
					}
					for _, id := range ids {
						fronts = append(fronts, N(dcim.ObjectKindFrontPort, id))
					}
				}
			}
			sortNodes(fronts)
			terms = fronts

		case dcim.ObjectKindCircuitTermination:
			if len(far) > 1 {
				p.IsSplit = true
				p.IsComplete = false
				return finish(p), nil
			}
			peer, ok, err := g.CircuitPeer(ctx, far[0].ID)
			if err != nil {
				return nil, err
			}
			if !ok {
				terms = nil
				break
			}
			peerNode := N(dcim.ObjectKindCircuitTermination, peer.ID)
			if peer.ProviderNetwork != nil && !peer.Cabled {
				pn := N(dcim.ObjectKindProviderNetwork, *peer.ProviderNetwork)
				p.Nodes = append(p.Nodes, []Node{peerNode}, []Node{pn})
				p.IsComplete = true
				p.Destinations = []Node{pn}
				return finish(p), nil
			}
			if !peer.Cabled {
				p.Nodes = append(p.Nodes, []Node{peerNode})
				return finish(p), nil
			}
			terms = []Node{peerNode}

		default:
			// An endpoint: the path is complete.
			p.IsComplete = true
			p.Destinations = far
			return finish(p), nil
		}
	}
	return finish(p), nil
}

// finish clears what an incomplete path must not claim.
func finish(p *Path) *Path {
	if !p.IsComplete {
		p.Destinations = nil
	}
	return p
}

func sortNodes(ns []Node) {
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].Kind != ns[j].Kind {
			return ns[i].Kind < ns[j].Kind
		}
		return ns[i].ID.String() < ns[j].ID.String()
	})
}
