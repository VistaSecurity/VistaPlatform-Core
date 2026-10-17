package cablepath

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// MemGraph is an in-memory Graph: the walker's table tests and the scale
// fixture (shared/testdb/dcimfixture), which computes 100,000 cables' paths
// without a query per hop. Build it with AddCable, AddFrontPort, SetPositions
// and AddCircuit.
type MemGraph struct {
	cables    map[uuid.UUID]Cable
	ends      map[Node]Link
	members   map[uuid.UUID]map[string][]Node // cable -> end -> terminations
	front     map[uuid.UUID]frontMap
	positions map[uuid.UUID]int
	byRear    map[uuid.UUID]map[int][]uuid.UUID
	circuits  map[uuid.UUID]memPeer
}

type frontMap struct {
	rear uuid.UUID
	pos  int
}

type memPeer struct {
	peer            uuid.UUID
	providerNetwork *uuid.UUID
}

// NewMemGraph returns an empty graph.
func NewMemGraph() *MemGraph {
	return &MemGraph{
		cables: map[uuid.UUID]Cable{}, ends: map[Node]Link{}, members: map[uuid.UUID]map[string][]Node{},
		front: map[uuid.UUID]frontMap{}, positions: map[uuid.UUID]int{}, byRear: map[uuid.UUID]map[int][]uuid.UUID{},
		circuits: map[uuid.UUID]memPeer{},
	}
}

// AddCable adds a cable with its A and B terminations. It panics on a
// termination already on a cable (the unique index's rule), so a broken
// fixture fails loudly.
func (g *MemGraph) AddCable(id uuid.UUID, status string, a, b []Node) {
	c := Cable{ID: id, Status: status}
	g.cables[id] = c
	g.members[id] = map[string][]Node{"A": a, "B": b}
	for end, ns := range map[string][]Node{"A": a, "B": b} {
		for _, n := range ns {
			if _, dup := g.ends[n]; dup {
				panic(fmt.Sprintf("cablepath: %s is already on a cable", n))
			}
			g.ends[n] = Link{Cable: c, End: end}
		}
	}
}

// RemoveCable deletes a cable and frees its terminations.
func (g *MemGraph) RemoveCable(id uuid.UUID) {
	for _, ns := range g.members[id] {
		for _, n := range ns {
			delete(g.ends, n)
		}
	}
	delete(g.members, id)
	delete(g.cables, id)
}

// SetPositions declares a rear port and its number of positions.
func (g *MemGraph) SetPositions(rear uuid.UUID, positions int) { g.positions[rear] = positions }

// AddFrontPort maps a front port to a rear port position.
func (g *MemGraph) AddFrontPort(front, rear uuid.UUID, position int) {
	g.front[front] = frontMap{rear: rear, pos: position}
	if g.byRear[rear] == nil {
		g.byRear[rear] = map[int][]uuid.UUID{}
	}
	g.byRear[rear][position] = append(g.byRear[rear][position], front)
	if _, ok := g.positions[rear]; !ok {
		g.positions[rear] = 1
	}
}

// AddCircuit joins two circuit terminations (A and Z). Either may be
// uuid.Nil for a circuit with one side; providerNetworkZ marks z as landing on
// a provider network.
func (g *MemGraph) AddCircuit(a, z uuid.UUID, providerNetworkZ *uuid.UUID) {
	if a != uuid.Nil && z != uuid.Nil {
		g.circuits[a] = memPeer{peer: z, providerNetwork: providerNetworkZ}
		g.circuits[z] = memPeer{peer: a}
		return
	}
	if a != uuid.Nil {
		g.circuits[a] = memPeer{}
	}
}

// Cable implements Graph.
func (g *MemGraph) Cable(_ context.Context, id uuid.UUID) (Cable, error) {
	c, ok := g.cables[id]
	if !ok {
		return Cable{}, fmt.Errorf("cablepath: no cable %s", id)
	}
	return c, nil
}

// FarEnd implements Graph.
func (g *MemGraph) FarEnd(_ context.Context, n Node) (Link, []Node, bool, error) {
	l, ok := g.ends[n]
	if !ok {
		return Link{}, nil, false, nil
	}
	other := "B"
	if l.End == "B" {
		other = "A"
	}
	return l, append([]Node(nil), g.members[l.Cable.ID][other]...), true, nil
}

// RearPort implements Graph.
func (g *MemGraph) RearPort(_ context.Context, frontID uuid.UUID) (uuid.UUID, int, bool, error) {
	f, ok := g.front[frontID]
	return f.rear, f.pos, ok, nil
}

// Positions implements Graph.
func (g *MemGraph) Positions(_ context.Context, rearID uuid.UUID) (int, error) {
	if n, ok := g.positions[rearID]; ok {
		return n, nil
	}
	return 1, nil
}

// FrontPorts implements Graph.
func (g *MemGraph) FrontPorts(_ context.Context, rearID uuid.UUID, position int) ([]uuid.UUID, error) {
	return append([]uuid.UUID(nil), g.byRear[rearID][position]...), nil
}

// CircuitPeer implements Graph.
func (g *MemGraph) CircuitPeer(_ context.Context, termID uuid.UUID) (Peer, bool, error) {
	p, ok := g.circuits[termID]
	if !ok || p.peer == uuid.Nil {
		return Peer{}, false, nil
	}
	_, cabled := g.ends[N(dcim.ObjectKindCircuitTermination, p.peer)]
	return Peer{ID: p.peer, Cabled: cabled, ProviderNetwork: p.providerNetwork}, true, nil
}
