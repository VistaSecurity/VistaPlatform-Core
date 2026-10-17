package cablepath

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// ids hands out stable, readable uuids per name so a failing test prints the
// hop by name.
type ids map[string]uuid.UUID

func (m ids) id(name string) uuid.UUID {
	if v, ok := m[name]; ok {
		return v
	}
	v := uuid.NewSHA1(uuid.NameSpaceOID, []byte(name))
	m[name] = v
	return v
}

func (m ids) name(id uuid.UUID) string {
	for k, v := range m {
		if v == id {
			return k
		}
	}
	return id.String()
}

func (m ids) iface(n string) Node { return N(dcim.ObjectKindInterface, m.id(n)) }
func (m ids) front(n string) Node { return N(dcim.ObjectKindFrontPort, m.id(n)) }
func (m ids) rear(n string) Node  { return N(dcim.ObjectKindRearPort, m.id(n)) }
func (m ids) ct(n string) Node    { return N(dcim.ObjectKindCircuitTermination, m.id(n)) }
func (m ids) cable(n string) Node { return N(KindCable, m.id(n)) }

// render prints a path as "I1 | C1 | F1 | R1 ..." with groups joined by '+'.
func (m ids) render(p *Path) string {
	var gs []string
	for _, g := range p.Nodes {
		var ns []string
		for _, n := range g {
			ns = append(ns, m.name(n.ID))
		}
		gs = append(gs, strings.Join(ns, "+"))
	}
	return strings.Join(gs, " | ")
}

type want struct {
	path                         string
	dest                         string
	complete, active, split, cut bool
}

func check(t *testing.T, m ids, g Graph, origin Node, w want) {
	t.Helper()
	p, err := Walk(context.Background(), g, origin)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatalf("no path from %s", m.name(origin.ID))
	}
	if got := m.render(p); w.path != "" && got != w.path {
		t.Errorf("path\n got %s\nwant %s", got, w.path)
	}
	dest := ""
	if d := p.Destination(); d != nil {
		dest = m.name(d.ID)
	}
	if dest != w.dest {
		t.Errorf("destination %q, want %q", dest, w.dest)
	}
	if p.IsComplete != w.complete || p.IsActive != w.active || p.IsSplit != w.split || p.Truncated != w.cut {
		t.Errorf("complete/active/split/truncated = %v/%v/%v/%v, want %v/%v/%v/%v",
			p.IsComplete, p.IsActive, p.IsSplit, p.Truncated, w.complete, w.active, w.split, w.cut)
	}
}

func TestWalk_DirectInterfaceToInterface(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.iface("I2")})
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | I2", dest: "I2", complete: true, active: true})
	check(t, m, g, m.iface("I2"), want{path: "I2 | C1 | I1", dest: "I1", complete: true, active: true})
}

func TestWalk_PlannedCableIsInactive(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.AddCable(m.id("C1"), "planned", []Node{m.iface("I1")}, []Node{m.iface("I2")})
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | I2", dest: "I2", complete: true, active: false})
}

func TestWalk_UncabledOriginHasNoPath(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	p, err := Walk(context.Background(), g, m.iface("I1"))
	if err != nil || p != nil {
		t.Fatalf("an uncabled origin has no path: got %v, %v", p, err)
	}
}

// I1 -C1- F1 (panel 1) ~ R1 -C2- R2 ~ F2 (panel 2) -C3- I2.
func TestWalk_ThroughPatchPanels(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.AddFrontPort(m.id("F1"), m.id("R1"), 1)
	g.AddFrontPort(m.id("F2"), m.id("R2"), 1)
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.front("F1")})
	g.AddCable(m.id("C2"), "connected", []Node{m.rear("R1")}, []Node{m.rear("R2")})
	g.AddCable(m.id("C3"), "connected", []Node{m.front("F2")}, []Node{m.iface("I2")})
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | F1 | R1 | C2 | R2 | F2 | C3 | I2", dest: "I2", complete: true, active: true})
	check(t, m, g, m.iface("I2"), want{path: "I2 | C3 | F2 | R2 | C2 | R1 | F1 | C1 | I1", dest: "I1", complete: true, active: true})
}

// A two-strand trunk: each front port's position survives the rear-to-rear
// cable, so strand 2 on one panel lands on strand 2 of the other.
func TestWalk_MultiPositionTrunkPreservesPosition(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	for _, p := range []string{"1", "2"} {
		g.SetPositions(m.id("R"+p), 2)
		g.AddFrontPort(m.id("F"+p+"a"), m.id("R"+p), 1)
		g.AddFrontPort(m.id("F"+p+"b"), m.id("R"+p), 2)
	}
	g.AddCable(m.id("T"), "connected", []Node{m.rear("R1")}, []Node{m.rear("R2")})
	g.AddCable(m.id("Ca1"), "connected", []Node{m.iface("Ia1")}, []Node{m.front("F1a")})
	g.AddCable(m.id("Ca2"), "connected", []Node{m.front("F2a")}, []Node{m.iface("Ia2")})
	g.AddCable(m.id("Cb1"), "connected", []Node{m.iface("Ib1")}, []Node{m.front("F1b")})
	g.AddCable(m.id("Cb2"), "connected", []Node{m.front("F2b")}, []Node{m.iface("Ib2")})
	check(t, m, g, m.iface("Ia1"), want{path: "Ia1 | Ca1 | F1a | R1 | T | R2 | F2a | Ca2 | Ia2", dest: "Ia2", complete: true, active: true})
	check(t, m, g, m.iface("Ib1"), want{path: "Ib1 | Cb1 | F1b | R1 | T | R2 | F2b | Cb2 | Ib2", dest: "Ib2", complete: true, active: true})
}

// I1 -C1- CT-A ==circuit== CT-Z -C2- I2.
func TestWalk_ThroughCircuit(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.AddCircuit(m.id("CTA"), m.id("CTZ"), nil)
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.ct("CTA")})
	g.AddCable(m.id("C2"), "connected", []Node{m.ct("CTZ")}, []Node{m.iface("I2")})
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | CTA | CTZ | C2 | I2", dest: "I2", complete: true, active: true})
	check(t, m, g, m.iface("I2"), want{path: "I2 | C2 | CTZ | CTA | C1 | I1", dest: "I1", complete: true, active: true})
}

func TestWalk_CircuitToProviderNetworkCompletes(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	pn := m.id("PN")
	g.AddCircuit(m.id("CTA"), m.id("CTZ"), &pn)
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.ct("CTA")})
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | CTA | CTZ | PN", dest: "PN", complete: true, active: true})
}

func TestWalk_CircuitWithUncabledFarSideIsIncomplete(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.AddCircuit(m.id("CTA"), m.id("CTZ"), nil)
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.ct("CTA")})
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | CTA | CTZ", active: true})
}

// A cable onto a multi-position rear port, with no front port before it to
// say which position: the path cannot continue and is split.
func TestWalk_SplitAtMultiPositionRearPort(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.SetPositions(m.id("R1"), 4)
	g.AddFrontPort(m.id("F1"), m.id("R1"), 1)
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.rear("R1")})
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | R1", active: true, split: true})
}

func TestWalk_SplitAtSeveralCircuitTerminations(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.AddCircuit(m.id("CT1"), m.id("CT1Z"), nil)
	g.AddCircuit(m.id("CT2"), m.id("CT2Z"), nil)
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.ct("CT1"), m.ct("CT2")})
	p, err := Walk(context.Background(), g, m.iface("I1"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsSplit || p.IsComplete {
		t.Fatalf("several far-end circuit terminations must split the path: %+v", p)
	}
}

// A cable whose far end has nothing on it (a cable laid to nowhere yet).
func TestWalk_DanglingEnd(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.AddCable(m.id("C1"), "planned", []Node{m.iface("I1")}, nil)
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | ", active: false})
}

// A patch panel whose rear port is not cabled: the path ends at the rear port.
func TestWalk_EndsAtUncabledRearPort(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.AddFrontPort(m.id("F1"), m.id("R1"), 1)
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.front("F1")})
	check(t, m, g, m.iface("I1"), want{path: "I1 | C1 | F1 | R1", active: true})
}

// A two-position panel with its rear cabled to its own front: every turn
// pushes a position and comes back, forever. The cap ends it, incomplete.
func TestWalk_CycleStopsAtDepthCap(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	g.SetPositions(m.id("R1"), 2)
	g.AddFrontPort(m.id("F1a"), m.id("R1"), 1)
	g.AddFrontPort(m.id("F1b"), m.id("R1"), 2)
	g.AddCable(m.id("C1"), "connected", []Node{m.iface("I1")}, []Node{m.front("F1a")})
	g.AddCable(m.id("Loop"), "connected", []Node{m.rear("R1")}, []Node{m.front("F1b")})
	p, err := Walk(context.Background(), g, m.iface("I1"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Truncated || p.IsComplete {
		t.Fatalf("a loop must stop at the cap, incomplete: truncated=%v complete=%v", p.Truncated, p.IsComplete)
	}
	cables := 0
	for _, grp := range p.Nodes {
		if grp[0].Kind == KindCable {
			cables++
		}
	}
	if cables != MaxHops {
		t.Fatalf("crossed %d cables, want the cap %d", cables, MaxHops)
	}
}

// A long but legal chain under the cap completes.
func TestWalk_LongChainUnderCapCompletes(t *testing.T) {
	m, g := ids{}, NewMemGraph()
	prev := m.iface("I1")
	const panels = 20
	for i := 0; i < panels; i++ {
		f, r := m.front("F"+string(rune('A'+i))), m.rear("R"+string(rune('A'+i)))
		g.AddFrontPort(f.ID, r.ID, 1)
		if i%2 == 0 {
			g.AddCable(uuid.New(), "connected", []Node{prev}, []Node{f})
			prev = r
		} else {
			g.AddCable(uuid.New(), "connected", []Node{prev}, []Node{r})
			prev = f
		}
	}
	g.AddCable(uuid.New(), "connected", []Node{prev}, []Node{m.iface("I2")})
	p, err := Walk(context.Background(), g, m.iface("I1"))
	if err != nil || !p.IsComplete || p.Destination().ID != m.id("I2") {
		t.Fatalf("a 21-cable chain should complete at I2: %+v, %v", p, err)
	}
}

func TestNode_JSONIsKindIDPair(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	b, err := json.Marshal([][]Node{{N(dcim.ObjectKindInterface, id)}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `[[["interface","11111111-2222-3333-4444-555555555555"]]]` {
		t.Fatalf("path JSON %s", b)
	}
	var back [][]Node
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, [][]Node{{N(dcim.ObjectKindInterface, id)}}) {
		t.Fatalf("round trip: %v %v", back, err)
	}
}

func TestSegments_GroupsTriples(t *testing.T) {
	m := ids{}
	nodes := [][]Node{{m.iface("I1")}, {m.cable("C1")}, {m.front("F1")}, {m.rear("R1")}}
	s := Segments(nodes)
	if len(s) != 2 || len(s[0].Cable) != 1 || len(s[1].Near) != 1 || s[1].Cable != nil {
		t.Fatalf("segments %+v", s)
	}
}

func TestIsOrigin(t *testing.T) {
	for k, want := range map[dcim.ObjectKind]bool{
		dcim.ObjectKindInterface: true, dcim.ObjectKindConsolePort: true, dcim.ObjectKindCircuitTermination: true,
		dcim.ObjectKindFrontPort: false, dcim.ObjectKindRearPort: false, dcim.ObjectKindAsset: false,
	} {
		if IsOrigin(k) != want {
			t.Errorf("IsOrigin(%s) = %v", k, !want)
		}
	}
}
