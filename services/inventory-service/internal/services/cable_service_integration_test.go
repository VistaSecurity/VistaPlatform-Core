package services

// DB-integration tests for cables, terminations and cable paths (DCIM
// BUILD_PLAN row 3.2). Skipped unless TEST_DATABASE_URL is set; run with
// make test-integration-db. Services run on the NON-OWNER app role, so RLS is
// in force as in production.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type cableFix struct {
	owner, app *sql.DB
	tenant     uuid.UUID
	ctx        context.Context
	cables     *CableService
	comps      *ComponentService
	ifaces     *InterfaceService
	circuits   *CircuitService
}

func newCableFix(t *testing.T) *cableFix {
	t.Helper()
	owner, app, tenant := ifaceFixture(t)
	return &cableFix{owner: owner, app: app, tenant: tenant, ctx: ifaceActorCtx(),
		cables: NewCableService(app), comps: NewComponentService(app), ifaces: NewInterfaceService(app), circuits: NewCircuitService(app)}
}

func (f *cableFix) asset(t *testing.T) uuid.UUID {
	return ifaceSeedAsset(t, f.owner, f.tenant, "monitoring")
}

func (f *cableFix) iface(t *testing.T, asset uuid.UUID, name, typ string) uuid.UUID {
	t.Helper()
	i, err := f.ifaces.Create(f.ctx, f.tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: name, Type: typ})
	if err != nil {
		t.Fatalf("interface %s: %v", name, err)
	}
	return i.ID
}

func (f *cableFix) comp(t *testing.T, route string, body map[string]any) uuid.UUID {
	t.Helper()
	raw, err := f.comps.Create(f.ctx, f.tenant, route, compBody(t, body))
	if err != nil {
		t.Fatalf("create %s %v: %v", route, body, err)
	}
	return uuid.MustParse(fmt.Sprint(compDecode(t, raw)["id"]))
}

// panel declares a one-position patch panel and returns its front and rear.
func (f *cableFix) panel(t *testing.T, asset uuid.UUID) (front, rear uuid.UUID) {
	t.Helper()
	rear = f.comp(t, ComponentRearPort, map[string]any{"asset_id": asset, "name": "Rear1", "type": "lc"})
	front = f.comp(t, ComponentFrontPort, map[string]any{"asset_id": asset, "name": "Front1", "type": "lc", "rear_port_id": rear})
	return front, rear
}

func term(kind dcim.ObjectKind, id uuid.UUID) map[string]any {
	return map[string]any{"termination_kind": string(kind), "termination_id": id.String()}
}

func (f *cableFix) tryCable(a, b map[string]any, extra map[string]any) (map[string]any, error) {
	body := map[string]any{"a_terminations": []any{a}, "b_terminations": []any{b}}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	out, err := f.cables.Create(f.ctx, f.tenant, raw)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (f *cableFix) cable(t *testing.T, a, b map[string]any) uuid.UUID {
	t.Helper()
	m, err := f.tryCable(a, b, map[string]any{"type": "cat6"})
	if err != nil {
		t.Fatalf("cable %v -> %v: %v", a, b, err)
	}
	return uuid.MustParse(fmt.Sprint(m["id"]))
}

func (f *cableFix) trace(t *testing.T, kind dcim.ObjectKind, id uuid.UUID) TraceResult {
	t.Helper()
	r, err := f.cables.Trace(f.ctx, f.tenant, kind, id)
	if err != nil {
		t.Fatalf("trace %s %s: %v", kind, id, err)
	}
	return r
}

func hopNames(p TracePath) string {
	var segs []string
	for _, s := range p.Segments {
		var parts []string
		for _, g := range [][]TraceNode{s.NearEnd, s.Cables, s.FarEnd} {
			var ns []string
			for _, n := range g {
				ns = append(ns, string(n.Kind))
			}
			parts = append(parts, strings.Join(ns, "+"))
		}
		segs = append(segs, strings.Join(parts, " > "))
	}
	return strings.Join(segs, " | ")
}

// Switch Gi1 -> panel A front, panel A rear -> panel B rear, panel B front ->
// server eth0: the trace from either end crosses both panels and lands on the
// other; a pass-through port's trace lists both directions. Deleting the
// trunk cuts both paths at the panels; deleting the first cable removes the
// switch port's path altogether.
//
// Mutation: drop the cablepath.Recompute call from CableService.Delete → the
// switch port still traces, complete, to the server after the trunk is gone,
// and this goes red.
func TestIntegration_Cables_PatchPanelTraceAndRecomputeOnDelete(t *testing.T) {
	f := newCableFix(t)
	sw, pa, pb, srv := f.asset(t), f.asset(t), f.asset(t), f.asset(t)
	gi1 := f.iface(t, sw, "GigabitEthernet1/0/1", "1000base-t")
	eth0 := f.iface(t, srv, "eth0", "1000base-t")
	fa, ra := f.panel(t, pa)
	fb, rb := f.panel(t, pb)

	c1 := f.cable(t, term(dcim.ObjectKindInterface, gi1), term(dcim.ObjectKindFrontPort, fa))
	trunk := f.cable(t, term(dcim.ObjectKindRearPort, ra), term(dcim.ObjectKindRearPort, rb))
	f.cable(t, term(dcim.ObjectKindFrontPort, fb), term(dcim.ObjectKindInterface, eth0))

	tr := f.trace(t, dcim.ObjectKindInterface, gi1)
	if len(tr.Paths) != 1 {
		t.Fatalf("Gi1 has %d paths, want 1", len(tr.Paths))
	}
	p := tr.Paths[0]
	if !p.IsComplete || !p.IsActive || p.IsSplit || p.Destination == nil || p.Destination.ID != eth0 {
		t.Fatalf("Gi1 path: complete=%v active=%v split=%v destination=%+v, want complete+active to eth0", p.IsComplete, p.IsActive, p.IsSplit, p.Destination)
	}
	if want := "interface > cable > front_port | rear_port > cable > rear_port | front_port > cable > interface"; hopNames(p) != want {
		t.Fatalf("hops\n got %s\nwant %s", hopNames(p), want)
	}
	if p.Destination.AssetID == nil || *p.Destination.AssetID != srv || p.Destination.Name != "eth0" {
		t.Fatalf("destination not named: %+v", p.Destination)
	}
	if back := f.trace(t, dcim.ObjectKindInterface, eth0); len(back.Paths) != 1 || back.Paths[0].Destination == nil || back.Paths[0].Destination.ID != gi1 {
		t.Fatalf("eth0 does not trace back to Gi1: %+v", back)
	}
	if through := f.trace(t, dcim.ObjectKindRearPort, ra); len(through.Paths) != 2 {
		t.Fatalf("rear port A carries %d paths, want both directions (2)", len(through.Paths))
	}

	if err := f.cables.Delete(f.ctx, f.tenant, trunk); err != nil {
		t.Fatal(err)
	}
	p = f.trace(t, dcim.ObjectKindInterface, gi1).Paths[0]
	if p.IsComplete || p.Destination != nil {
		t.Fatalf("after the trunk is deleted Gi1 still traces complete to %+v", p.Destination)
	}
	if want := "interface > cable > front_port | rear_port >  > "; hopNames(p) != want {
		t.Fatalf("cut path\n got %q\nwant %q", hopNames(p), want)
	}
	if through := f.trace(t, dcim.ObjectKindRearPort, rb); len(through.Paths) != 1 {
		t.Fatalf("rear port B carries %d paths after the cut, want eth0's only", len(through.Paths))
	}
	var stale int
	probe, _ := json.Marshal([][]any{{[]string{"cable", trunk.String()}}})
	if err := f.owner.QueryRow(`SELECT count(*) FROM cable_paths WHERE tenant_id = $1 AND path @> $2::jsonb`, f.tenant, string(probe)).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("%d stored paths still run over the deleted trunk (%v)", stale, err)
	}

	if err := f.cables.Delete(f.ctx, f.tenant, c1); err != nil {
		t.Fatal(err)
	}
	if tr := f.trace(t, dcim.ObjectKindInterface, gi1); len(tr.Paths) != 0 {
		t.Fatalf("an uncabled interface has %d paths, want none", len(tr.Paths))
	}
	var cid sql.NullString
	if err := f.owner.QueryRow(`SELECT cable_id::text FROM interfaces WHERE id = $1`, gi1).Scan(&cid); err != nil || cid.Valid {
		t.Fatalf("interface cable_id after delete = %v (%v), want NULL", cid, err)
	}
}

// A termination is on one cable only: the service refuses the second cable
// with a conflict, and the unique index refuses a second termination row
// written past the service.
//
// Mutation: drop cable_terminations_termination_uniq from schema.sql → the raw
// insert succeeds and this goes red.
func TestIntegration_Cables_TerminationOnOneCableOnly(t *testing.T) {
	f := newCableFix(t)
	a, b, c := f.asset(t), f.asset(t), f.asset(t)
	ia, ib, ic := f.iface(t, a, "eth0", "1000base-t"), f.iface(t, b, "eth0", "1000base-t"), f.iface(t, c, "eth0", "1000base-t")
	first := f.cable(t, term(dcim.ObjectKindInterface, ia), term(dcim.ObjectKindInterface, ib))
	if _, err := f.tryCable(term(dcim.ObjectKindInterface, ia), term(dcim.ObjectKindInterface, ic), nil); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("a second cable on a cabled interface: %v, want a conflict", err)
	}
	var second uuid.UUID
	if err := f.owner.QueryRow(`INSERT INTO cables (tenant_id) VALUES ($1) RETURNING id`, f.tenant).Scan(&second); err != nil {
		t.Fatal(err)
	}
	_, err := f.owner.Exec(`INSERT INTO cable_terminations (tenant_id, cable_id, cable_end, termination_kind, termination_id) VALUES ($1, $2, 'A', 'interface', $3)`,
		f.tenant, second, ia)
	if err == nil || !strings.Contains(err.Error(), "cable_terminations_termination_uniq") {
		t.Fatalf("a second termination row for one interface: %v, want the unique index to refuse it", err)
	}
	if _, err := f.cables.Get(f.ctx, f.tenant, first); err != nil {
		t.Fatal(err)
	}
}

// The compatibility matrix and the other termination rules.
//
// Mutation: drop the dcim.CableCompatible check from checkEnds → the
// interface-to-console-port cable is accepted and this goes red.
func TestIntegration_Cables_TerminationRules(t *testing.T) {
	f := newCableFix(t)
	a, b := f.asset(t), f.asset(t)
	eth := f.iface(t, a, "eth0", "1000base-t")
	eth1 := f.iface(t, a, "eth1", "1000base-t")
	vlan := f.iface(t, a, "Vlan10", "virtual")
	con := f.comp(t, ComponentConsolePort, map[string]any{"asset_id": b, "name": "con 0", "type": "rj-45"})
	csp := f.comp(t, ComponentConsoleServerPort, map[string]any{"asset_id": a, "name": "port1", "type": "rj-45"})
	marked := f.comp(t, ComponentConsoleServerPort, map[string]any{"asset_id": a, "name": "port2", "type": "rj-45", "mark_connected": true})
	other := f.iface(t, b, "eth0", "1000base-t")

	cases := []struct {
		name string
		a, b []map[string]any
		want error
	}{
		{"interface to console port", []map[string]any{term(dcim.ObjectKindInterface, eth)}, []map[string]any{term(dcim.ObjectKindConsolePort, con)}, ErrIPAMInvalid},
		{"virtual interface", []map[string]any{term(dcim.ObjectKindInterface, vlan)}, []map[string]any{term(dcim.ObjectKindInterface, other)}, ErrIPAMInvalid},
		{"marked connected", []map[string]any{term(dcim.ObjectKindConsoleServerPort, marked)}, []map[string]any{term(dcim.ObjectKindConsolePort, con)}, ErrIPAMInvalid},
		{"mixed kinds on one end", []map[string]any{term(dcim.ObjectKindInterface, eth), term(dcim.ObjectKindConsoleServerPort, csp)}, []map[string]any{term(dcim.ObjectKindInterface, other)}, ErrIPAMInvalid},
		{"empty end", []map[string]any{term(dcim.ObjectKindInterface, eth)}, []map[string]any{}, ErrIPAMInvalid},
		{"unknown power feed", []map[string]any{term(dcim.ObjectKindPowerFeed, uuid.New())}, []map[string]any{term(dcim.ObjectKindInterface, other)}, ErrIPAMInvalid},
		{"unknown termination", []map[string]any{term(dcim.ObjectKindInterface, uuid.New())}, []map[string]any{term(dcim.ObjectKindInterface, other)}, ErrIPAMInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"a_terminations": c.a, "b_terminations": c.b})
			if _, err := f.cables.Create(f.ctx, f.tenant, raw); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM cables WHERE tenant_id = $1`, f.tenant).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused cable left %d rows (%v)", n, err)
	}

	// Allowed: console port to console server port; both ends on one asset.
	f.cable(t, term(dcim.ObjectKindConsoleServerPort, csp), term(dcim.ObjectKindConsolePort, con))
	loop := f.cable(t, term(dcim.ObjectKindInterface, eth), term(dcim.ObjectKindInterface, eth1))
	if p := f.trace(t, dcim.ObjectKindInterface, eth).Paths; len(p) != 1 || p[0].Destination == nil || p[0].Destination.ID != eth1 {
		t.Fatalf("a same-asset cable should trace eth0 to eth1: %+v", p)
	}

	// A cabled termination cannot then be marked connected.
	if _, err := f.comps.Update(f.ctx, f.tenant, ComponentConsoleServerPort, csp, []byte(`{"mark_connected":true}`)); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("marking a cabled console server port connected: %v, want invalid", err)
	}
	if _, err := f.ifaces.Patch(f.ctx, f.tenant, eth, map[string]json.RawMessage{"mark_connected": json.RawMessage(`true`)}); err == nil {
		t.Fatal("marking a cabled interface connected was accepted")
	}
	// Status: a planned cable makes the path inactive.
	if _, err := f.cables.Update(f.ctx, f.tenant, loop, []byte(`{"operational_status":"planned"}`)); err != nil {
		t.Fatal(err)
	}
	if p := f.trace(t, dcim.ObjectKindInterface, eth1).Paths; len(p) != 1 || p[0].IsActive {
		t.Fatalf("a planned cable's path should be inactive: %+v", p)
	}
}

// Replacing an end re-points the path; the change log records the cable and
// each termination.
func TestIntegration_Cables_ReplaceEndAndChanges(t *testing.T) {
	f := newCableFix(t)
	a, b, c := f.asset(t), f.asset(t), f.asset(t)
	ia, ib, ic := f.iface(t, a, "eth0", "1000base-t"), f.iface(t, b, "eth0", "1000base-t"), f.iface(t, c, "eth0", "1000base-t")
	id := f.cable(t, term(dcim.ObjectKindInterface, ia), term(dcim.ObjectKindInterface, ib))
	body, _ := json.Marshal(map[string]any{"b_terminations": []any{term(dcim.ObjectKindInterface, ic)}, "label": "patch-42", "color": "#FF0000", "length": 2.5, "length_unit": "m"})
	raw, err := f.cables.Update(f.ctx, f.tenant, id, body)
	if err != nil {
		t.Fatal(err)
	}
	var cab map[string]any
	_ = json.Unmarshal(raw, &cab)
	if cab["color"] != "ff0000" || cab["label"] != "patch-42" {
		t.Fatalf("cable after patch: %v", cab)
	}
	bt, _ := cab["b_terminations"].([]any)
	if len(bt) != 1 || bt[0].(map[string]any)["termination_id"] != ic.String() || bt[0].(map[string]any)["name"] != "eth0" {
		t.Fatalf("b_terminations after replace: %v", cab["b_terminations"])
	}
	if p := f.trace(t, dcim.ObjectKindInterface, ia).Paths; len(p) != 1 || p[0].Destination.ID != ic {
		t.Fatalf("A end should now trace to the new B: %+v", p)
	}
	if p := f.trace(t, dcim.ObjectKindInterface, ib).Paths; len(p) != 0 {
		t.Fatalf("the detached interface still has %d paths", len(p))
	}
	if _, err := f.cables.Update(f.ctx, f.tenant, id, []byte(`{"length": 3}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cables.Update(f.ctx, f.tenant, id, []byte(`{"length_unit": null}`)); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("a length without a unit: %v, want invalid", err)
	}
	var kinds []string
	rows, err := f.owner.Query(`SELECT object_kind || ':' || action FROM object_changes WHERE tenant_id = $1 AND object_kind IN ('cable','cable_termination') ORDER BY created_at, object_kind`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		kinds = append(kinds, k)
	}
	_ = rows.Close()
	got := strings.Join(kinds, ",")
	for _, want := range []string{"cable:create", "cable_termination:create", "cable:update", "cable_termination:delete"} {
		if !strings.Contains(got, want) {
			t.Fatalf("change log %s lacks %s", got, want)
		}
	}
}

// Deleting a component detaches its cable end and recomputes the far side's
// path; remapping a front port to another rear position moves the path.
func TestIntegration_Cables_ComponentChangesRecompute(t *testing.T) {
	f := newCableFix(t)
	sw, panel, srv := f.asset(t), f.asset(t), f.asset(t)
	gi := f.iface(t, sw, "GigabitEthernet1/0/1", "1000base-t")
	eth := f.iface(t, srv, "eth0", "1000base-t")
	front, rear := f.panel(t, panel)
	f.cable(t, term(dcim.ObjectKindInterface, gi), term(dcim.ObjectKindFrontPort, front))
	if p := f.trace(t, dcim.ObjectKindInterface, gi).Paths[0]; p.IsComplete {
		t.Fatal("a path ending at an uncabled rear port is not complete")
	}
	f.cable(t, term(dcim.ObjectKindRearPort, rear), term(dcim.ObjectKindInterface, eth))
	if p := f.trace(t, dcim.ObjectKindInterface, gi).Paths[0]; !p.IsComplete || p.Destination.ID != eth {
		t.Fatalf("Gi through the panel should reach eth0: %+v", p)
	}
	// A two-position rear port: the front port moves to position 2 and the
	// cable on the rear now lands on... the rear is cabled to an interface, so
	// a single front port on position 2 of a 2-position rear still traces
	// (the front port pushed its position).
	if _, err := f.comps.Update(f.ctx, f.tenant, ComponentRearPort, rear, []byte(`{"positions":2}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.comps.Update(f.ctx, f.tenant, ComponentFrontPort, front, []byte(`{"rear_port_position":2}`)); err != nil {
		t.Fatal(err)
	}
	// eth0 reaches the 2-position rear port with no position to follow: split.
	if p := f.trace(t, dcim.ObjectKindInterface, eth).Paths[0]; !p.IsSplit || p.IsComplete {
		t.Fatalf("eth0 into a 2-position rear port should be split: %+v", p)
	}
	// Delete the server's interface: its cable end goes, Gi's path ends dangling.
	if err := f.ifaces.Delete(f.ctx, f.tenant, eth); err != nil {
		t.Fatal(err)
	}
	if p := f.trace(t, dcim.ObjectKindInterface, gi).Paths[0]; p.IsComplete {
		t.Fatalf("Gi still traces complete after the far interface was deleted: %+v", p.Destination)
	}
	var orphans int
	if err := f.owner.QueryRow(`SELECT count(*) FROM cable_terminations WHERE termination_kind = 'interface' AND termination_id = $1`, eth).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("the deleted interface left %d termination rows (%v)", orphans, err)
	}
	// Delete the rear port: its front port goes by cascade; Gi has no far end.
	if err := f.comps.Delete(f.ctx, f.tenant, ComponentRearPort, rear); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(`SELECT count(*) FROM cable_terminations WHERE tenant_id = $1 AND termination_kind IN ('front_port','rear_port')`, f.tenant).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("the deleted panel left %d termination rows (%v)", orphans, err)
	}
}

// Through a circuit: Gi -> CT A ==circuit== CT Z -> eth0; deleting the Z
// termination cuts the path at A.
func TestIntegration_Cables_ThroughCircuit(t *testing.T) {
	f := newCableFix(t)
	ctx, tenant, svc := f.ctx, f.tenant, f.circuits
	mpls := platformCircuitType(t, ctx, svc, tenant, "mpls")
	prov := mustCreate(t, ctx, svc, tenant, CircuitRouteProviders, `{"name":"Lumen","asns":[3356]}`)
	circ := mustCreate(t, ctx, svc, tenant, CircuitRouteCircuits, fmt.Sprintf(`{"cid":"CKT-7","provider_id":%q,"type_id":%q}`, prov, mpls))
	ctA := mustCreate(t, ctx, svc, tenant, CircuitRouteTerminations, fmt.Sprintf(`{"circuit_id":%q,"term_side":"A"}`, circ))
	ctZ := mustCreate(t, ctx, svc, tenant, CircuitRouteTerminations, fmt.Sprintf(`{"circuit_id":%q,"term_side":"Z"}`, circ))
	a, b := f.asset(t), f.asset(t)
	gi, eth := f.iface(t, a, "GigabitEthernet0/0", "1000base-t"), f.iface(t, b, "eth0", "1000base-t")
	f.cable(t, term(dcim.ObjectKindInterface, gi), term(dcim.ObjectKindCircuitTermination, ctA))
	f.cable(t, term(dcim.ObjectKindCircuitTermination, ctZ), term(dcim.ObjectKindInterface, eth))
	p := f.trace(t, dcim.ObjectKindInterface, gi).Paths[0]
	if !p.IsComplete || p.Destination.ID != eth {
		t.Fatalf("Gi through the circuit should reach eth0: %+v", p)
	}
	if want := "interface > cable > circuit_termination | circuit_termination > cable > interface"; hopNames(p) != want {
		t.Fatalf("hops\n got %s\nwant %s", hopNames(p), want)
	}
	if p.Segments[0].FarEnd[0].Name != "CKT-7 A" {
		t.Fatalf("circuit termination named %q, want CKT-7 A", p.Segments[0].FarEnd[0].Name)
	}
	if tr := f.trace(t, dcim.ObjectKindCircuitTermination, ctZ); len(tr.Paths) != 1 || tr.Paths[0].Destination.ID != eth {
		t.Fatalf("CT Z's own path: %+v", tr.Paths)
	}
	if err := svc.Delete(ctx, tenant, CircuitRouteTerminations, ctZ); err != nil {
		t.Fatal(err)
	}
	if p := f.trace(t, dcim.ObjectKindInterface, gi).Paths[0]; p.IsComplete {
		t.Fatalf("Gi still traces complete after the circuit's Z side was deleted")
	}
}

// A tenant cannot see, trace or cable onto another tenant's objects, and the
// app role cannot write another tenant's rows past the service.
//
// Mutation: drop the cables / cable_terminations / cable_paths
// tenant_isolation policy → a cross-tenant read or insert succeeds.
func TestIntegration_Cables_RLS(t *testing.T) {
	f := newCableFix(t)
	tenantB := testdb.NewTenant(t, f.owner)
	a, b := f.asset(t), f.asset(t)
	ia, ib := f.iface(t, a, "eth0", "1000base-t"), f.iface(t, b, "eth0", "1000base-t")
	id := f.cable(t, term(dcim.ObjectKindInterface, ia), term(dcim.ObjectKindInterface, ib))

	if rows, total, err := f.cables.List(f.ctx, tenantB, IPAMListParams{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B listed %d cables (%v)", total, err)
	}
	if _, err := f.cables.Get(f.ctx, tenantB, id); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B got tenant A's cable: %v", err)
	}
	if _, err := f.cables.Trace(f.ctx, tenantB, dcim.ObjectKindInterface, ia); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B traced tenant A's interface: %v", err)
	}
	bAsset := ifaceSeedAsset(t, f.owner, tenantB, "monitoring")
	bi, err := f.ifaces.Create(f.ctx, tenantB, uuid.Nil, InterfaceInput{AssetID: bAsset, Name: "eth0", Type: "1000base-t"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"a_terminations": []any{term(dcim.ObjectKindInterface, bi.ID)}, "b_terminations": []any{term(dcim.ObjectKindInterface, ia)}})
	if _, err := f.cables.Create(f.ctx, tenantB, raw); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("tenant B cabled onto tenant A's interface: %v", err)
	}
	for _, q := range []string{
		`INSERT INTO cables (tenant_id) VALUES ($1)`,
		`INSERT INTO cable_paths (tenant_id, origin_kind, origin_id) VALUES ($1, 'interface', gen_random_uuid())`,
	} {
		err := func() error {
			tx, err := f.app.Begin()
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.Exec(`SELECT set_config('app.tenant_id', $1, true)`, tenantB.String()); err != nil {
				return err
			}
			_, err = tx.Exec(q, f.tenant)
			return err
		}()
		if err == nil {
			t.Fatalf("the app role scoped to tenant B wrote a row for tenant A: %s", q)
		}
	}
}

// The query language reaches cables (QUERY_LANGUAGE §15.6): cable.type,
// cable.status and cabled_to run against the real tables.
func TestIntegration_Cables_QueryFields(t *testing.T) {
	f := newCableFix(t)
	a, b, c := f.asset(t), f.asset(t), f.asset(t)
	ia, ib := f.iface(t, a, "eth0", "1000base-t"), f.iface(t, b, "eth0", "1000base-t")
	f.iface(t, c, "eth0", "1000base-t")
	if _, err := f.tryCable(term(dcim.ObjectKindInterface, ia), term(dcim.ObjectKindInterface, ib), map[string]any{"type": "smf-os2", "operational_status": "planned"}); err != nil {
		t.Fatal(err)
	}
	var bName string
	if err := f.owner.QueryRow(`SELECT hostname FROM assets WHERE id = $1`, b).Scan(&bName); err != nil {
		t.Fatal(err)
	}
	match := func(q string) map[uuid.UUID]bool {
		t.Helper()
		cq, err := query.Compile(q, "asset", query.DefaultCatalog(), query.DefaultOptionsFor(query.DefaultCatalog()))
		if err != nil {
			t.Fatalf("compile %q: %v", q, err)
		}
		out := map[uuid.UUID]bool{}
		testdb.AsTenant(t, f.owner, f.tenant, func(tx *sql.Tx) {
			rows, err := tx.Query("SELECT a.id FROM assets a WHERE a.tenant_id = '"+f.tenant.String()+"' AND "+cq.Where, cq.Args...)
			if err != nil {
				t.Fatalf("run %q: %v", q, err)
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					t.Fatal(err)
				}
				out[id] = true
			}
		})
		return out
	}
	if got := match(`cable.type = smf-os2`); !got[a] || !got[b] || got[c] || len(got) != 2 {
		t.Errorf("cable.type: %v", got)
	}
	if got := match(`cable.status = planned`); !got[a] || !got[b] || len(got) != 2 {
		t.Errorf("cable.status: %v", got)
	}
	if got := match(`cabled_to = "` + bName + `"`); !got[a] || got[b] || len(got) != 1 {
		t.Errorf("cabled_to %s: %v", bName, got)
	}
	if got := match(`cable.type != smf-os2`); !got[c] || got[a] {
		t.Errorf("cable.type != (row-shaped): %v", got)
	}
}
