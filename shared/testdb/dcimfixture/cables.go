package dcimfixture

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablepath"
)

// The cable populator (DCIM BUILD_PLAN row 3.2): Scale.CablesPerRack cables in
// every rack — §12's 100,000 at Scale1 — with their terminations, the
// components' cable_id/cable_end, and every interface's cached cable path.
//
// Per rack, with L the rack's interfaces in slot then name order and h = |L|/2:
//
//   - cables 1-3 are a patch through two panels: L[0] → Front1 of slot 2's
//     rear port; that rear port → slot 3's rear port (a two-position trunk);
//     slot 3's Front1 → L[h]. The trace from L[0] crosses both panels and the
//     position stack (PatchedInterfaces lists those origins);
//   - every other cable is direct: L[k] ↔ L[h+k].
//
// Paths are computed by the same walker the service runs
// (shared/dcim/cablepath), over an in-memory graph of what is written here,
// and bulk-loaded: 200,000 origins without a query per hop.

// CableLabel is the stable label of the n-th (0-based) cable in a rack.
func CableLabel(site, rack, n int) string { return fmt.Sprintf("C-%04d-%02d-%02d", site, rack, n+1) }

type fixtureEnd struct {
	kind  dcim.ObjectKind
	id    uuid.UUID
	asset uuid.UUID
}

type fixtureCable struct {
	label, typ string
	a, b       fixtureEnd
}

func populateCables(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	per := e.Scale.AssetsPerRack
	if len(e.Interfaces) == 0 || e.Scale.CablesPerRack <= 0 || per == 0 {
		return -1, nil
	}
	ifaces := map[uuid.UUID][]Interface{}
	for _, i := range e.Interfaces {
		ifaces[i.AssetID] = append(ifaces[i.AssetID], i)
	}
	rears := map[uuid.UUID]uuid.UUID{}
	for _, r := range e.RearPorts {
		rears[r.AssetID] = r.ID
	}
	front1 := map[uuid.UUID]uuid.UUID{}
	for _, f := range e.FrontPorts {
		if f.Name == frontPortName(1) {
			front1[f.AssetID] = f.ID
		}
	}

	var cables []fixtureCable
	e.PatchedInterfaces = nil
	for start := 0; start+per <= len(e.Assets); start += per {
		rack := e.Assets[start : start+per]
		var L []fixtureEnd
		for _, a := range rack {
			for _, i := range ifaces[a.ID] {
				L = append(L, fixtureEnd{kind: dcim.ObjectKindInterface, id: i.ID, asset: a.ID})
			}
		}
		h := len(L) / 2
		site, rk := rack[0].Site, rack[0].Rack
		n := 0
		add := func(typ string, a, b fixtureEnd) {
			cables = append(cables, fixtureCable{label: CableLabel(site, rk, n), typ: typ, a: a, b: b})
			e.Witness(CableLabel(site, rk, n))
			n++
		}
		k := 0
		if e.Scale.CablesPerRack >= 3 && per >= 4 && rears[rack[2].ID] != uuid.Nil && rears[rack[3].ID] != uuid.Nil &&
			front1[rack[2].ID] != uuid.Nil && front1[rack[3].ID] != uuid.Nil && h > 0 {
			p2, p3 := rack[2].ID, rack[3].ID
			add("cat6", L[0], fixtureEnd{kind: dcim.ObjectKindFrontPort, id: front1[p2], asset: p2})
			add("smf-os2", fixtureEnd{kind: dcim.ObjectKindRearPort, id: rears[p2], asset: p2}, fixtureEnd{kind: dcim.ObjectKindRearPort, id: rears[p3], asset: p3})
			add("cat6", fixtureEnd{kind: dcim.ObjectKindFrontPort, id: front1[p3], asset: p3}, L[h])
			e.PatchedInterfaces = append(e.PatchedInterfaces, L[0].id)
			k = 1
		}
		for ; n < e.Scale.CablesPerRack && h+k < len(L) && k < h; k++ {
			add("cat6", L[k], L[h+k])
		}
	}
	if len(cables) == 0 {
		return -1, nil
	}

	if err := copyRows(ctx, tx, "cables", []string{"tenant_id", "label", "type", "operational_status", "source_kind", "status"}, len(cables),
		func(i int) []any {
			return []any{e.Tenant, cables[i].label, cables[i].typ, "connected", "declared", "active"}
		}); err != nil {
		return 0, err
	}
	ids := map[string]uuid.UUID{}
	rows, err := tx.QueryContext(ctx, `SELECT id, label FROM cables WHERE tenant_id = $1`, e.Tenant)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id uuid.UUID
		var label string
		if err := rows.Scan(&id, &label); err != nil {
			_ = rows.Close()
			return 0, err
		}
		ids[label] = id
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	err = copyRows(ctx, tx, "cable_terminations", []string{"tenant_id", "cable_id", "cable_end", "termination_kind", "termination_id", "asset_id"},
		2*len(cables), func(j int) []any {
			c := cables[j/2]
			end, t := "A", c.a
			if j%2 == 1 {
				end, t = "B", c.b
			}
			return []any{e.Tenant, ids[c.label], end, string(t.kind), t.id, t.asset}
		})
	if err != nil {
		return 0, err
	}
	// The denormalised filter columns, from each end's asset (sites, racks
	// and locations come from the earlier populators when their tables exist).
	if _, err := tx.ExecContext(ctx, `UPDATE cable_terminations ct SET site_id = a.site_id, location_id = a.location_id, rack_id = a.rack_id
		FROM assets a WHERE ct.tenant_id = $1 AND a.id = ct.asset_id`, e.Tenant); err != nil {
		return 0, err
	}
	for kind, table := range map[dcim.ObjectKind]string{dcim.ObjectKindInterface: "interfaces", dcim.ObjectKindFrontPort: "front_ports", dcim.ObjectKindRearPort: "rear_ports"} {
		if _, err := tx.ExecContext(ctx, `UPDATE public.`+table+` x SET cable_id = ct.cable_id, cable_end = ct.cable_end
			FROM cable_terminations ct WHERE ct.tenant_id = $1 AND ct.termination_kind = $2 AND ct.termination_id = x.id`, e.Tenant, string(kind)); err != nil {
			return 0, err
		}
	}

	// The paths, by the service's own walker over what was just written.
	g := cablepath.NewMemGraph()
	for _, r := range e.RearPorts {
		g.SetPositions(r.ID, FrontPortsPerRear)
	}
	rearOf := map[uuid.UUID]uuid.UUID{}
	for _, r := range e.RearPorts {
		rearOf[r.AssetID] = r.ID
	}
	for _, f := range e.FrontPorts {
		var pos int
		if _, err := fmt.Sscanf(f.Name, "Front%d", &pos); err != nil {
			return 0, fmt.Errorf("front port name %q: %w", f.Name, err)
		}
		g.AddFrontPort(f.ID, rearOf[f.AssetID], pos)
	}
	var origins []cablepath.Node
	for _, c := range cables {
		g.AddCable(ids[c.label], "connected", []cablepath.Node{cablepath.N(c.a.kind, c.a.id)}, []cablepath.Node{cablepath.N(c.b.kind, c.b.id)})
		for _, t := range []fixtureEnd{c.a, c.b} {
			if cablepath.IsOrigin(t.kind) {
				origins = append(origins, cablepath.N(t.kind, t.id))
			}
		}
	}
	type pathRow struct {
		origin cablepath.Node
		path   string
		dest   *cablepath.Node
		p      *cablepath.Path
	}
	paths := make([]pathRow, 0, len(origins))
	for _, o := range origins {
		p, err := cablepath.Walk(ctx, g, o)
		if err != nil {
			return 0, err
		}
		b, err := json.Marshal(p.Nodes)
		if err != nil {
			return 0, err
		}
		paths = append(paths, pathRow{origin: o, path: string(b), dest: p.Destination(), p: p})
	}
	err = copyRows(ctx, tx, "cable_paths", []string{"tenant_id", "origin_kind", "origin_id", "path", "destination_kind", "destination_id",
		"is_complete", "is_active", "is_split"}, len(paths), func(i int) []any {
		r := paths[i]
		var dk, di any
		if r.dest != nil {
			dk, di = string(r.dest.Kind), r.dest.ID
		}
		return []any{e.Tenant, string(r.origin.Kind), r.origin.ID, r.path, dk, di, r.p.IsComplete, r.p.IsActive, r.p.IsSplit}
	})
	if err != nil {
		return 0, err
	}
	return len(cables), nil
}
