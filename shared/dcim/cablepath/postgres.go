package cablepath

// The Postgres side: PGGraph reads the topology inside the caller's tenant
// transaction, Recompute rewrites cable_paths for a set of origins, and
// Affected finds the origins whose cached path a change can move.
//
// Recompute runs in the SAME transaction as the write that triggered it (the
// cable service, the front/rear port and circuit-termination hooks), so a
// committed change never leaves a stale path behind.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// PGGraph is a Graph over one tenant transaction.
type PGGraph struct {
	tx     *sql.Tx
	tenant uuid.UUID
}

// NewPGGraph returns the graph of tenant read through tx.
func NewPGGraph(tx *sql.Tx, tenant uuid.UUID) *PGGraph { return &PGGraph{tx: tx, tenant: tenant} }

// Cable implements Graph.
func (g *PGGraph) Cable(ctx context.Context, id uuid.UUID) (Cable, error) {
	c := Cable{ID: id}
	err := g.tx.QueryRowContext(ctx, `SELECT operational_status FROM cables WHERE tenant_id = $1 AND id = $2`, g.tenant, id).Scan(&c.Status)
	return c, err
}

// FarEnd implements Graph: one query for the near termination's cable and
// the far end's terminations.
//
// A cable nobody has accepted is not walked (DCIM row 3.3): an LLDP proposal
// (status `pending`) or a rejected one holds its ports, but no path runs over
// it until it is approved — approving it is what recomputes the paths.
func (g *PGGraph) FarEnd(ctx context.Context, n Node) (Link, []Node, bool, error) {
	rows, err := g.tx.QueryContext(ctx, `
		SELECT near.cable_id, near.cable_end::text, c.operational_status, far.termination_kind, far.termination_id
		  FROM cable_terminations near
		  JOIN cables c ON c.id = near.cable_id AND c.status NOT IN ('pending', 'rejected')
		  LEFT JOIN cable_terminations far ON far.cable_id = near.cable_id AND far.cable_end <> near.cable_end
		 WHERE near.tenant_id = $1 AND near.termination_kind = $2 AND near.termination_id = $3`,
		g.tenant, string(n.Kind), n.ID)
	if err != nil {
		return Link{}, nil, false, err
	}
	defer func() { _ = rows.Close() }()
	var l Link
	var far []Node
	found := false
	for rows.Next() {
		var kind sql.NullString
		var id uuid.NullUUID
		if err := rows.Scan(&l.Cable.ID, &l.End, &l.Cable.Status, &kind, &id); err != nil {
			return Link{}, nil, false, err
		}
		found = true
		if kind.Valid && id.Valid {
			far = append(far, N(dcim.ObjectKind(kind.String), id.UUID))
		}
	}
	return l, far, found, rows.Err()
}

// RearPort implements Graph.
func (g *PGGraph) RearPort(ctx context.Context, frontID uuid.UUID) (uuid.UUID, int, bool, error) {
	var rear uuid.UUID
	var pos int
	err := g.tx.QueryRowContext(ctx, `SELECT rear_port_id, rear_port_position FROM front_ports WHERE tenant_id = $1 AND id = $2`,
		g.tenant, frontID).Scan(&rear, &pos)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, 0, false, nil
	}
	return rear, pos, err == nil, err
}

// Positions implements Graph.
func (g *PGGraph) Positions(ctx context.Context, rearID uuid.UUID) (int, error) {
	var n int
	err := g.tx.QueryRowContext(ctx, `SELECT positions FROM rear_ports WHERE tenant_id = $1 AND id = $2`, g.tenant, rearID).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 1, nil
	}
	return n, err
}

// FrontPorts implements Graph.
func (g *PGGraph) FrontPorts(ctx context.Context, rearID uuid.UUID, position int) ([]uuid.UUID, error) {
	rows, err := g.tx.QueryContext(ctx, `SELECT id FROM front_ports WHERE tenant_id = $1 AND rear_port_id = $2 AND rear_port_position = $3 ORDER BY id`,
		g.tenant, rearID, position)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CircuitPeer implements Graph.
func (g *PGGraph) CircuitPeer(ctx context.Context, termID uuid.UUID) (Peer, bool, error) {
	var p Peer
	var kind sql.NullString
	var target uuid.NullUUID
	err := g.tx.QueryRowContext(ctx, `
		SELECT peer.id, peer.termination_kind, peer.termination_id,
		       EXISTS (SELECT 1 FROM cable_terminations ct WHERE ct.termination_kind = 'circuit_termination' AND ct.termination_id = peer.id)
		  FROM circuit_terminations t
		  JOIN circuit_terminations peer ON peer.circuit_id = t.circuit_id AND peer.term_side <> t.term_side
		 WHERE t.tenant_id = $1 AND t.id = $2`, g.tenant, termID).Scan(&p.ID, &kind, &target, &p.Cabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Peer{}, false, nil
	}
	if err != nil {
		return Peer{}, false, err
	}
	if kind.Valid && kind.String == "provider_network" && target.Valid {
		pn := target.UUID
		p.ProviderNetwork = &pn
	}
	return p, true, nil
}

// OutletPowerPort implements Graph.
func (g *PGGraph) OutletPowerPort(ctx context.Context, outletID uuid.UUID) (uuid.UUID, bool, error) {
	var port uuid.NullUUID
	err := g.tx.QueryRowContext(ctx, `SELECT power_port_id FROM power_outlets WHERE tenant_id = $1 AND id = $2`, g.tenant, outletID).Scan(&port)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return port.UUID, port.Valid, nil
}

// pathJSON is what cable_paths.path stores for a path.
func pathJSON(p *Path) ([]byte, error) {
	if p.Nodes == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(p.Nodes)
}

// Save upserts origin's row in cable_paths (p non-nil) or deletes it (p nil:
// the origin is on no cable).
func Save(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, origin Node, p *Path) error {
	if p == nil {
		_, err := tx.ExecContext(ctx, `DELETE FROM cable_paths WHERE tenant_id = $1 AND origin_kind = $2 AND origin_id = $3`,
			tenant, string(origin.Kind), origin.ID)
		return err
	}
	b, err := pathJSON(p)
	if err != nil {
		return err
	}
	var dk sql.NullString
	var di uuid.NullUUID
	if d := p.Destination(); d != nil {
		dk = sql.NullString{String: string(d.Kind), Valid: true}
		di = uuid.NullUUID{UUID: d.ID, Valid: true}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO cable_paths (tenant_id, origin_kind, origin_id, path, destination_kind, destination_id, is_complete, is_active, is_split)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, origin_kind, origin_id) DO UPDATE SET
		    path = EXCLUDED.path, destination_kind = EXCLUDED.destination_kind, destination_id = EXCLUDED.destination_id,
		    is_complete = EXCLUDED.is_complete, is_active = EXCLUDED.is_active, is_split = EXCLUDED.is_split,
		    updated_at = now()`,
		tenant, string(origin.Kind), origin.ID, string(b), dk, di, p.IsComplete, p.IsActive, p.IsSplit)
	return err
}

// Recompute walks each origin and rewrites its cable_paths row (deleting it
// when the origin is no longer cabled). Non-origin kinds are ignored, as are
// duplicates.
func Recompute(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, origins []Node) error {
	g := NewPGGraph(tx, tenant)
	seen := map[Node]bool{}
	for _, o := range origins {
		if seen[o] || !IsOrigin(o.Kind) {
			continue
		}
		seen[o] = true
		p, err := Walk(ctx, g, o)
		if err != nil {
			return fmt.Errorf("cablepath: walk %s: %w", o, err)
		}
		if err := Save(ctx, tx, tenant, o, p); err != nil {
			return fmt.Errorf("cablepath: save %s: %w", o, err)
		}
	}
	return nil
}

// Through returns the origins of the stored paths that run through any of
// nodes (GIN on cable_paths.path), plus every node that is itself an origin.
//
// A power port in nodes also brings in the power outlets drawing from it: a
// path that ended at such an outlet (its inlet was uncabled) continues through
// the port once the port is cabled, and that path does not yet contain the
// port.
func Through(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, nodes []Node) ([]Node, error) {
	nodes, err := withOutletsOfPorts(ctx, tx, tenant, nodes)
	if err != nil {
		return nil, err
	}
	var out []Node
	seen := map[Node]bool{}
	add := func(n Node) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range nodes {
		if IsOrigin(n.Kind) {
			add(n)
		}
		probe, err := json.Marshal([][]Node{{n}})
		if err != nil {
			return nil, err
		}
		rows, err := tx.QueryContext(ctx, `SELECT origin_kind, origin_id FROM cable_paths WHERE tenant_id = $1 AND path @> $2::jsonb`,
			tenant, string(probe))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k string
			var id uuid.UUID
			if err := rows.Scan(&k, &id); err != nil {
				_ = rows.Close()
				return nil, err
			}
			add(N(dcim.ObjectKind(k), id))
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// withOutletsOfPorts appends to nodes the power outlets whose power_port_id is
// one of the power ports in nodes.
func withOutletsOfPorts(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, nodes []Node) ([]Node, error) {
	var ports []string
	for _, n := range nodes {
		if n.Kind == dcim.ObjectKindPowerPort {
			ports = append(ports, n.ID.String())
		}
	}
	if len(ports) == 0 {
		return nodes, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM power_outlets WHERE tenant_id = $1 AND power_port_id = ANY($2::uuid[]) ORDER BY id`,
		tenant, "{"+strings.Join(ports, ",")+"}")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := append([]Node(nil), nodes...)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, N(dcim.ObjectKindPowerOutlet, id))
	}
	return out, rows.Err()
}

// CableNodes returns a cable's node and every termination on it.
func CableNodes(ctx context.Context, tx *sql.Tx, tenant, cable uuid.UUID) ([]Node, error) {
	out := []Node{N(KindCable, cable)}
	rows, err := tx.QueryContext(ctx, `SELECT termination_kind, termination_id FROM cable_terminations WHERE tenant_id = $1 AND cable_id = $2
		ORDER BY cable_end, termination_kind, termination_id`, tenant, cable)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		var id uuid.UUID
		if err := rows.Scan(&k, &id); err != nil {
			return nil, err
		}
		out = append(out, N(dcim.ObjectKind(k), id))
	}
	return out, rows.Err()
}
