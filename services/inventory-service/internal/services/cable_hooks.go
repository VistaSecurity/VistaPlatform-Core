package services

// The hooks that keep cable paths true when something other than a cable
// changes (DCIM BUILD_PLAN row 3.2; DATA_MODEL §4: "recomputed on any change
// to a cable, a front/rear port mapping, or a circuit termination touching the
// path"), and the mark_connected rule on the component side.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablepath"
)

// refuseMarkConnectedWithCable: mark_connected says "there is a cable here we
// do not model"; with a modelled cable attached it would say two things
// (NetBox CabledObjectModel.clean).
func refuseMarkConnectedWithCable(row map[string]any) error {
	if b, _ := row["mark_connected"].(bool); b && !isEmpty(row["cable_id"]) {
		return ipamInvalid("mark_connected cannot be set while a cable is attached; remove the cable first")
	}
	return nil
}

func cableRowUUID(row map[string]any, col string) (uuid.UUID, bool) {
	if row == nil || isEmpty(row[col]) {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(fmt.Sprint(row[col]))
	return id, err == nil
}

// componentCableAfterWrite runs after every component write (engine
// AfterWrite). Deletes sweep the terminations left on the deleted object (a
// rear port's front ports go by cascade, so both kinds are swept); a front
// port's mapping change and a rear port's positions change recompute the paths
// through them.
func componentCableAfterWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, kind dcim.ObjectKind, pre, post map[string]any) error {
	if post == nil {
		kinds := []dcim.ObjectKind{kind}
		if kind == dcim.ObjectKindRearPort {
			kinds = append(kinds, dcim.ObjectKindFrontPort)
		}
		if err := sweepOrphanTerminations(ctx, tx, tenant, kinds...); err != nil {
			return err
		}
		// A deleted front port also ends the paths that ran through its
		// rear port to it.
		if rear, ok := cableRowUUID(pre, "rear_port_id"); ok && kind == dcim.ObjectKindFrontPort {
			return recomputeAround(ctx, tx, tenant, []cablepath.Node{cablepath.N(dcim.ObjectKindRearPort, rear)})
		}
		return nil
	}
	var nodes []cablepath.Node
	switch kind {
	case dcim.ObjectKindFrontPort:
		changed := pre == nil || fmt.Sprint(pre["rear_port_id"]) != fmt.Sprint(post["rear_port_id"]) ||
			fmt.Sprint(pre["rear_port_position"]) != fmt.Sprint(post["rear_port_position"])
		if !changed {
			return nil
		}
		id, _ := cableRowUUID(post, "id")
		nodes = append(nodes, cablepath.N(dcim.ObjectKindFrontPort, id))
		for _, r := range []map[string]any{pre, post} {
			if rear, ok := cableRowUUID(r, "rear_port_id"); ok {
				nodes = append(nodes, cablepath.N(dcim.ObjectKindRearPort, rear))
			}
		}
	case dcim.ObjectKindRearPort:
		if pre == nil || fmt.Sprint(pre["positions"]) == fmt.Sprint(post["positions"]) {
			return nil
		}
		id, _ := cableRowUUID(post, "id")
		nodes = append(nodes, cablepath.N(dcim.ObjectKindRearPort, id))
	default:
		return nil
	}
	return recomputeAround(ctx, tx, tenant, nodes)
}

// circuitTerminationAfterWrite: a circuit termination is a cable end and the
// bridge between a circuit's sides. Any write to one (its side, its target —
// a provider network completes a path) moves the paths through it and through
// the circuit's other side; a delete sweeps its cable termination.
func circuitTerminationAfterWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	if post == nil {
		if err := sweepOrphanTerminations(ctx, tx, tenant, dcim.ObjectKindCircuitTermination); err != nil {
			return err
		}
	}
	var nodes []cablepath.Node
	for _, r := range []map[string]any{pre, post} {
		if r == nil {
			continue
		}
		if id, ok := cableRowUUID(r, "id"); ok {
			nodes = append(nodes, cablepath.N(dcim.ObjectKindCircuitTermination, id))
		}
		circuit, ok := cableRowUUID(r, "circuit_id")
		if !ok {
			continue
		}
		rows, err := tx.QueryContext(ctx, `SELECT id FROM circuit_terminations WHERE tenant_id = $1 AND circuit_id = $2`, tenant, circuit)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			nodes = append(nodes, cablepath.N(dcim.ObjectKindCircuitTermination, id))
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return recomputeAround(ctx, tx, tenant, nodes)
}

// circuitAfterWrite: deleting a circuit cascades its terminations.
func circuitAfterWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, _, post map[string]any) error {
	if post != nil {
		return nil
	}
	return sweepOrphanTerminations(ctx, tx, tenant, dcim.ObjectKindCircuitTermination)
}

// allCableTerminationKinds are the kinds with a table, for the merge sweep.
func allCableTerminationKinds() []dcim.ObjectKind {
	var out []dcim.ObjectKind
	for _, k := range cablepath.TerminationKinds {
		if _, ok := terminationTables[k]; ok {
			out = append(out, k)
		}
	}
	return out
}
