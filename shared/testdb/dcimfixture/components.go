package dcimfixture

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// Port is one generated console, rear or front port (DCIM BUILD_PLAN row 3.1).
// The cable populator (row 3.2) reads Env.ConsolePorts, Env.RearPorts and
// Env.FrontPorts to terminate cables on them and to trace through a rear port.
type Port struct {
	ID      uuid.UUID
	AssetID uuid.UUID
	Name    string
}

// Per asset: one console port, one rear port with FrontPortsPerRear positions,
// and one front port per position (front N maps to rear position N).
const (
	// FrontPortsPerRear is also the rear port's `positions`.
	FrontPortsPerRear = 2
)

func rearPortName() string { return "Rear1" }

func frontPortName(pos int) string { return "Front" + string(rune('0'+pos)) }

func consoleNames(ctx context.Context, tx *sql.Tx, e *Env, table string) ([]Port, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, asset_id, name FROM public.`+table+` WHERE tenant_id = $1 ORDER BY asset_id, name`, e.Tenant)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Port
	for rows.Next() {
		var p Port
		if err := rows.Scan(&p.ID, &p.AssetID, &p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// populateConsolePorts gives every asset one RJ-45 console port, "con 0".
func populateConsolePorts(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 {
		return -1, nil
	}
	cols := []string{"tenant_id", "asset_id", "name", "type", "speed", "source_kind", "status", "first_seen_at", "last_seen_at"}
	err := copyRows(ctx, tx, "console_ports", cols, len(e.Assets), func(i int) []any {
		e.Witness(e.Assets[i].ID.String() + "|con 0")
		return []any{e.Tenant, e.Assets[i].ID, "con 0", "rj-45", 9600, "declared", "active", Epoch, Epoch}
	})
	if err != nil {
		return 0, err
	}
	if e.ConsolePorts, err = consoleNames(ctx, tx, e, "console_ports"); err != nil {
		return 0, err
	}
	return len(e.Assets), nil
}

// populateRearPorts gives every asset one LC rear port with FrontPortsPerRear
// positions, "Rear1".
func populateRearPorts(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 {
		return -1, nil
	}
	cols := []string{"tenant_id", "asset_id", "name", "type", "positions", "source_kind", "status", "first_seen_at", "last_seen_at"}
	err := copyRows(ctx, tx, "rear_ports", cols, len(e.Assets), func(i int) []any {
		e.Witness(e.Assets[i].ID.String() + "|" + rearPortName())
		return []any{e.Tenant, e.Assets[i].ID, rearPortName(), "lc", FrontPortsPerRear, "declared", "active", Epoch, Epoch}
	})
	if err != nil {
		return 0, err
	}
	if e.RearPorts, err = consoleNames(ctx, tx, e, "rear_ports"); err != nil {
		return 0, err
	}
	return len(e.Assets), nil
}

// populateFrontPorts gives every asset FrontPortsPerRear front ports, one per
// position of its rear port.
func populateFrontPorts(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.RearPorts) == 0 {
		return -1, nil
	}
	n := len(e.RearPorts) * FrontPortsPerRear
	cols := []string{"tenant_id", "asset_id", "name", "type", "rear_port_id", "rear_port_position", "source_kind", "status", "first_seen_at", "last_seen_at"}
	err := copyRows(ctx, tx, "front_ports", cols, n, func(i int) []any {
		r := e.RearPorts[i/FrontPortsPerRear]
		pos := i%FrontPortsPerRear + 1
		e.Witness(r.AssetID.String() + "|" + frontPortName(pos))
		return []any{e.Tenant, r.AssetID, frontPortName(pos), "lc", r.ID, pos, "declared", "active", Epoch, Epoch}
	})
	if err != nil {
		return 0, err
	}
	if e.FrontPorts, err = consoleNames(ctx, tx, e, "front_ports"); err != nil {
		return 0, err
	}
	return n, nil
}
