package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// moveMergeComponents re-parents the merged-away asset's port components onto
// the survivor (DCIM BUILD_PLAN row 3.1): console ports, console server ports,
// rear ports, front ports, device bays, power ports and power outlets. As with
// interfaces they have an identity index, (tenant, asset, name) over
// non-rejected rows, so two records of one device very often both carry `Rear1`
// or `con 0`, and a bare UPDATE would collide.
//
// The rule is the interface rule: for a same-name pair the SURVIVOR's row wins
// (its type, mapping and declared fields stand), the source's observation
// window and count are folded into it, and the source row goes. What hangs off
// the source row is carried across first, because the FKs are ON DELETE CASCADE
// or SET NULL and would otherwise take it silently:
//
//   - front ports of a same-name rear-port pair are re-pointed at the
//     survivor's rear port where their position is free there and within its
//     `positions` (a position the survivor already maps stands; a front port
//     that cannot be placed goes with the dropped rear port);
//   - outlets fed by a same-name power port pair are re-pointed at the
//     survivor's power port;
//   - a same-name device-bay pair keeps the survivor's bay and, when the
//     survivor's bay is empty, takes the source bay's installed asset;
//   - a bay of ANOTHER asset that holds the merged-away asset now holds the
//     survivor, unless the survivor already sits in a bay.
//
// Every other source component, rejected ones included, simply moves.
func moveMergeComponents(ctx context.Context, tx *sqlx.Tx, tenant, from, to uuid.UUID) error {
	pairs := func(table string) string {
		return `SELECT src.id AS src_id, dst.id AS dst_id FROM ` + table + ` src
		          JOIN ` + table + ` dst ON dst.tenant_id = src.tenant_id AND dst.asset_id = $3
		                             AND dst.name = src.name AND dst.status <> 'rejected'
		         WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'`
	}
	fold := func(table string) string {
		return `UPDATE ` + table + ` dst
		           SET first_seen_at = LEAST(dst.first_seen_at, src.first_seen_at),
		               last_seen_at = GREATEST(dst.last_seen_at, src.last_seen_at),
		               observation_count = dst.observation_count + src.observation_count
		          FROM ` + table + ` src
		         WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
		           AND dst.tenant_id = $1 AND dst.asset_id = $3 AND dst.status <> 'rejected'
		           AND dst.name = src.name`
	}
	dropDup := func(table string) string {
		return `DELETE FROM ` + table + ` src USING ` + table + ` dst
		         WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
		           AND dst.tenant_id = $1 AND dst.asset_id = $3 AND dst.status <> 'rejected'
		           AND dst.name = src.name`
	}
	move := func(table string) string {
		return `UPDATE ` + table + ` SET asset_id = $3 WHERE tenant_id = $1 AND asset_id = $2`
	}
	steps := []struct{ what, sql string }{
		// Front ports first: a same-name pair is dropped (survivor wins), then
		// what is left of the source's front ports is re-pointed at the
		// survivor's rear port of the same name where the position is free.
		{"fold front ports", fold("front_ports")},
		{"drop duplicate front ports", dropDup("front_ports")},
		{"re-point front ports at the surviving rear port", `
			UPDATE front_ports f SET rear_port_id = p.dst_id FROM (` + pairs("rear_ports") + `) p
			 WHERE f.tenant_id = $1 AND f.rear_port_id = p.src_id
			   AND f.rear_port_position <= (SELECT positions FROM rear_ports WHERE id = p.dst_id)
			   AND NOT EXISTS (SELECT 1 FROM front_ports d WHERE d.rear_port_id = p.dst_id AND d.rear_port_position = f.rear_port_position)`},
		{"fold rear ports", fold("rear_ports")},
		{"drop duplicate rear ports", dropDup("rear_ports")},
		{"move rear ports", move("rear_ports")},
		{"move front ports", move("front_ports")},

		{"fold console ports", fold("console_ports")},
		{"drop duplicate console ports", dropDup("console_ports")},
		{"move console ports", move("console_ports")},
		{"fold console server ports", fold("console_server_ports")},
		{"drop duplicate console server ports", dropDup("console_server_ports")},
		{"move console server ports", move("console_server_ports")},

		// Outlets before power ports: re-point the survivors' feed, then drop.
		{"fold power outlets", fold("power_outlets")},
		{"drop duplicate power outlets", dropDup("power_outlets")},
		{"re-point outlets at the surviving power port", `
			UPDATE power_outlets o SET power_port_id = p.dst_id FROM (` + pairs("power_ports") + `) p
			 WHERE o.tenant_id = $1 AND o.power_port_id = p.src_id`},
		{"fold power ports", fold("power_ports")},
		{"drop duplicate power ports", dropDup("power_ports")},
		{"move power ports", move("power_ports")},
		{"move power outlets", move("power_outlets")},

		// Device bays. A same-name pair whose survivor bay is empty takes the
		// source bay's installed asset; the source value is parked in a temp
		// table because the installed-asset index is unique.
		{"park installed assets of duplicate bays", `
			CREATE TEMP TABLE merge_bay_fill ON COMMIT DROP AS
			SELECT p.dst_id, src.installed_asset_id FROM (` + pairs("device_bays") + `) p
			  JOIN device_bays src ON src.id = p.src_id
			  JOIN device_bays dst ON dst.id = p.dst_id
			 WHERE src.installed_asset_id IS NOT NULL AND dst.installed_asset_id IS NULL`},
		{"fold device bays", fold("device_bays")},
		{"drop duplicate device bays", dropDup("device_bays")},
		{"fill empty surviving bays", `
			UPDATE device_bays b SET installed_asset_id = f.installed_asset_id FROM merge_bay_fill f WHERE b.id = f.dst_id`},
		{"drop the bay fill", `DROP TABLE merge_bay_fill`},
		{"move device bays", move("device_bays")},
		{"re-point bays that hold the merged-away asset", `
			UPDATE device_bays SET installed_asset_id = $3
			 WHERE tenant_id = $1 AND installed_asset_id = $2
			   AND NOT EXISTS (SELECT 1 FROM device_bays d WHERE d.tenant_id = $1 AND d.installed_asset_id = $3)`},
	}
	for _, s := range steps {
		args := []any{tenant, from, to}
		if !strings.Contains(s.sql, "$1") {
			args = nil // a statement with no placeholders takes no arguments
		}
		if _, err := tx.ExecContext(ctx, s.sql, args...); err != nil {
			return fmt.Errorf("merge: components: %s: %w", s.what, err)
		}
	}
	// Cable ends (row 3.2): a moved component keeps its cable (its
	// termination row's asset_id is an assetReferrer); a dropped duplicate's
	// cable end goes with it and the paths over it are recomputed.
	if err := sweepOrphanTerminations(ctx, tx.Tx, tenant, allCableTerminationKinds()...); err != nil {
		return fmt.Errorf("merge: components: sweep cable terminations: %w", err)
	}
	return nil
}
