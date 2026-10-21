package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// moveMergeHardware re-parents the merged-away asset's row 2.4 hardware onto
// the survivor: module bays, modules, inventory items and its virtual chassis
// membership. Module bays and inventory items have identity indexes scoped by
// asset, so — as for interfaces and ports — a same-name pair collides and the
// SURVIVOR's row wins, with the source's observation window folded into it:
//
//   - a module in a source bay whose same-name survivor bay is EMPTY moves into
//     that bay; one whose survivor bay already holds a module loses to it — its
//     components stay (module_id cleared, they were moved with the ports) and
//     the module row goes;
//   - inventory items pair at the top level by name; the source item's
//     children move under the survivor's item where no same-name child is
//     there already (a colliding child goes with its dropped parent — the
//     survivor's own child stands);
//   - an unchassised survivor takes the duplicate's chassis membership (and
//     mastership, via assetReferrers); the duplicate leaves the chassis;
//   - virtual device contexts (DCIM gap 1) pair by name: the source context's
//     interface memberships move to the survivor's same-name context and the
//     source row goes; the rest move, losing an identifier the survivor
//     already uses (identifiers are unique per asset).
//
// Runs after moveMergeComponents, which has already moved the ports a module
// declared (their module_id still names the source module).
func moveMergeHardware(ctx context.Context, tx *sqlx.Tx, tenant, from, to uuid.UUID) error {
	bayPairs := `SELECT src.id AS src_id, dst.id AS dst_id FROM module_bays src
	               JOIN module_bays dst ON dst.tenant_id = src.tenant_id AND dst.asset_id = $3
	                                   AND dst.name = src.name AND dst.status <> 'rejected'
	              WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'`
	losing := `SELECT m.id FROM modules m JOIN (` + bayPairs + `) p ON p.src_id = m.module_bay_id
	            WHERE m.tenant_id = $1`
	itemPairs := `SELECT src.id AS src_id, dst.id AS dst_id FROM inventory_items src
	                JOIN inventory_items dst ON dst.tenant_id = src.tenant_id AND dst.asset_id = $3 AND dst.parent_id IS NULL
	                                        AND dst.name = src.name AND dst.status <> 'rejected'
	               WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.parent_id IS NULL AND src.status <> 'rejected'`
	steps := []struct{ what, sql string }{
		{"move modules into empty surviving bays", `
			UPDATE modules m SET module_bay_id = p.dst_id, asset_id = $3 FROM (` + bayPairs + `) p
			 WHERE m.tenant_id = $1 AND m.module_bay_id = p.src_id AND m.status <> 'rejected'
			   AND NOT EXISTS (SELECT 1 FROM modules o WHERE o.module_bay_id = p.dst_id AND o.status <> 'rejected')`},
	}
	for _, t := range moduleComponentTables {
		steps = append(steps, struct{ what, sql string }{"release " + t + " of losing modules",
			`UPDATE ` + t + ` SET module_id = NULL WHERE tenant_id = $1 AND module_id IN (` + losing + `)`})
	}
	steps = append(steps, []struct{ what, sql string }{
		{"drop losing modules", `DELETE FROM modules WHERE tenant_id = $1 AND id IN (` + losing + `)`},
		{"fold module bays", `
			UPDATE module_bays dst SET first_seen_at = LEAST(dst.first_seen_at, src.first_seen_at),
			       last_seen_at = GREATEST(dst.last_seen_at, src.last_seen_at),
			       observation_count = dst.observation_count + src.observation_count
			  FROM module_bays src
			 WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
			   AND dst.tenant_id = $1 AND dst.asset_id = $3 AND dst.status <> 'rejected' AND dst.name = src.name`},
		{"drop duplicate module bays", `
			DELETE FROM module_bays src USING module_bays dst
			 WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
			   AND dst.tenant_id = $1 AND dst.asset_id = $3 AND dst.status <> 'rejected' AND dst.name = src.name`},
		{"move module bays", `UPDATE module_bays SET asset_id = $3 WHERE tenant_id = $1 AND asset_id = $2`},
		{"move modules", `UPDATE modules SET asset_id = $3 WHERE tenant_id = $1 AND asset_id = $2`},
		{"fold inventory items", `
			UPDATE inventory_items dst SET first_seen_at = LEAST(dst.first_seen_at, src.first_seen_at),
			       last_seen_at = GREATEST(dst.last_seen_at, src.last_seen_at),
			       observation_count = dst.observation_count + src.observation_count
			  FROM (` + itemPairs + `) p JOIN inventory_items src ON src.id = p.src_id
			 WHERE dst.id = p.dst_id`},
		{"re-parent children of duplicate items", `
			UPDATE inventory_items c SET parent_id = p.dst_id, asset_id = $3 FROM (` + itemPairs + `) p
			 WHERE c.tenant_id = $1 AND c.parent_id = p.src_id
			   AND NOT EXISTS (SELECT 1 FROM inventory_items d WHERE d.tenant_id = $1 AND d.parent_id = p.dst_id
			                   AND d.name = c.name AND d.status <> 'rejected')`},
		{"drop duplicate items", `DELETE FROM inventory_items WHERE tenant_id = $1 AND id IN (SELECT src_id FROM (` + itemPairs + `) p)`},
		{"move inventory items", `UPDATE inventory_items SET asset_id = $3 WHERE tenant_id = $1 AND asset_id = $2`},
		{"re-point memberships of duplicate contexts", `
			INSERT INTO interface_virtual_device_contexts (tenant_id, interface_id, virtual_device_context_id)
			SELECT j.tenant_id, j.interface_id, dst.id
			  FROM interface_virtual_device_contexts j
			  JOIN virtual_device_contexts src ON src.id = j.virtual_device_context_id
			  JOIN virtual_device_contexts dst ON dst.tenant_id = src.tenant_id AND dst.asset_id = $3
			                                  AND dst.name = src.name AND dst.status <> 'rejected'
			 WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
			ON CONFLICT DO NOTHING`},
		{"fold contexts", `
			UPDATE virtual_device_contexts dst SET first_seen_at = LEAST(dst.first_seen_at, src.first_seen_at),
			       last_seen_at = GREATEST(dst.last_seen_at, src.last_seen_at),
			       observation_count = dst.observation_count + src.observation_count
			  FROM virtual_device_contexts src
			 WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
			   AND dst.tenant_id = $1 AND dst.asset_id = $3 AND dst.status <> 'rejected' AND dst.name = src.name`},
		{"drop duplicate contexts", `
			DELETE FROM virtual_device_contexts src USING virtual_device_contexts dst
			 WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
			   AND dst.tenant_id = $1 AND dst.asset_id = $3 AND dst.status <> 'rejected' AND dst.name = src.name`},
		{"release colliding context identifiers", `
			UPDATE virtual_device_contexts src SET identifier = NULL
			 WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.identifier IS NOT NULL
			   AND EXISTS (SELECT 1 FROM virtual_device_contexts dst WHERE dst.tenant_id = $1 AND dst.asset_id = $3
			               AND dst.identifier = src.identifier AND dst.status <> 'rejected')`},
		{"move contexts", `UPDATE virtual_device_contexts SET asset_id = $3 WHERE tenant_id = $1 AND asset_id = $2`},
	}...)
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s.sql, tenant, from, to); err != nil {
			return fmt.Errorf("merge: hardware: %s: %w", s.what, err)
		}
	}
	return moveMergeChassisMembership(ctx, tx, tenant, from, to)
}

// moveMergeChassisMembership: an unchassised survivor takes the duplicate's
// virtual chassis membership; the duplicate always leaves its chassis.
func moveMergeChassisMembership(ctx context.Context, tx *sqlx.Tx, tenant, from, to uuid.UUID) error {
	var (
		vc       uuid.NullUUID
		pos, pri sql.NullInt64
	)
	err := tx.QueryRowContext(ctx, `SELECT virtual_chassis_id, vc_position, vc_priority FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenant, from).Scan(&vc, &pos, &pri)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !vc.Valid) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("merge: hardware: chassis membership: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET virtual_chassis_id = NULL, vc_position = NULL, vc_priority = NULL
		WHERE tenant_id = $1 AND id = $2`, tenant, from); err != nil {
		return fmt.Errorf("merge: hardware: release the duplicate's chassis: %w", err)
	}
	// The position is the duplicate's, now free; checked anyway, because a
	// unique violation would abort the merge's transaction.
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET virtual_chassis_id = $3, vc_position = $4, vc_priority = $5
		WHERE tenant_id = $1 AND id = $2 AND virtual_chassis_id IS NULL
		  AND ($4::smallint IS NULL OR NOT EXISTS (SELECT 1 FROM assets o WHERE o.tenant_id = $1 AND o.virtual_chassis_id = $3
		       AND o.vc_position = $4::smallint AND o.deleted_at IS NULL))`, tenant, to, vc.UUID, nullInt64(pos), nullInt64(pri)); err != nil {
		return fmt.Errorf("merge: hardware: chassis membership: %w", err)
	}
	return nil
}

func nullInt64(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return n.Int64
}
