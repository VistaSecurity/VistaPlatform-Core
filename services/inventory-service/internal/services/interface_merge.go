package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// moveMergeInterfaces re-parents the merged-away asset's interfaces onto the
// survivor (DCIM BUILD_PLAN row 1.2). Interfaces are an asset-owned child with
// an identity index, (tenant, asset, name) over non-rejected rows, so — as with
// endpoints and identifiers — two records of one device very often both carry
// `eth0`, and a bare UPDATE would collide.
//
// The rule for a same-name pair is the endpoint rule: the SURVIVOR's row wins
// (its declared fields, mode, VLANs and LAG stand), the source's observation
// window and count are folded into it, the source's MACs the survivor does not
// already carry move across as additional MACs, and anything that pointed at
// the source row as its LAG, parent or bridge is re-pointed at the survivor's
// row BEFORE the source row goes — those self-FKs are ON DELETE SET NULL, so
// skipping that step would silently unhook a LAG's members. IP addresses
// assigned to the source row (polymorphic, no FK) and its FHRP assignments
// (FK ON DELETE CASCADE) are re-pointed the same way. Every other source
// interface (including rejected ones, which hold no name) simply moves.
func moveMergeInterfaces(ctx context.Context, tx *sqlx.Tx, tenant, from, to uuid.UUID) error {
	const pairs = `
		SELECT src.id AS src_id, dst.id AS dst_id
		  FROM interfaces src
		  JOIN interfaces dst ON dst.tenant_id = src.tenant_id AND dst.asset_id = $3
		                     AND dst.name = src.name AND dst.status <> 'rejected'
		 WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'`
	steps := []struct{ what, sql string }{
		{"re-point LAG members", `UPDATE interfaces m SET lag_id = p.dst_id FROM (` + pairs + `) p
		                          WHERE m.tenant_id = $1 AND m.lag_id = p.src_id`},
		{"re-point children", `UPDATE interfaces m SET parent_id = p.dst_id FROM (` + pairs + `) p
		                        WHERE m.tenant_id = $1 AND m.parent_id = p.src_id`},
		{"re-point bridged", `UPDATE interfaces m SET bridge_id = p.dst_id FROM (` + pairs + `) p
		                       WHERE m.tenant_id = $1 AND m.bridge_id = p.src_id`},
		{"fold observations", `UPDATE interfaces dst
		                          SET first_seen_at = LEAST(dst.first_seen_at, src.first_seen_at),
		                              last_seen_at = GREATEST(dst.last_seen_at, src.last_seen_at),
		                              observation_count = dst.observation_count + src.observation_count
		                         FROM interfaces src
		                        WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
		                          AND dst.tenant_id = $1 AND dst.asset_id = $3 AND dst.status <> 'rejected'
		                          AND dst.name = src.name`},
		{"re-point IP addresses", `UPDATE ip_addresses ip SET assigned_id = p.dst_id FROM (` + pairs + `) p
		                            WHERE ip.tenant_id = $1 AND ip.assigned_kind = 'interface' AND ip.assigned_id = p.src_id`},
		{"re-point FHRP assignments", `UPDATE fhrp_group_assignments f SET interface_id = p.dst_id FROM (` + pairs + `) p
		                                WHERE f.tenant_id = $1 AND f.interface_id = p.src_id
		                                  AND NOT EXISTS (SELECT 1 FROM fhrp_group_assignments d
		                                                   WHERE d.tenant_id = $1 AND d.interface_id = p.dst_id AND d.group_id = f.group_id)`},
		{"move MACs", `UPDATE mac_addresses m SET interface_id = p.dst_id, is_primary = false
		                 FROM (` + pairs + `) p
		                WHERE m.interface_id = p.src_id
		                  AND NOT EXISTS (SELECT 1 FROM mac_addresses d WHERE d.interface_id = p.dst_id AND d.mac = m.mac)`},
		{"drop duplicate interfaces", `DELETE FROM interfaces src
		                USING interfaces dst
		                WHERE src.tenant_id = $1 AND src.asset_id = $2 AND src.status <> 'rejected'
		                  AND dst.tenant_id = $1 AND dst.asset_id = $3 AND dst.status <> 'rejected'
		                  AND dst.name = src.name`},
		{"move interfaces", `UPDATE interfaces SET asset_id = $3 WHERE tenant_id = $1 AND asset_id = $2`},
	}
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s.sql, tenant, from, to); err != nil {
			return fmt.Errorf("merge: interfaces: %s: %w", s.what, err)
		}
	}
	return nil
}
