package services

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

var mergeInformalReferrers = []fkRef{
	{"sensors", "asset_id"}, {"sensor_discoveries", "asset_id"}, {"tickets", "asset_id"}, {"external_connections", "elevated_asset_id"}, {"asset_merge_management_history", "asset_id"},
}

// moveMergeFindings preserves finding IDs, workflow decisions, ticket links and
// evidence. A duplicate becomes historical on the survivor, never deleted.
func moveMergeFindings(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, subject string, from, to uuid.UUID) error {
	const match = `dst.tenant_id=$1 AND dst.subject_type=$2 AND dst.subject_id=$4 AND dst.producer=src.producer AND dst.kind=src.kind AND dst.control_id IS NOT DISTINCT FROM src.control_id AND dst.detection_state<>'ARCHIVED'`
	if _, err := tx.ExecContext(ctx, `UPDATE findings dst SET first_seen=least(dst.first_seen,src.first_seen),last_seen=greatest(dst.last_seen,src.last_seen),occurrence_count=dst.occurrence_count+src.occurrence_count,updated_at=now() FROM findings src WHERE src.tenant_id=$1 AND src.subject_type=$2 AND src.subject_id=$3 AND src.detection_state<>'ARCHIVED' AND `+match, tenant, subject, from, to); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings src SET detection_state='ARCHIVED',evidence=src.evidence||jsonb_build_object('merge_coalesced_into',dst.id::text),updated_at=now() FROM findings dst WHERE src.tenant_id=$1 AND src.subject_type=$2 AND src.subject_id=$3 AND src.detection_state<>'ARCHIVED' AND `+match, tenant, subject, from, to); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE findings SET subject_id=$4,updated_at=now() WHERE tenant_id=$1 AND subject_type=$2 AND subject_id=$3`, tenant, subject, from, to)
	return err
}

func moveMergePolymorphicChildren(ctx context.Context, tx *sqlx.Tx, tenant, from, to uuid.UUID) error {
	rows, err := tx.QueryContext(ctx, `SELECT src.id,dst.id FROM asset_endpoints src JOIN asset_endpoints dst ON dst.tenant_id=src.tenant_id AND dst.asset_id=$3 AND coalesce(dst.address::text,'')=coalesce(src.address::text,'') AND coalesce(dst.fqdn,'')=coalesce(src.fqdn,'') AND coalesce(dst.port,-1)=coalesce(src.port,-1) AND dst.transport=src.transport WHERE src.tenant_id=$1 AND src.asset_id=$2 ORDER BY src.id`, tenant, from, to)
	if err != nil {
		return err
	}
	var pairs [][2]uuid.UUID
	for rows.Next() {
		var pair [2]uuid.UUID
		if err := rows.Scan(&pair[0], &pair[1]); err != nil {
			_ = rows.Close()
			return err
		}
		pairs = append(pairs, pair)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, pair := range pairs {
		if err := moveMergeFindings(ctx, tx, tenant, "endpoint", pair[0], pair[1]); err != nil {
			return fmt.Errorf("merge endpoint findings: %w", err)
		}
	}
	if err := moveMergeFindings(ctx, tx, tenant, "asset", from, to); err != nil {
		return fmt.Errorf("merge asset findings: %w", err)
	}
	for _, ref := range mergeInformalReferrers {
		if _, err := tx.ExecContext(ctx, `UPDATE `+ref.table+` SET `+ref.column+`=$3 WHERE tenant_id=$1 AND `+ref.column+`=$2`, tenant, from, to); err != nil {
			return err
		}
	}
	return nil
}

// State follows a newer observation with compatible provenance. Administrative
// updated_at is deliberately excluded: a merge or edit is not a sighting.
const preferNewerMergeState = `src.last_seen_at > dst.last_seen_at AND dst.source_kind <> 'declared'
 AND (dst.source_kind <> 'measured' OR src.source_kind IN ('measured','declared'))`

// Package coverage is a derived count of the surviving active rows. Recompute
// only existing measured/imported coverage, preserving its evidence clock and
// leaving declared coverage untouched. The merge audit retains original values.
func recomputeMergePackageCounts(ctx context.Context, tx *sqlx.Tx, tenant, asset uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `UPDATE asset_facts f SET value=to_jsonb((SELECT count(*) FROM software_installs i
      WHERE i.tenant_id=f.tenant_id AND i.asset_id=f.asset_id AND i.status='active' AND i.source_kind=f.source_kind)),updated_at=now()
      WHERE f.tenant_id=$1 AND f.asset_id=$2 AND f.key='sw.package_count' AND f.source_kind IN ('measured','imported')`, tenant, asset)
	return err
}
