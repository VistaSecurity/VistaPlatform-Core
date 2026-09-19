package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Only candidate protection and the policy revision enter merge previews/audits.
// The surrounding tenant configuration may contain unrelated private settings.
type mergeEnrichmentPolicy struct {
	Version           int         `json:"version"`
	SensitiveAssetIDs []uuid.UUID `json:"sensitive_asset_ids"`
}

// Lifecycle session locks precede this row; policy precedes identifier and asset
// row locks, matching enrichment writers that hold policy through identity work.
func lockMergeEnrichmentPolicy(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, write bool) error {
	if write {
		if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{}') ON CONFLICT(tenant_id) DO NOTHING`, tenant); err != nil {
			return err
		}
	}
	lock := " FOR SHARE"
	if write {
		lock = " FOR UPDATE"
	}
	var version int
	err := tx.QueryRowContext(ctx, `SELECT version FROM tenant_admin_settings WHERE tenant_id=$1`+lock, tenant).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

func readMergeEnrichmentPolicy(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, candidates []uuid.UUID) (mergeEnrichmentPolicy, error) {
	policy := mergeEnrichmentPolicy{Version: 1, SensitiveAssetIDs: []uuid.UUID{}}
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT version,COALESCE(config->'identity_enrichment'->'sensitive_asset_ids','[]') FROM tenant_admin_settings WHERE tenant_id=$1`, tenant).Scan(&policy.Version, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return policy, nil
	}
	if err != nil {
		return policy, err
	}
	var ids []uuid.UUID
	if err := json.Unmarshal(raw, &ids); err != nil {
		return policy, err
	}
	selected := map[uuid.UUID]bool{}
	for _, id := range candidates {
		selected[id] = true
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		if selected[id] && !seen[id] {
			policy.SensitiveAssetIDs = append(policy.SensitiveAssetIDs, id)
			seen[id] = true
		}
	}
	sort.Slice(policy.SensitiveAssetIDs, func(i, j int) bool {
		return policy.SensitiveAssetIDs[i].String() < policy.SensitiveAssetIDs[j].String()
	})
	return policy, nil
}

func preserveMergeEnrichmentPolicy(ctx context.Context, tx *sqlx.Tx, tenant, survivor, actor uuid.UUID, sources []uuid.UUID, reason string) error {
	var raw []byte
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT version,COALESCE(config->'identity_enrichment'->'sensitive_asset_ids','[]') FROM tenant_admin_settings WHERE tenant_id=$1`, tenant).Scan(&version, &raw); err != nil {
		return err
	}
	var ids []uuid.UUID
	if err := json.Unmarshal(raw, &ids); err != nil {
		return err
	}
	sourceSet := map[uuid.UUID]bool{}
	for _, source := range sources {
		sourceSet[source] = true
	}
	changed := false
	seen := map[uuid.UUID]bool{}
	preserved := []uuid.UUID{}
	for _, id := range ids {
		if sourceSet[id] {
			id = survivor
			changed = true
		}
		if !seen[id] {
			preserved = append(preserved, id)
			seen[id] = true
		}
	}
	if !changed {
		return nil
	}
	sort.Slice(preserved, func(i, j int) bool { return preserved[i].String() < preserved[j].String() })
	encoded, err := json.Marshal(preserved)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,sensitive_asset_ids}',$2::jsonb),version=version+1,updated_by=$3,updated_at=now() WHERE tenant_id=$1`, tenant, string(encoded), nullableUUID(actor)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE tenant_admin_settings_audit SET change_reason=$4 WHERE tenant_id=$1 AND version_before=$2 AND version_after=$3`, tenant, version, version+1, reason)
	return err
}
