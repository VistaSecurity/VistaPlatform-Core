package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Management profiles remain paired: selecting a connection also selects its
// credential reference. Historical encrypted records remain on archived source
// IDs and are explicitly referenced by the survivor's merge audit.
func mergeManagementProfiles(snap mergeSnapshot) map[uuid.UUID]map[string]any {
	profiles := map[uuid.UUID]map[string]any{}
	for _, table := range []string{"asset_management", "asset_credentials"} {
		for _, record := range snap.Records[table] {
			var row map[string]any
			_ = json.Unmarshal(record.Data, &row)
			id, _ := uuid.Parse(mergeString(row["asset_id"]))
			if profiles[id] == nil {
				profiles[id] = map[string]any{"asset_id": id}
			}
			fields := []string{"management_url", "management_protocol"}
			if table == "asset_credentials" {
				fields = []string{"credential_id"}
				profiles[id]["credentials_configured"] = true
			}
			for _, field := range fields {
				value := row[field]
				if field == "management_url" {
					parsed, err := url.Parse(mergeString(value))
					if err == nil {
						parsed.User = nil
						parsed.RawQuery = ""
						parsed.Fragment = ""
						value = parsed.String()
					} else {
						value = "Configured endpoint"
					}
				}
				profiles[id][field] = value
			}
		}
	}
	return profiles
}
func addManagementPreview(out *AssetMergePreview, snap mergeSnapshot) error {
	profiles := mergeManagementProfiles(snap)
	if selected, explicit := out.FieldResolutions["management_profile"]; explicit {
		if _, exists := profiles[selected]; !exists {
			return ErrMergeSelection
		}
	}
	if len(profiles) == 0 {
		return nil
	}
	values := []MergeFieldValue{}
	for _, asset := range out.Assets {
		if profile, ok := profiles[asset.AssetID]; ok {
			values = append(values, MergeFieldValue{AssetID: asset.AssetID, Value: profile, Declared: true})
		}
	}
	if len(values) > 1 {
		out.Conflicts = append(out.Conflicts, MergeFieldConflict{Field: "management_profile", Values: values, RequiresResolution: true})
	}
	selected := out.SurvivorAssetID
	if choice, ok := out.FieldResolutions["management_profile"]; ok {
		selected = choice
	} else if len(values) == 1 {
		selected = values[0].AssetID
	}
	if profile, ok := profiles[selected]; ok {
		out.SelectedFields["management_profile"] = profile
	}
	return nil
}
func applyMergeManagement(ctx context.Context, tx *sqlx.Tx, tenant, survivor uuid.UUID, preview *AssetMergePreview) error {
	profile, ok := preview.SelectedFields["management_profile"].(map[string]any)
	if !ok {
		return nil
	}
	selected, ok := profile["asset_id"].(uuid.UUID)
	if !ok || selected == survivor {
		return nil
	}
	// Preserve the previous survivor profile before replacing it. Ciphertext is
	// stored only in this restricted internal table, never in the public audit.
	for _, table := range []string{"asset_management", "asset_credentials"} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_merge_management_history(tenant_id,id,asset_id,source_asset_id,record_table,record) SELECT $1,gen_random_uuid(),$2,$2,$3,to_jsonb(r) FROM `+table+` r WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor, table); err != nil {
			return err
		}
	}
	// A complete paired selection may intentionally have no credential or URL.
	// Archive the old pair, then copy the selected pair while retaining originals.
	for _, table := range []string{"asset_management", "asset_credentials"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor); err != nil {
			return err
		}
	}
	columns := map[string]string{
		"asset_management":  "management_url,management_protocol,tls_insecure_skip_verify,connection_status,last_interrogated_at,interrogation_error,interrogation_schedule_id,created_at,updated_at",
		"asset_credentials": "credential_id,username,password_enc,created_at,updated_at",
	}
	for table, cols := range columns {
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+table+`(tenant_id,asset_id,`+cols+`) SELECT tenant_id,$3,`+cols+` FROM `+table+` WHERE tenant_id=$1 AND asset_id=$2`, tenant, selected, survivor); err != nil {
			return fmt.Errorf("select merge management profile: %w", err)
		}
	}
	return nil
}
