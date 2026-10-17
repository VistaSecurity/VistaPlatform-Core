package services

// Custom fields on assets (DCIM BUILD_PLAN row 5.1; ADR-0010 D5). The asset
// service is hand-written, so it calls the validator itself: UpdateAsset (PUT
// /infrastructure-assets/{id}) merges the fields it names over the stored
// ones and CreateAsset fills defaults, both checked against the tenant's
// definitions for kind `asset` by shared/dcim/customfields.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/customfields"
)

// assetCustomFields validates patch merged over the asset's stored values
// (assetID uuid.Nil: a new asset, nothing stored) and returns what to store.
func (s *AssetService) assetCustomFields(ctx context.Context, tenantID, assetID uuid.UUID, patch map[string]interface{}, create bool) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		stored := map[string]interface{}{}
		if assetID != uuid.Nil {
			var raw []byte
			if err := tx.QueryRowContext(ctx,
				`SELECT custom_fields FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
				tenantID, assetID).Scan(&raw); err != nil {
				return err
			}
			var err error
			if stored, err = customfields.FromJSON(raw); err != nil {
				return err
			}
		}
		var err error
		out, err = validateCustomFieldsTx(ctx, tx, dcim.ObjectKindAsset, create, stored, patch, enforcesRequired(ctx, ""))
		return err
	})
	switch {
	case errors.Is(err, customfields.ErrInvalid):
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, customFieldMessage(err))
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("asset %s: %w", assetID, ErrNotFound)
	}
	return out, err
}

// setAssetCustomFields writes an already-validated map.
func (s *AssetService) setAssetCustomFields(ctx context.Context, tenantID, assetID uuid.UUID, values map[string]interface{}) error {
	b, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE assets SET custom_fields = $3::jsonb, updated_at = now() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
			tenantID, assetID, string(b))
		return err
	})
}
