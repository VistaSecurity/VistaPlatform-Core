package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// Called only inside the transaction that creates a new tenant. Both password
// and social signup use that path. This is provisioning, not a migration of
// existing tenants or a fallback that could override an explicit policy.
func seedSignupIdentityPolicy(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_admin_settings (tenant_id, config)
 VALUES ($1, jsonb_build_object(
   'identity_admission', jsonb_build_object('mode', 'enforce', 'activated_at', now()),
   'identity_enrichment', jsonb_build_object('enabled', true,
     'excluded_cidrs', '[]'::jsonb, 'sensitive_asset_ids', '[]'::jsonb)
 ))`, tenantID)
	if err != nil {
		return fmt.Errorf("seed signup identity policy: %w", err)
	}
	// The normal audit trigger covers UPDATE only. Record initial provisioning
	// with no acting user: this is the product default, not a customer edit.
	_, err = tx.ExecContext(ctx, `INSERT INTO tenant_admin_settings_audit
 (id, tenant_id, config_before, config_after, version_before, version_after, changed_by, change_reason)
 SELECT gen_random_uuid(), tenant_id, '{}'::jsonb, config, 0, version, NULL,
 'New tenant default: identity admission and automatic enrichment enabled'
 FROM tenant_admin_settings WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return fmt.Errorf("audit signup identity policy: %w", err)
	}
	return nil
}
