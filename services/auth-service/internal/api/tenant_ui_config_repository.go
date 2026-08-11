package api

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// tenantUIConfigStore is the persistence seam the tenant/platform UI-config
// handlers depend on. Declaring it as an interface (the *sql.DB-backed
// repository is the production impl) lets the contract test drive the real
// handlers with an in-memory stub — no database — per the spec-first contract
// recipe (ADR-0001). All SQL is the verbatim platform_settings / tenants.ui_config
// read/write that previously lived inline in the handler closures.
type tenantUIConfigStore interface {
	// GetPlatformUIConfigJSON returns platform_settings.setting_value for the
	// 'ui_config' key. sql.ErrNoRows is returned through unchanged (the handlers
	// treat a missing platform default as non-fatal).
	GetPlatformUIConfigJSON(ctx context.Context) ([]byte, error)
	// GetTenantUIConfigJSON returns COALESCE(ui_config::text, '{}') for the
	// tenant. sql.ErrNoRows is returned through so the handler can map a missing
	// tenant to 404.
	GetTenantUIConfigJSON(ctx context.Context, tenantID uuid.UUID) ([]byte, error)
	UpdateTenantUIConfigJSON(ctx context.Context, tenantID uuid.UUID, configJSON []byte) error
}

type tenantUIConfigRepository struct {
	db *sql.DB
}

func newTenantUIConfigRepo(db *sql.DB) *tenantUIConfigRepository {
	return &tenantUIConfigRepository{db: db}
}

// NOTE: these read/write platform_settings and the GLOBAL tenants table (neither
// carries a tenant_isolation policy), so they are not RLS-scoped and stay on the
// plain handle. Tenant-row access keeps its explicit WHERE id = $N predicate.
func (r *tenantUIConfigRepository) GetPlatformUIConfigJSON(ctx context.Context) ([]byte, error) {
	var configJSON []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT setting_value::text
		FROM platform_settings
		WHERE setting_key = 'ui_config'
	`).Scan(&configJSON)
	if err != nil {
		return nil, err
	}
	return configJSON, nil
}

func (r *tenantUIConfigRepository) GetTenantUIConfigJSON(ctx context.Context, tenantID uuid.UUID) ([]byte, error) {
	var configJSON []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(ui_config::text, '{}')
		FROM tenants
		WHERE id = $1
	`, tenantID).Scan(&configJSON)
	if err != nil {
		return nil, err
	}
	return configJSON, nil
}

func (r *tenantUIConfigRepository) UpdateTenantUIConfigJSON(ctx context.Context, tenantID uuid.UUID, configJSON []byte) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE tenants
		SET ui_config = $1::jsonb, updated_at = NOW()
		WHERE id = $2
	`, configJSON, tenantID)
	return err
}
