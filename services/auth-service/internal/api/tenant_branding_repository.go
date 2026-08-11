package api

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// tenantBrandingStore is the persistence seam the tenant-branding handlers
// depend on. Declaring it as an interface (the *sql.DB-backed repository is the
// production implementation) lets the contract test drive the real handlers with
// an in-memory stub — no database — per the spec-first contract recipe
// (ADR-0001). The SQL is the verbatim tenants.custom_branding read/write that
// previously lived inline in the GetTenantBranding / UpdateTenantBranding
// closures.
type tenantBrandingStore interface {
	// GetBrandingJSON returns COALESCE(custom_branding::text, '{}') for the
	// tenant. sql.ErrNoRows is returned through unchanged so the handler can map
	// a missing tenant to 404.
	GetBrandingJSON(ctx context.Context, tenantID uuid.UUID) ([]byte, error)
	UpdateBrandingJSON(ctx context.Context, tenantID uuid.UUID, brandingJSON []byte) error
}

type tenantBrandingRepository struct {
	db *sql.DB
}

func newTenantBrandingRepo(db *sql.DB) *tenantBrandingRepository {
	return &tenantBrandingRepository{db: db}
}

// NOTE: branding/UI-config live on the GLOBAL tenants table (no tenant_isolation
// policy), so these reads/writes are not RLS-scoped and intentionally stay on the
// plain handle. They keep their explicit WHERE id = $N tenant predicate.
func (r *tenantBrandingRepository) GetBrandingJSON(ctx context.Context, tenantID uuid.UUID) ([]byte, error) {
	var brandingJSON []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(custom_branding::text, '{}')
		FROM tenants
		WHERE id = $1
	`, tenantID).Scan(&brandingJSON)
	if err != nil {
		return nil, err
	}
	return brandingJSON, nil
}

func (r *tenantBrandingRepository) UpdateBrandingJSON(ctx context.Context, tenantID uuid.UUID, brandingJSON []byte) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE tenants
		SET custom_branding = $1::jsonb, updated_at = NOW()
		WHERE id = $2
	`, brandingJSON, tenantID)
	return err
}
