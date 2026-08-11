package scopes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/database"
)

// ErrNotFound is returned when a Scope lookup misses (either truly missing or
// not visible to the current tenant under RLS).
var ErrNotFound = errors.New("scope not found")

// ErrSystemScopeDelete is returned when a caller attempts to delete a system
// (auto-seeded) scope. System scopes are editable but not deletable — deleting
// them would orphan CBOM artifacts that reference the scope.
var ErrSystemScopeDelete = errors.New("system scopes cannot be deleted")

// Repository encapsulates Scope persistence. Tenant isolation is enforced by
// an explicit tenant_id predicate on every query — RLS is set up but inert in
// this deployment (the service connects as the table owner), so it must not be
// relied on as the isolation boundary. The set_config('app.tenant_id') call is
// kept for defense-in-depth should the connection role ever change.
type Repository struct {
	db *database.DB
}

// NewRepository constructs a Repository over the given DB.
func NewRepository(db *database.DB) *Repository {
	return &Repository{db: db}
}

// withTenantSession runs fn inside a transaction with `app.tenant_id` set to
// the given tenant, so RLS policies match the caller's tenant scope. Returns
// the underlying error from fn (or commit/rollback).
func (r *Repository) withTenantSession(ctx context.Context, tenantID uuid.UUID, fn func(*sql.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("scopes: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("scopes: set tenant_id: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

const scopeColumns = `id, tenant_id, name, description, predicate, version,
	is_default, is_system, deleted_at, created_by, updated_by, created_at, updated_at`

// List returns all non-deleted scopes for the given tenant, ordered by
// (is_system DESC, name ASC) so system defaults appear first.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Scope, error) {
	var scopes []Scope
	err := r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT `+scopeColumns+`
			FROM public.scopes
			WHERE deleted_at IS NULL
			ORDER BY is_system DESC, name ASC
		`)
		if err != nil {
			return fmt.Errorf("scopes: query list: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			s, scanErr := scanScope(rows)
			if scanErr != nil {
				return scanErr
			}
			scopes = append(scopes, s)
		}
		return rows.Err()
	})
	return scopes, err
}

// Get returns a single scope by id within the tenant's scope. The tenant_id
// predicate is the real isolation boundary — RLS is inert because the service
// connects as the table owner, so every by-id query must filter tenant_id
// explicitly. Returns ErrNotFound if missing.
func (r *Repository) Get(ctx context.Context, tenantID, scopeID uuid.UUID) (*Scope, error) {
	var out *Scope
	err := r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT `+scopeColumns+`
			FROM public.scopes
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`, scopeID, tenantID)
		s, scanErr := scanScope(row)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return ErrNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		out = &s
		return nil
	})
	return out, err
}

// Create inserts a new scope. Caller is responsible for providing a unique
// (tenant_id, name) — the DB constraint will reject duplicates.
func (r *Repository) Create(ctx context.Context, s *Scope) error {
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	return r.withTenantSession(ctx, s.TenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			INSERT INTO public.scopes
				(tenant_id, name, description, predicate, version, is_default, is_system,
				 created_by, updated_by)
			VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8)
			RETURNING id, created_at, updated_at, version
		`, s.TenantID, s.Name, s.Description, s.Predicate, s.IsDefault, s.IsSystem,
			s.CreatedBy, s.UpdatedBy,
		).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt, &s.Version)
	})
}

// Update overwrites name/description/predicate. Version is bumped iff name or
// predicate actually changed (the audit trigger fires on the same condition).
// Returns ErrNotFound if the row is missing.
func (r *Repository) Update(ctx context.Context, tenantID, scopeID uuid.UUID, updatedBy uuid.UUID, req UpdateRequest) (*Scope, error) {
	if err := ValidateName(req.Name); err != nil {
		return nil, err
	}
	var out *Scope
	err := r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		// Bump version only when content actually changed.
		// $1 must be cast at both use sites: bare, the SET deduces varchar(255)
		// from the column while IS DISTINCT FROM deduces text — Postgres rejects
		// the statement with "inconsistent types deduced for parameter $1".
		row := tx.QueryRowContext(ctx, `
			UPDATE public.scopes
			SET name = $1::text,
				description = $2,
				predicate = $3,
				updated_by = $4,
				updated_at = now(),
				version = CASE
					WHEN name::text IS DISTINCT FROM $1::text OR predicate IS DISTINCT FROM $3
					THEN version + 1
					ELSE version
				END
			WHERE id = $5 AND tenant_id = $6 AND deleted_at IS NULL
			RETURNING `+scopeColumns+`
		`, req.Name, req.Description, req.Predicate, updatedBy, scopeID, tenantID)
		s, scanErr := scanScope(row)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return ErrNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		out = &s
		return nil
	})
	return out, err
}

// Delete soft-deletes a non-system scope. System scopes return
// ErrSystemScopeDelete — deletion is rejected because existing CBOM artifacts
// may reference the scope by id.
func (r *Repository) Delete(ctx context.Context, tenantID, scopeID uuid.UUID) error {
	return r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		var isSystem bool
		err := tx.QueryRowContext(ctx, `
			SELECT is_system FROM public.scopes WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`, scopeID, tenantID).Scan(&isSystem)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if isSystem {
			return ErrSystemScopeDelete
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE public.scopes SET deleted_at = now() WHERE id = $1 AND tenant_id = $2
		`, scopeID, tenantID)
		return err
	})
}

// CountForTenant returns the number of non-deleted scopes for a tenant. Used
// by the default-seeder to short-circuit when defaults already exist.
func (r *Repository) CountForTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM public.scopes WHERE deleted_at IS NULL
		`).Scan(&n)
	})
	return n, err
}

// scanScope reads a Scope from a row-like object (sql.Row or sql.Rows). It
// is defined as a generic-ish helper that takes a Scan() method via duck-type.
func scanScope(r interface{ Scan(...interface{}) error }) (Scope, error) {
	var s Scope
	var description sql.NullString
	err := r.Scan(
		&s.ID, &s.TenantID, &s.Name, &description, &s.Predicate, &s.Version,
		&s.IsDefault, &s.IsSystem, &s.DeletedAt,
		&s.CreatedBy, &s.UpdatedBy, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return Scope{}, err
	}
	if description.Valid {
		s.Description = description.String
	}
	return s, nil
}
