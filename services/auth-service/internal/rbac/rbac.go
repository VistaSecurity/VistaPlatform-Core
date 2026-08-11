package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ErrRoleNotInTenant is returned by the role-scoped RBAC operations when the
// target role does not belong to the caller's tenant. Handlers map it to
// 404 so a cross-tenant roleId can't read or rewrite another tenant's role even
// if the path-level guard is ever bypassed.
var ErrRoleNotInTenant = errors.New("role does not belong to tenant")

// RBACService handles role-based access control operations
type RBACService struct {
	db *sql.DB
}

// NewRBACService creates a new RBAC service
func NewRBACService(db *sql.DB) *RBACService {
	return &RBACService{
		db: db,
	}
}

// GetTenantRoles returns all roles for a tenant
func (s *RBACService) GetTenantRoles(tenantID uuid.UUID) ([]Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM tenant_roles r
		WHERE r.tenant_id = $1
		ORDER BY r.name`

	// RLS-scoped read over tenant_roles (tenant_isolation policy); tenant is known.
	var roles []Role
	err := shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(context.Background(), query, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var role Role
			if scanErr := rows.Scan(
				&role.ID, &role.Name, &role.Description,
				&role.CreatedAt, &role.UpdatedAt,
			); scanErr != nil {
				return fmt.Errorf("failed to scan role: %w", scanErr)
			}
			roles = append(roles, role)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query tenant roles: %w", err)
	}

	return roles, nil
}

// GetTenantPermissions returns all permissions for a tenant
func (s *RBACService) GetTenantPermissions(tenantID uuid.UUID) ([]Permission, error) {
	// tenant_permissions is a GLOBAL reference table (no tenant_isolation policy);
	// the query has no tenant_id filter. Left unwrapped — there is no RLS to satisfy.
	query := `
		SELECT DISTINCT p.id, p.name, p.description, p.resource, p.action
		FROM tenant_permissions p
		ORDER BY p.resource, p.action`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tenant permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var permissions []Permission
	for rows.Next() {
		var perm Permission
		err := rows.Scan(
			&perm.ID, &perm.Name, &perm.Description,
			&perm.Resource, &perm.Action,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// roleBelongsToTenant reports whether roleID is a role of tenantID. This
// is the tenant filter that keeps the role-scoped operations from touching
// another tenant's role even if a handler forgets the path guard.
func (s *RBACService) roleBelongsToTenant(tenantID, roleID uuid.UUID) (bool, error) {
	// RLS-scoped read over tenant_roles (tenant_isolation policy); tenant is known.
	var exists bool
	err := shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(),
			`SELECT EXISTS(SELECT 1 FROM tenant_roles WHERE id = $1 AND tenant_id = $2)`,
			roleID, tenantID,
		).Scan(&exists)
	})
	if err != nil {
		return false, fmt.Errorf("check role tenant ownership: %w", err)
	}
	return exists, nil
}

// GetPermissionMatrix returns the permission matrix for a role within the
// caller's tenant. Returns ErrRoleNotInTenant when the role is not the tenant's.
func (s *RBACService) GetPermissionMatrix(tenantID, roleID uuid.UUID) (interface{}, error) {
	owned, err := s.roleBelongsToTenant(tenantID, roleID)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, ErrRoleNotInTenant
	}
	// Simple implementation - return empty matrix for now
	// In a full implementation, this would query the database for role permissions
	return map[string]interface{}{
		"role_id":     roleID,
		"permissions": []string{},
	}, nil
}

// UpdateRolePermissions updates permissions for a role within the caller's
// tenant. Returns ErrRoleNotInTenant when the role is not the tenant's, so a
// cross-tenant roleId can never be rewritten.
func (s *RBACService) UpdateRolePermissions(tenantID, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	owned, err := s.roleBelongsToTenant(tenantID, roleID)
	if err != nil {
		return err
	}
	if !owned {
		return ErrRoleNotInTenant
	}
	// Simple implementation - no-op for now
	// In a full implementation, this would update the database
	return nil
}

// GetUserRoles returns roles assigned to a user
func (s *RBACService) GetUserRoles(tenantID, userID uuid.UUID) ([]Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM tenant_roles r
		JOIN user_tenant_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2 AND ur.is_active = true
		ORDER BY r.name`

	// RLS-scoped read over tenant_roles + user_tenant_roles; tenant is known.
	var roles []Role
	err := shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(context.Background(), query, userID, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var role Role
			if scanErr := rows.Scan(
				&role.ID, &role.Name, &role.Description,
				&role.CreatedAt, &role.UpdatedAt,
			); scanErr != nil {
				return fmt.Errorf("failed to scan role: %w", scanErr)
			}
			role.Permissions = nil
			roles = append(roles, role)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}

	return roles, nil
}

// AssignUserRole adds or reactivates a tenant role for a user without removing their other roles.
func (s *RBACService) AssignUserRole(tenantID, userID, roleID uuid.UUID) error {
	// RLS-scoped: users, tenant_roles, and user_tenant_roles all carry
	// tenant_isolation policies. The tenant is known, so the user/role tenant
	// validation + the assignment run inside one WithTenantTx. The explicit
	// `!= tenantID` guards are kept as the primary control.
	return shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		var userTenant uuid.UUID
		err := tx.QueryRowContext(context.Background(), `
			SELECT tenant_id FROM users WHERE id = $1 AND deleted_at IS NULL
		`, userID).Scan(&userTenant)
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		if err != nil {
			return fmt.Errorf("failed to resolve user tenant: %w", err)
		}
		if userTenant != tenantID {
			return fmt.Errorf("user not in tenant")
		}

		var roleTenant uuid.UUID
		err = tx.QueryRowContext(context.Background(), `
			SELECT tenant_id FROM tenant_roles WHERE id = $1
		`, roleID).Scan(&roleTenant)
		if err == sql.ErrNoRows {
			return fmt.Errorf("role not found")
		}
		if err != nil {
			return fmt.Errorf("failed to resolve role tenant: %w", err)
		}
		if roleTenant != tenantID {
			return fmt.Errorf("role not in tenant")
		}

		if _, err = tx.ExecContext(context.Background(), `
			INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_at, is_active)
			VALUES ($1, $2, $3, NOW(), true)
			ON CONFLICT (user_id, tenant_id, role_id)
			DO UPDATE SET is_active = true, assigned_at = NOW(), expires_at = NULL
		`, userID, tenantID, roleID); err != nil {
			return fmt.Errorf("failed to assign role: %w", err)
		}
		return nil
	})
}

// RemoveUserRole deactivates a role assignment for a user in a tenant.
func (s *RBACService) RemoveUserRole(tenantID, userID, roleID uuid.UUID) error {
	// RLS-scoped write over user_tenant_roles (tenant_isolation policy); tenant
	// is known. The "not found" sentinel is surfaced via a typed error from fn.
	return shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(context.Background(), `
			UPDATE user_tenant_roles
			SET is_active = false
			WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3 AND is_active = true
		`, userID, tenantID, roleID)
		if err != nil {
			return fmt.Errorf("failed to remove role: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("active role assignment not found")
		}
		return nil
	})
}

// GetUserPermissions returns effective permissions for a user
func (s *RBACService) GetUserPermissions(tenantID, userID uuid.UUID) ([]Permission, error) {
	query := `
		SELECT DISTINCT p.id, p.name, p.description, p.resource, p.action
		FROM tenant_permissions p
		JOIN tenant_role_permissions rp ON p.id = rp.permission_id
		JOIN tenant_roles r ON rp.role_id = r.id
		JOIN user_tenant_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2 AND ur.is_active = true
		ORDER BY p.resource, p.action`

	// RLS-scoped: joins tenant_roles + user_tenant_roles (tenant_isolation
	// policies) with the global tenant_permissions/tenant_role_permissions tables;
	// tenant is known.
	var permissions []Permission
	err := shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(context.Background(), query, userID, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var perm Permission
			if scanErr := rows.Scan(
				&perm.ID, &perm.Name, &perm.Description,
				&perm.Resource, &perm.Action,
			); scanErr != nil {
				return fmt.Errorf("failed to scan permission: %w", scanErr)
			}
			permissions = append(permissions, perm)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query user permissions: %w", err)
	}

	return permissions, nil
}

// CheckPermission checks if a user has a specific permission
func (s *RBACService) CheckPermission(tenantID, userID uuid.UUID, permission string) (bool, error) {
	query := `
		SELECT COUNT(*) > 0
		FROM tenant_permissions p
		JOIN tenant_role_permissions rp ON p.id = rp.permission_id
		JOIN tenant_roles r ON rp.role_id = r.id
		JOIN user_tenant_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2 AND p.name = $3 AND ur.is_active = true`

	// RLS-scoped: joins tenant_roles + user_tenant_roles (tenant_isolation
	// policies); tenant is known.
	var hasPermission bool
	err := shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), query, userID, tenantID, permission).Scan(&hasPermission)
	})
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return hasPermission, nil
}
