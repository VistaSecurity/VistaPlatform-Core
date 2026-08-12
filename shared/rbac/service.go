package rbac

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/models"
)

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

// GetDB returns the database connection
func (r *RBACService) GetDB() *sql.DB {
	return r.db
}

// CheckPermission checks if a user has a specific permission in a tenant
func (r *RBACService) CheckPermission(userID, tenantID uuid.UUID, permission string) (bool, error) {
	query := `
		SELECT user_has_permission($1, $2, $3)
	`

	var hasPermission bool
	err := r.db.QueryRow(query, userID, tenantID, permission).Scan(&hasPermission)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return hasPermission, nil
}

// CheckPlatformPermission checks if a platform user has a specific permission
func (r *RBACService) CheckPlatformPermission(userID uuid.UUID, permission string) (bool, error) {
	query := `
		SELECT platform_user_has_permission($1, $2)
	`

	var hasPermission bool
	err := r.db.QueryRow(query, userID, permission).Scan(&hasPermission)
	if err != nil {
		return false, fmt.Errorf("failed to check platform permission: %w", err)
	}

	return hasPermission, nil
}

// GetUserPermissions gets all permissions for a user in a tenant
func (r *RBACService) GetUserPermissions(userID, tenantID uuid.UUID) ([]*models.TenantPermission, error) {
	query := `
		SELECT tp.id, tp.name, tp.resource, tp.action, tp.scope, tp.description, tp.created_at
		FROM get_user_permissions($1, $2) gup
		JOIN tenant_permissions tp ON tp.name = gup.permission_name
	`

	rows, err := r.db.Query(query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.TenantPermission
	for rows.Next() {
		var perm models.TenantPermission
		err := rows.Scan(
			&perm.ID, &perm.Name, &perm.Resource, &perm.Action,
			&perm.Scope, &perm.Description, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, &perm)
	}

	return permissions, nil
}

// ---------------------------------------------------------------------------
// RLS WARNING for the tenant-scoped methods below.
//
// Everything from here down that touches tenant_roles, user_tenant_roles or
// permission_audit_logs issues raw SQL on r.db with no app.tenant_id set. Those
// tables are RLS-scoped, and every service constructs RBACService with the
// RLS-scoped crypto_app handle, so under enforced RLS these read zero rows and
// write zero rows — without error.
//
// They are NOT currently reachable: the live tenant RBAC surface is
// services/auth-service/internal/rbac, which wraps each of these in
// WithTenantTx correctly. The only shared-RBAC methods with production callers
// are CheckPermission and CheckPlatformPermission, and those are safe because
// they delegate to the SECURITY DEFINER functions user_has_permission() /
// get_user_permissions(), which run as the owner and are not subject to RLS.
//
// So this is dead code that is also wrong. Wire any of it up as-is and role
// listing/assignment silently becomes a no-op. Either delete this block in
// favour of the auth-service implementation, or wrap each method in
// WithTenantTx before using it.
// ---------------------------------------------------------------------------

// GetUserRoles gets all roles for a user in a tenant
func (r *RBACService) GetUserRoles(userID, tenantID uuid.UUID) ([]*models.TenantRole, error) {
	query := `
		SELECT tr.id, tr.tenant_id, tr.name, tr.display_name, tr.description, 
		       tr.is_system_role, tr.created_at, tr.updated_at
		FROM user_tenant_roles utr
		JOIN tenant_roles tr ON utr.role_id = tr.id
		WHERE utr.user_id = $1 AND utr.tenant_id = $2 AND utr.is_active = true
		  AND (utr.expires_at IS NULL OR utr.expires_at > NOW())
	`

	rows, err := r.db.Query(query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	var roles []*models.TenantRole
	for rows.Next() {
		var role models.TenantRole
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.DisplayName,
			&role.Description, &role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, &role)
	}

	return roles, nil
}

// AssignRole assigns a role to a user in a tenant
func (r *RBACService) AssignRole(req *models.RoleAssignmentRequest) error {
	// Check if user exists and belongs to tenant
	var userExists bool
	checkQuery := `
		SELECT EXISTS(
			SELECT 1 FROM users 
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		)
	`
	err := r.db.QueryRow(checkQuery, req.UserID, req.TenantID).Scan(&userExists)
	if err != nil {
		return fmt.Errorf("failed to check user existence: %w", err)
	}
	if !userExists {
		return fmt.Errorf("user does not exist or does not belong to tenant")
	}

	// Check if role exists and belongs to tenant
	var roleExists bool
	roleQuery := `
		SELECT EXISTS(
			SELECT 1 FROM tenant_roles 
			WHERE id = $1 AND tenant_id = $2
		)
	`
	err = r.db.QueryRow(roleQuery, req.RoleID, req.TenantID).Scan(&roleExists)
	if err != nil {
		return fmt.Errorf("failed to check role existence: %w", err)
	}
	if !roleExists {
		return fmt.Errorf("role does not exist or does not belong to tenant")
	}

	// Assign role
	assignQuery := `
		INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, assigned_by, assigned_at, expires_at, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, true)
		ON CONFLICT (user_id, tenant_id, role_id) 
		DO UPDATE SET 
			assigned_by = EXCLUDED.assigned_by,
			assigned_at = EXCLUDED.assigned_at,
			expires_at = EXCLUDED.expires_at,
			is_active = true
	`

	_, err = r.db.Exec(assignQuery, req.UserID, req.TenantID, req.RoleID, req.AssignedBy, time.Now(), req.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// RemoveRole removes a role from a user in a tenant
func (r *RBACService) RemoveRole(userID, tenantID, roleID uuid.UUID) error {
	query := `
		UPDATE user_tenant_roles 
		SET is_active = false 
		WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3
	`

	result, err := r.db.Exec(query, userID, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("role assignment not found")
	}

	return nil
}

// GetTenantRoles gets all roles for a tenant
func (r *RBACService) GetTenantRoles(tenantID uuid.UUID) ([]*models.TenantRole, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, is_system_role, created_at, updated_at
		FROM tenant_roles
		WHERE tenant_id = $1
		ORDER BY is_system_role DESC, display_name ASC
	`

	rows, err := r.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant roles: %w", err)
	}
	defer rows.Close()

	var roles []*models.TenantRole
	for rows.Next() {
		var role models.TenantRole
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.DisplayName,
			&role.Description, &role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, &role)
	}

	return roles, nil
}

// GetTenantPermissions gets all available permissions
func (r *RBACService) GetTenantPermissions() ([]*models.TenantPermission, error) {
	query := `
		SELECT id, name, resource, action, scope, description, created_at
		FROM tenant_permissions
		ORDER BY resource, action
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.TenantPermission
	for rows.Next() {
		var perm models.TenantPermission
		err := rows.Scan(
			&perm.ID, &perm.Name, &perm.Resource, &perm.Action,
			&perm.Scope, &perm.Description, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, &perm)
	}

	return permissions, nil
}

// GetPermissionMatrix gets the permission matrix for a role
func (r *RBACService) GetPermissionMatrix(roleID uuid.UUID) (*models.PermissionMatrix, error) {
	// Get role info
	roleQuery := `
		SELECT id, name FROM tenant_roles WHERE id = $1
	`
	var roleIDCheck uuid.UUID
	var roleName string
	err := r.db.QueryRow(roleQuery, roleID).Scan(&roleIDCheck, &roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Get all permissions with grant status
	permissionsQuery := `
		SELECT 
			tp.id, tp.name, tp.resource, tp.action, tp.scope,
			COALESCE(trp.permission_id IS NOT NULL, false) as granted
		FROM tenant_permissions tp
		LEFT JOIN tenant_role_permissions trp ON tp.id = trp.permission_id AND trp.role_id = $1
		ORDER BY tp.resource, tp.action
	`

	rows, err := r.db.Query(permissionsQuery, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission matrix: %w", err)
	}
	defer rows.Close()

	matrix := &models.PermissionMatrix{
		RoleID:      roleID,
		RoleName:    roleName,
		Permissions: make([]models.PermissionDetail, 0),
	}

	for rows.Next() {
		var perm models.PermissionDetail

		err := rows.Scan(
			&perm.PermissionID, &perm.PermissionName, &perm.Resource,
			&perm.Action, &perm.Scope, &perm.Granted,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission matrix row: %w", err)
		}

		matrix.Permissions = append(matrix.Permissions, perm)
	}

	return matrix, nil
}

// UpdateRolePermissions updates the permissions for a role
func (r *RBACService) UpdateRolePermissions(roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Remove existing permissions
	_, err = tx.Exec("DELETE FROM tenant_role_permissions WHERE role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to remove existing permissions: %w", err)
	}

	// Add new permissions
	if len(permissionIDs) > 0 {
		insertQuery := `
			INSERT INTO tenant_role_permissions (role_id, permission_id, created_at)
			SELECT $1, unnest($2::uuid[]), NOW()
		`
		_, err = tx.Exec(insertQuery, roleID, pq.Array(permissionIDs))
		if err != nil {
			return fmt.Errorf("failed to insert new permissions: %w", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// LogPermissionCheck logs a permission check for audit purposes
func (r *RBACService) LogPermissionCheck(req *models.PermissionCheckRequest, granted bool) error {
	query := `
		INSERT INTO permission_audit_logs 
		(user_id, tenant_id, action, resource_type, resource_id, permission_required, permission_granted, ip_address, user_agent, created_at)
		VALUES ($1, $2, 'permission_check', $3, $4, $5, $6, $7, $8, NOW())
	`

	_, err := r.db.Exec(query, req.UserID, req.TenantID, req.Resource, req.ResourceID, req.Permission, granted, req.IPAddress, req.UserAgent)
	if err != nil {
		log.Printf("Failed to log permission check: %v", err)
		// Don't return error as this is just logging
	}

	return nil
}

// GetPlatformUsers gets all platform users
func (r *RBACService) GetPlatformUsers() ([]*models.PlatformUser, error) {
	query := `
		SELECT pu.id, pu.email, pu.first_name, pu.last_name, pu.role_id, 
		       pu.is_active, pu.email_verified, pu.last_login_at, pu.created_at, pu.updated_at,
		       pr.name as role_name, pr.display_name as role_display_name
		FROM platform_users pu
		JOIN platform_roles pr ON pu.role_id = pr.id
		WHERE pu.deleted_at IS NULL
		ORDER BY pu.created_at DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform users: %w", err)
	}
	defer rows.Close()

	var users []*models.PlatformUser
	for rows.Next() {
		var user models.PlatformUser
		var roleName, roleDisplayName string

		err := rows.Scan(
			&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.RoleID,
			&user.IsActive, &user.EmailVerified, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
			&roleName, &roleDisplayName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan platform user: %w", err)
		}

		user.Role = &models.PlatformRole{
			ID:          user.RoleID,
			Name:        roleName,
			DisplayName: roleDisplayName,
		}

		users = append(users, &user)
	}

	return users, nil
}

// GetPlatformRoles gets all platform roles
func (r *RBACService) GetPlatformRoles() ([]*models.PlatformRole, error) {
	query := `
		SELECT id, name, display_name, description, is_system_role, created_at, updated_at
		FROM platform_roles
		ORDER BY is_system_role DESC, display_name ASC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform roles: %w", err)
	}
	defer rows.Close()

	var roles []*models.PlatformRole
	for rows.Next() {
		var role models.PlatformRole
		err := rows.Scan(
			&role.ID, &role.Name, &role.DisplayName, &role.Description,
			&role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan platform role: %w", err)
		}
		roles = append(roles, &role)
	}

	return roles, nil
}

// GetPlatformPermissions gets all platform permissions
func (r *RBACService) GetPlatformPermissions() ([]*models.PlatformPermission, error) {
	query := `
		SELECT id, name, resource, action, description, created_at
		FROM platform_permissions
		ORDER BY resource, action
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.PlatformPermission
	for rows.Next() {
		var perm models.PlatformPermission
		err := rows.Scan(
			&perm.ID, &perm.Name, &perm.Resource, &perm.Action,
			&perm.Description, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan platform permission: %w", err)
		}
		permissions = append(permissions, &perm)
	}

	return permissions, nil
}

// GetPlatformUserPermissions gets all permissions for a platform user
func (r *RBACService) GetPlatformUserPermissions(userID uuid.UUID) ([]*models.PlatformPermission, error) {
	query := `
		SELECT DISTINCT pp.id, pp.name, pp.resource, pp.action, pp.description, pp.created_at
		FROM platform_users pu
		JOIN platform_roles pr ON pu.role_id = pr.id
		JOIN platform_role_permissions prp ON pr.id = prp.role_id
		JOIN platform_permissions pp ON prp.permission_id = pp.id
		WHERE pu.id = $1
		  AND pu.is_active = true
		  AND pu.deleted_at IS NULL
		ORDER BY pp.resource, pp.action
	`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.PlatformPermission
	for rows.Next() {
		var perm models.PlatformPermission
		err := rows.Scan(
			&perm.ID, &perm.Name, &perm.Resource, &perm.Action,
			&perm.Description, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan platform permission: %w", err)
		}
		permissions = append(permissions, &perm)
	}

	return permissions, nil
}
