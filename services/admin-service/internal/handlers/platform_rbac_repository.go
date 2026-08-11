package handlers

import (
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

// platformRoleRow is a platform role plus its denormalized user count, as read
// by the roles list/detail queries. A role's permission names are fetched
// separately via RolePermissionNames.
type platformRoleRow struct {
	models.PlatformRole
	UserCount int
}

// platformRBACStore is the data dependency of the platform RBAC handlers
// (roles CRUD + the platform-permission reads). The concrete
// platformRBACRepository moves the previously-inline SQL verbatim; the
// interface lets the handlers be contract-tested with an in-memory stub and no
// database. See platform_rbac_contract_test.go.
type platformRBACStore interface {
	ListRoles() ([]platformRoleRow, error)
	GetRole(id string) (platformRoleRow, error)
	RolePermissionNames(roleID string) ([]string, error)
	CreateRole(name, displayName, description string) (id string, createdAt, updatedAt time.Time, err error)
	UpdateRoleFields(id string, displayName, description *string) error
	RoleIsSystem(id string) (bool, error)
	DeleteRole(id string) error
	SetRolePermissions(roleID string, permissionIDs []string) error
	ListPermissions() ([]models.PlatformPermission, error)
	GetPermission(id string) (models.PlatformPermission, error)
}

// userPermissionProvider is the one-method dependency of
// GetCurrentUserPermissions; *rbac.RBACService satisfies it. Extracted so the
// handler is stub-testable without an RBAC service or database.
type userPermissionProvider interface {
	GetPlatformUserPermissions(userID uuid.UUID) ([]*models.PlatformPermission, error)
}

type platformRBACRepository struct{ db *sql.DB }

// NewPlatformRBACStore builds the production store backed by *sql.DB.
func NewPlatformRBACStore(db *sql.DB) platformRBACStore {
	return &platformRBACRepository{db: db}
}

func (r *platformRBACRepository) ListRoles() ([]platformRoleRow, error) {
	query := `
			SELECT pr.id, pr.name, pr.display_name, pr.description, pr.is_system_role,
			       pr.created_at, pr.updated_at,
			       COALESCE(COUNT(DISTINCT pu.id), 0) as user_count
			FROM platform_roles pr
			LEFT JOIN platform_users pu ON pu.role_id = pr.id AND pu.deleted_at IS NULL
			GROUP BY pr.id, pr.name, pr.display_name, pr.description, pr.is_system_role,
			         pr.created_at, pr.updated_at
			ORDER BY pr.created_at ASC
		`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var roles []platformRoleRow
	for rows.Next() {
		var role platformRoleRow
		if err := rows.Scan(
			&role.ID, &role.Name, &role.DisplayName, &role.Description,
			&role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt,
			&role.UserCount,
		); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (r *platformRBACRepository) GetRole(id string) (platformRoleRow, error) {
	var role platformRoleRow
	query := `
			SELECT pr.id, pr.name, pr.display_name, pr.description, pr.is_system_role,
			       pr.created_at, pr.updated_at,
			       COALESCE(COUNT(DISTINCT pu.id), 0) as user_count
			FROM platform_roles pr
			LEFT JOIN platform_users pu ON pu.role_id = pr.id AND pu.deleted_at IS NULL
			WHERE pr.id = $1
			GROUP BY pr.id, pr.name, pr.display_name, pr.description, pr.is_system_role,
			         pr.created_at, pr.updated_at
		`

	err := r.db.QueryRow(query, id).Scan(
		&role.ID, &role.Name, &role.DisplayName, &role.Description,
		&role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt,
		&role.UserCount,
	)
	return role, err
}

func (r *platformRBACRepository) RolePermissionNames(roleID string) ([]string, error) {
	permissionsQuery := `
				SELECT pp.name
				FROM platform_permissions pp
				JOIN platform_role_permissions prp ON pp.id = prp.permission_id
				WHERE prp.role_id = $1
				ORDER BY pp.name
			`
	permRows, err := r.db.Query(permissionsQuery, roleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = permRows.Close() }()
	var permissions []string
	for permRows.Next() {
		var permName string
		if err := permRows.Scan(&permName); err == nil {
			permissions = append(permissions, permName)
		}
	}
	return permissions, nil
}

func (r *platformRBACRepository) CreateRole(name, displayName, description string) (string, time.Time, time.Time, error) {
	query := `
			INSERT INTO platform_roles (name, display_name, description, is_system_role)
			VALUES ($1, $2, $3, false)
			RETURNING id, created_at, updated_at
		`

	var roleID string
	var createdAt, updatedAt time.Time
	err := r.db.QueryRow(query, name, displayName, description).
		Scan(&roleID, &createdAt, &updatedAt)
	return roleID, createdAt, updatedAt, err
}

func (r *platformRBACRepository) UpdateRoleFields(id string, displayName, description *string) error {
	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}
	argIndex := 1

	if displayName != nil {
		updates = append(updates, "display_name = $"+strconv.Itoa(argIndex))
		args = append(args, *displayName)
		argIndex++
	}
	if description != nil {
		updates = append(updates, "description = $"+strconv.Itoa(argIndex))
		args = append(args, *description)
		argIndex++
	}

	updates = append(updates, "updated_at = NOW()")
	args = append(args, id)

	query := "UPDATE platform_roles SET " + strings.Join(updates, ", ") + " WHERE id = $" + strconv.Itoa(argIndex) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice

	_, err := r.db.Exec(query, args...)
	return err
}

func (r *platformRBACRepository) RoleIsSystem(id string) (bool, error) {
	var isSystemRole bool
	err := r.db.QueryRow("SELECT is_system_role FROM platform_roles WHERE id = $1", id).Scan(&isSystemRole)
	return isSystemRole, err
}

func (r *platformRBACRepository) DeleteRole(id string) error {
	_, err := r.db.Exec("DELETE FROM platform_roles WHERE id = $1", id)
	return err
}

// SetRolePermissions replaces a role's permission set transactionally: it
// clears every existing platform_role_permissions row for the role, then
// inserts one row per supplied permission id. An empty permissionIDs slice
// clears the role entirely. Insert failures (e.g. an unknown permission id
// violating the FK to platform_permissions(id)) roll the whole change back.
func (r *platformRBACRepository) SetRolePermissions(roleID string, permissionIDs []string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	// Roll back on any early return; a no-op after a successful Commit.
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM platform_role_permissions WHERE role_id = $1", roleID); err != nil {
		return err
	}

	if len(permissionIDs) > 0 {
		// Single multi-row INSERT: VALUES ($1,$2),($1,$3),...
		args := make([]interface{}, 0, len(permissionIDs)+1)
		args = append(args, roleID)
		valueClauses := make([]string, 0, len(permissionIDs))
		for i, permID := range permissionIDs {
			valueClauses = append(valueClauses, "($1, $"+strconv.Itoa(i+2)+")")
			args = append(args, permID)
		}
		query := "INSERT INTO platform_role_permissions (role_id, permission_id) VALUES " + strings.Join(valueClauses, ", ") //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
		if _, err := tx.Exec(query, args...); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *platformRBACRepository) ListPermissions() ([]models.PlatformPermission, error) {
	query := `
			SELECT id, name, resource, action, description, created_at
			FROM platform_permissions
			ORDER BY resource, action
		`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var permissions []models.PlatformPermission
	for rows.Next() {
		var permission models.PlatformPermission
		if err := rows.Scan(
			&permission.ID, &permission.Name, &permission.Resource, &permission.Action,
			&permission.Description, &permission.CreatedAt,
		); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func (r *platformRBACRepository) GetPermission(id string) (models.PlatformPermission, error) {
	var permission models.PlatformPermission
	query := `
			SELECT id, name, resource, action, description, created_at
			FROM platform_permissions
			WHERE id = $1
		`

	err := r.db.QueryRow(query, id).Scan(
		&permission.ID, &permission.Name, &permission.Resource, &permission.Action,
		&permission.Description, &permission.CreatedAt,
	)
	return permission, err
}
