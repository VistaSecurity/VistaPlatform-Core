package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ErrRoleNotInTenant is returned by the role-scoped RBAC operations when the
// target role does not belong to the caller's tenant. Handlers map it to
// 404 so a cross-tenant roleId can't read or rewrite another tenant's role even
// if the path-level guard is ever bypassed.
var ErrRoleNotInTenant = errors.New("role does not belong to tenant")

// ErrSystemRoleImmutable is returned when a write targets a role with
// is_system_role = true. This is not a policy preference: the reconciliation DO
// block in scripts/database/seed.sql (and assignRolePermissions in
// internal/auth/service.go) re-assert the canonical grant set for every system
// role on EVERY helm upgrade and every ensureTenantRoles() call. Accepting such
// a write would report success and then be silently reverted. Handlers map this
// to 403 — the same answer the platform-admin side gives
// (services/admin-service/internal/handlers/roles.go).
var ErrSystemRoleImmutable = errors.New("system roles are read-only")

// ErrRoleNameConflict is returned when a custom role name collides with an
// existing role in the same tenant (unique constraint tenant_roles_tenant_id_name_key).
var ErrRoleNameConflict = errors.New("a role with that name already exists")

// ErrInvalidRoleName is returned when the supplied (or derived) role slug does
// not match roleNamePattern.
var ErrInvalidRoleName = errors.New("invalid role name")

// ErrRoleReferencedBySSO is returned when a delete would silently damage SSO
// provisioning. sso_group_role_mappings.role_id cascades on delete and
// sso_providers.default_role_id is SET NULL, so dropping a referenced role would
// quietly stop assigning roles to federated users. Blocked, with the reference
// named, rather than cascading.
var ErrRoleReferencedBySSO = errors.New("role is referenced by SSO configuration")

// ErrUnknownPermissions is returned when a request names permission ids that are
// not in the tenant_permissions catalogue. This is the outer escalation guard:
// no grant can be minted that the catalogue does not define.
type ErrUnknownPermissions struct {
	IDs []uuid.UUID
}

func (e *ErrUnknownPermissions) Error() string {
	return fmt.Sprintf("unknown permission ids: %v", e.IDs)
}

// ErrPermissionNotHeld is returned when the caller tries to ADD a permission
// they do not personally hold. Without this, `users.manage` would be a de facto
// superuser permission: its holder could mint a role carrying any permission and
// assign it to themselves via POST /tenant/:id/users/:uid/roles, which is gated
// on the same `users.manage`. The seeded role design deliberately withholds
// `billing.update` from tenant_admin; without this guard that separation is two
// API calls away from being undone.
//
// The guard applies only to the ADDED delta — a caller editing a role that
// already grants something they lack may leave it in place, and may always
// remove grants.
type ErrPermissionNotHeld struct {
	Names []string
}

func (e *ErrPermissionNotHeld) Error() string {
	return fmt.Sprintf("caller does not hold permission(s): %s", strings.Join(e.Names, ", "))
}

// ErrRoleInUse is returned when a delete is attempted on a role that users still
// hold and no reassignment target was supplied.
type ErrRoleInUse struct {
	UserCount int
}

func (e *ErrRoleInUse) Error() string {
	return fmt.Sprintf("role is held by %d user(s)", e.UserCount)
}

// roleNamePattern constrains the stable internal slug. Lowercase so it can never
// collide with a system role by case alone, and bounded at 50 to match
// tenant_roles.name varchar(50).
var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,49}$`)

// roleMetaRow is the identity of a role, used by every role-scoped operation to
// establish tenant ownership and system-role status in one read.
type roleMetaRow struct {
	Name         string
	DisplayName  string
	Description  string
	IsSystemRole bool
}

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
	// permission_count / user_count are computed here because the Roles &
	// Permissions list renders both. The page previously read them off the
	// never-populated `permissions` map and therefore always showed "—".
	query := `
		SELECT r.id, r.name, r.display_name, COALESCE(r.description, ''),
		       COALESCE(r.is_system_role, false),
		       (SELECT COUNT(*) FROM tenant_role_permissions rp WHERE rp.role_id = r.id),
		       (SELECT COUNT(*) FROM user_tenant_roles ur
		          WHERE ur.role_id = r.id AND ur.tenant_id = r.tenant_id AND ur.is_active = true),
		       r.created_at, r.updated_at
		FROM tenant_roles r
		WHERE r.tenant_id = $1
		ORDER BY r.is_system_role DESC, r.name`

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
				&role.ID, &role.Name, &role.DisplayName, &role.Description,
				&role.IsSystemRole, &role.PermissionCount, &role.UserCount,
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

// roleMeta resolves roleID's identity WITHIN tenantID. This is the tenant
// filter that keeps the role-scoped operations from touching another tenant's
// role even if a handler forgets the path guard: a role belonging to a different
// tenant produces no row and therefore ErrRoleNotInTenant, indistinguishable
// from "no such role".
func (s *RBACService) roleMeta(ctx context.Context, tx *sql.Tx, tenantID, roleID uuid.UUID) (roleMetaRow, error) {
	var m roleMetaRow
	err := tx.QueryRowContext(ctx, `
		SELECT name, display_name, COALESCE(description, ''), COALESCE(is_system_role, false)
		FROM tenant_roles WHERE id = $1 AND tenant_id = $2
	`, roleID, tenantID).Scan(&m.Name, &m.DisplayName, &m.Description, &m.IsSystemRole)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrRoleNotInTenant
	}
	if err != nil {
		return m, fmt.Errorf("resolve role: %w", err)
	}
	return m, nil
}

// callerPermissionIDs returns the permission ids the acting user effectively
// holds in this tenant — the ceiling for what they may grant. Runs on the caller's
// transaction so it shares the tenant context already set by WithTenantTx.
func (s *RBACService) callerPermissionIDs(ctx context.Context, tx *sql.Tx, tenantID, actorID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT p.id
		FROM tenant_permissions p
		JOIN tenant_role_permissions rp ON p.id = rp.permission_id
		JOIN tenant_roles r ON rp.role_id = r.id
		JOIN user_tenant_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2 AND ur.is_active = true
	`, actorID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve caller permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	held := make(map[uuid.UUID]struct{})
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan caller permission: %w", err)
		}
		held[id] = struct{}{}
	}
	return held, rows.Err()
}

// grantedPermissionIDs returns the permission ids currently granted to a role.
func grantedPermissionIDs(ctx context.Context, tx *sql.Tx, roleID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT permission_id FROM tenant_role_permissions WHERE role_id = $1`, roleID)
	if err != nil {
		return nil, fmt.Errorf("read role grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	granted := make(map[uuid.UUID]struct{})
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan role grant: %w", err)
		}
		granted[id] = struct{}{}
	}
	return granted, rows.Err()
}

func permissionIDSetToSlice(set map[uuid.UUID]struct{}) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	return out
}

// validateGrantable enforces the two escalation guards, in order:
//
//  1. Catalogue bound — every requested id must exist in tenant_permissions.
//     Nothing outside the catalogue can ever be minted into a role.
//  2. Caller bound — the caller may only ADD permissions they personally hold.
//     Permissions already on the role are exempt (so an admin can edit a role
//     without being forced to drop grants they lack), and removals are always
//     allowed.
//
// `wanted` is the requested set; `current` is the role's existing grants.
//
// `delegated` is the set of permission NAMES exempted from guard (2) by a named
// role-delegation exception (see role_delegations_gen.go). It is passed nil by
// every caller that EDITS a role's permission set — minting a permission onto a
// role is not delegating a role, and the exception must not reach it. Only
// AssignUserRole, which hands an existing role to a user, supplies one.
func (s *RBACService) validateGrantable(
	ctx context.Context, tx *sql.Tx, tenantID, actorID uuid.UUID,
	wanted []uuid.UUID, current map[uuid.UUID]struct{}, delegated map[string]struct{},
) error {
	if len(wanted) == 0 {
		return nil
	}

	// (1) Catalogue bound.
	known := make(map[uuid.UUID]string, len(wanted))
	rows, err := tx.QueryContext(ctx,
		`SELECT id, name FROM tenant_permissions WHERE id = ANY($1)`, pq.Array(wanted))
	if err != nil {
		return fmt.Errorf("resolve permission catalogue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return fmt.Errorf("scan permission catalogue: %w", err)
		}
		known[id] = name
	}
	if err := rows.Err(); err != nil {
		return err
	}

	var unknown []uuid.UUID
	for _, id := range wanted {
		if _, ok := known[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		return &ErrUnknownPermissions{IDs: unknown}
	}

	// (2) Caller bound — only over the ADDED delta.
	var added []uuid.UUID
	for _, id := range wanted {
		if _, alreadyGranted := current[id]; !alreadyGranted {
			added = append(added, id)
		}
	}
	if len(added) == 0 {
		return nil
	}

	held, err := s.callerPermissionIDs(ctx, tx, tenantID, actorID)
	if err != nil {
		return err
	}
	var denied []string
	for _, id := range added {
		if _, ok := held[id]; ok {
			continue
		}
		if _, exempt := delegated[known[id]]; exempt {
			continue
		}
		denied = append(denied, known[id])
	}
	if len(denied) > 0 {
		sort.Strings(denied)
		return &ErrPermissionNotHeld{Names: denied}
	}
	return nil
}

// GetPermissionMatrix returns the FULL tenant permission catalogue annotated with
// which entries this role grants and which the caller may switch on. Returns
// ErrRoleNotInTenant when the role is not the tenant's.
func (s *RBACService) GetPermissionMatrix(tenantID, roleID, actorID uuid.UUID) (*PermissionMatrix, error) {
	ctx := context.Background()
	var out *PermissionMatrix

	// RLS-scoped: tenant_roles and user_tenant_roles carry tenant_isolation
	// policies; tenant_permissions / tenant_role_permissions are global.
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		meta, err := s.roleMeta(ctx, tx, tenantID, roleID)
		if err != nil {
			return err
		}

		held, err := s.callerPermissionIDs(ctx, tx, tenantID, actorID)
		if err != nil {
			return err
		}

		rows, err := tx.QueryContext(ctx, `
			SELECT p.id, p.name, COALESCE(p.description, ''), p.resource, p.action,
			       (rp.permission_id IS NOT NULL) AS granted
			FROM tenant_permissions p
			LEFT JOIN tenant_role_permissions rp
			  ON rp.permission_id = p.id AND rp.role_id = $1
			ORDER BY p.resource, p.action`, roleID)
		if err != nil {
			return fmt.Errorf("read permission matrix: %w", err)
		}
		defer func() { _ = rows.Close() }()

		m := &PermissionMatrix{
			RoleID:               roleID,
			RoleName:             meta.Name,
			DisplayName:          meta.DisplayName,
			Description:          meta.Description,
			IsSystemRole:         meta.IsSystemRole,
			Editable:             !meta.IsSystemRole,
			Permissions:          []MatrixPermission{},
			GrantedPermissionIDs: []uuid.UUID{},
		}
		for rows.Next() {
			var p MatrixPermission
			if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.Granted); err != nil {
				return fmt.Errorf("scan permission matrix row: %w", err)
			}
			_, p.Grantable = held[p.ID]
			m.Permissions = append(m.Permissions, p)
			if p.Granted {
				m.GrantedPermissionIDs = append(m.GrantedPermissionIDs, p.ID)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		out = m
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateRolePermissions REPLACES a role's grant set with permissionIDs, in one
// transaction. An empty slice clears every grant.
//
// Refusals, in order: cross-tenant role (ErrRoleNotInTenant), system role
// (ErrSystemRoleImmutable), permission outside the catalogue
// (*ErrUnknownPermissions), permission the caller does not hold
// (*ErrPermissionNotHeld).
func (s *RBACService) UpdateRolePermissions(tenantID, roleID, actorID uuid.UUID, permissionIDs []uuid.UUID) error {
	ctx := context.Background()

	// RLS-scoped write: the DELETE/INSERT join tenant_roles (tenant_isolation)
	// to resolve the role, so app.tenant_id must be set on this transaction.
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		meta, err := s.roleMeta(ctx, tx, tenantID, roleID)
		if err != nil {
			return err
		}
		if meta.IsSystemRole {
			return ErrSystemRoleImmutable
		}

		current, err := grantedPermissionIDs(ctx, tx, roleID)
		if err != nil {
			return err
		}
		// nil delegations: this REWRITES a role's permission set. A delegation
		// lets an actor hand over a role, not mint the permission elsewhere.
		if err := s.validateGrantable(ctx, tx, tenantID, actorID, permissionIDs, current, nil); err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx,
			`DELETE FROM tenant_role_permissions WHERE role_id = $1`, roleID); err != nil {
			return fmt.Errorf("clear role permissions: %w", err)
		}
		if len(permissionIDs) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_role_permissions (role_id, permission_id)
			SELECT $1, unnest($2::uuid[])
			ON CONFLICT (role_id, permission_id) DO NOTHING
		`, roleID, pq.Array(permissionIDs)); err != nil {
			return fmt.Errorf("assign role permissions: %w", err)
		}
		return nil
	})
}

// CreateTenantRole creates a custom (is_system_role = false) role and its initial
// grants in one transaction. Custom roles are safe across upgrades: every
// reconciliation statement in scripts/database/seed.sql is qualified with
// `AND is_system_role = true`.
func (s *RBACService) CreateTenantRole(tenantID, actorID uuid.UUID, req CreateRoleRequest) (*Role, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = slugifyRoleName(req.DisplayName)
	}
	name = strings.ToLower(name)
	if !roleNamePattern.MatchString(name) {
		return nil, ErrInvalidRoleName
	}

	permissionIDs := make([]uuid.UUID, 0, len(req.PermissionIDs))
	for _, raw := range req.PermissionIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPermissionID, raw)
		}
		permissionIDs = append(permissionIDs, id)
	}

	ctx := context.Background()
	var out *Role

	// RLS-scoped write: tenant_roles carries tenant_isolation, so app.tenant_id
	// must satisfy the policy WITH CHECK on the INSERT.
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		// nil delegations: same reason as UpdateRolePermissions — a new custom
		// role is a place to mint permissions, not a role being handed over.
		if err := s.validateGrantable(ctx, tx, tenantID, actorID, permissionIDs, map[uuid.UUID]struct{}{}, nil); err != nil {
			return err
		}

		role := Role{
			Name:            name,
			DisplayName:     strings.TrimSpace(req.DisplayName),
			Description:     strings.TrimSpace(req.Description),
			IsSystemRole:    false,
			PermissionCount: len(permissionIDs),
		}
		err := tx.QueryRowContext(ctx, `
			INSERT INTO tenant_roles (tenant_id, name, display_name, description, is_system_role)
			VALUES ($1, $2, $3, $4, false)
			RETURNING id, created_at, updated_at
		`, tenantID, role.Name, role.DisplayName, role.Description).
			Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrRoleNameConflict
			}
			return fmt.Errorf("create tenant role: %w", err)
		}

		if len(permissionIDs) > 0 {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO tenant_role_permissions (role_id, permission_id)
				SELECT $1, unnest($2::uuid[])
				ON CONFLICT (role_id, permission_id) DO NOTHING
			`, role.ID, pq.Array(permissionIDs)); err != nil {
				return fmt.Errorf("assign new role permissions: %w", err)
			}
		}
		out = &role
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteTenantRole deletes a custom role.
//
// Delete semantics: a role that users still hold is REFUSED (*ErrRoleInUse)
// unless the caller names a reassignment target. Silently moving people to
// another role would change who can do what as a side effect of a delete; making
// the caller name the destination keeps that an explicit act. When reassignTo is
// supplied, holders are moved to it — skipping users who already hold the target,
// exactly as the analyst retirement in scripts/database/seed.sql does, because
// user_tenant_roles is unique on (user_id, tenant_id, role_id).
//
// A role wired into SSO is refused outright (ErrRoleReferencedBySSO): the FKs
// there cascade-delete group mappings and NULL a provider's default role, which
// would silently stop provisioning federated users.
func (s *RBACService) DeleteTenantRole(tenantID, roleID uuid.UUID, reassignTo *uuid.UUID) (*DeleteRoleResult, error) {
	ctx := context.Background()
	var out *DeleteRoleResult

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		meta, err := s.roleMeta(ctx, tx, tenantID, roleID)
		if err != nil {
			return err
		}
		if meta.IsSystemRole {
			return ErrSystemRoleImmutable
		}

		var ssoRefs int
		if err := tx.QueryRowContext(ctx, `
			SELECT (SELECT COUNT(*) FROM sso_group_role_mappings WHERE role_id = $1 AND tenant_id = $2)
			     + (SELECT COUNT(*) FROM sso_providers WHERE default_role_id = $1 AND tenant_id = $2)
		`, roleID, tenantID).Scan(&ssoRefs); err != nil {
			return fmt.Errorf("check sso references: %w", err)
		}
		if ssoRefs > 0 {
			return ErrRoleReferencedBySSO
		}

		var holders int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM user_tenant_roles
			WHERE role_id = $1 AND tenant_id = $2 AND is_active = true
		`, roleID, tenantID).Scan(&holders); err != nil {
			return fmt.Errorf("count role holders: %w", err)
		}

		result := &DeleteRoleResult{RoleID: roleID}

		if holders > 0 {
			if reassignTo == nil {
				return &ErrRoleInUse{UserCount: holders}
			}
			target, err := s.roleMeta(ctx, tx, tenantID, *reassignTo)
			if err != nil {
				return err
			}
			if *reassignTo == roleID {
				return ErrReassignToSelf
			}
			res, err := tx.ExecContext(ctx, `
				UPDATE user_tenant_roles utr
				SET role_id = $1
				WHERE utr.tenant_id = $2 AND utr.role_id = $3
				  AND NOT EXISTS (
				    SELECT 1 FROM user_tenant_roles u2
				    WHERE u2.user_id = utr.user_id AND u2.tenant_id = utr.tenant_id AND u2.role_id = $1
				  )
			`, *reassignTo, tenantID, roleID)
			if err != nil {
				return fmt.Errorf("reassign role holders: %w", err)
			}
			moved, err := res.RowsAffected()
			if err != nil {
				return err
			}
			result.ReassignedUsers = int(moved)
			result.ReassignedToID = reassignTo
			result.ReassignedToName = target.Name
		}

		// Drop whatever assignments remain — users who already held the target
		// role (so the UPDATE skipped them), plus any inactive assignments.
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM user_tenant_roles WHERE role_id = $1 AND tenant_id = $2`, roleID, tenantID); err != nil {
			return fmt.Errorf("clear role assignments: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM tenant_role_permissions WHERE role_id = $1`, roleID); err != nil {
			return fmt.Errorf("clear role permissions: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM tenant_roles WHERE id = $1 AND tenant_id = $2`, roleID, tenantID); err != nil {
			return fmt.Errorf("delete role: %w", err)
		}

		out = result
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrInvalidPermissionID is returned when a permission_id in a request body is
// not a UUID.
var ErrInvalidPermissionID = errors.New("invalid permission id")

// ErrReassignToSelf is returned when reassign_to names the role being deleted.
var ErrReassignToSelf = errors.New("reassign_to must be a different role")

// slugifyRoleName derives the stable internal name from a display name when the
// caller does not supply one: lowercase, non-alphanumerics folded to underscore.
func slugifyRoleName(display string) string {
	var b strings.Builder
	prevUnderscore := false
	for _, r := range strings.ToLower(strings.TrimSpace(display)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevUnderscore = false
		case !prevUnderscore && b.Len() > 0:
			b.WriteRune('_')
			prevUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if len(out) > 50 {
		out = strings.Trim(out[:50], "_")
	}
	return out
}

// isUniqueViolation reports whether err is a Postgres unique-constraint failure
// (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	// sqlmock and other drivers surface the constraint textually.
	return strings.Contains(strings.ToLower(err.Error()), "duplicate key value")
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
func (s *RBACService) AssignUserRole(tenantID, userID, roleID, actorID uuid.UUID) error {
	ctx := context.Background()
	// RLS-scoped: users, tenant_roles, and user_tenant_roles all carry
	// tenant_isolation policies. The tenant is known, so the user/role tenant
	// validation + the assignment run inside one WithTenantTx. The explicit
	// `!= tenantID` guards are kept as the primary control.
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		var userTenant uuid.UUID
		err := tx.QueryRowContext(ctx, `
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
		err = tx.QueryRowContext(ctx, `
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

		rolePermissions, err := grantedPermissionIDs(ctx, tx, roleID)
		if err != nil {
			return err
		}
		// This hands an EXISTING role to a user, so the named role-delegation
		// exceptions apply here (and only here, plus the equivalent guard in
		// internal/api/users.go). Empty for every pairing not listed in
		// standards/permissions.yaml.
		delegated, err := DelegatedPermissionNames(ctx, tx, tenantID, actorID, roleID)
		if err != nil {
			return err
		}
		if err := s.validateGrantable(ctx, tx, tenantID, actorID, permissionIDSetToSlice(rolePermissions), map[uuid.UUID]struct{}{}, delegated); err != nil {
			return err
		}

		if _, err = tx.ExecContext(ctx, `
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
