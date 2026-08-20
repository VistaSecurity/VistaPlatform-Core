package rbac

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/google/uuid"
)

// ValidateRoleGrantable refuses to let actorID cause roleID to be handed to
// anyone when the role holds a permission the actor does not personally hold.
// It is the role-ASSIGNMENT half of the escalation guard (the permission-set
// half is RBACService.validateGrantable).
//
// It lives here, rather than beside one of its callers, because there is more
// than one way to arm a role assignment and every one of them has to answer the
// same question the same way:
//
//	internal/api/users.go   direct assignment / invitation (the actor names a user)
//	ee/sso/tenant_sso.go    SSO provider config (the actor names an IdP group or
//	                        a default role, and the IdP names the user later)
//
// A second, subtly different copy is how the SSO path came to have no ceiling
// at all. Callers differ only in WHERE the role id came from; what makes a role
// grantable is this function.
//
// Two conditions:
//
//  1. roleID is the tenant's own role. A role id belonging to another tenant is
//     ErrRoleNotInTenant, never "grantable because we could not read its
//     grants" — the permission read below is keyed on role_id alone, so an
//     unscoped id would otherwise resolve to a foreign role's permissions (or,
//     under RLS, to no rows at all, which reads as "holds nothing" and passes).
//  2. Every permission the role holds is one the actor holds too.
//
// The one documented relaxation to (2) is DelegatedPermissionNames: a specific,
// named (grantor role, grantee role) pairing may carry a specific, named
// permission across the guard. Nothing else is exempt, and no role gains a
// permission it did not have.
func ValidateRoleGrantable(ctx context.Context, tx *sql.Tx, tenantID, actorID, roleID uuid.UUID) error {
	// (1) The role must be this tenant's. Checked before the grant read, so a
	// foreign role can never reach the permission comparison.
	var ownerTenant uuid.UUID
	err := tx.QueryRowContext(ctx, `
		SELECT tenant_id FROM tenant_roles WHERE id = $1
	`, roleID).Scan(&ownerTenant)
	if err == sql.ErrNoRows {
		return ErrRoleNotInTenant
	}
	if err != nil {
		return fmt.Errorf("resolve role tenant: %w", err)
	}
	if ownerTenant != tenantID {
		return ErrRoleNotInTenant
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT p.id, p.name
		FROM tenant_role_permissions rp
		JOIN tenant_permissions p ON p.id = rp.permission_id
		WHERE rp.role_id = $1
	`, roleID)
	if err != nil {
		return fmt.Errorf("read role grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	rolePermissions := map[uuid.UUID]string{}
	permissionIDs := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return fmt.Errorf("scan role grant: %w", err)
		}
		rolePermissions[id] = name
		permissionIDs = append(permissionIDs, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(permissionIDs) == 0 {
		return nil
	}

	// Named role-delegation exceptions (standards/permissions.yaml ->
	// RoleDelegations). Empty for every pairing but the ones listed there, so
	// the guard below is unchanged for everything else.
	delegated, err := DelegatedPermissionNames(ctx, tx, tenantID, actorID, roleID)
	if err != nil {
		return err
	}

	heldRows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT p.id
		FROM tenant_permissions p
		JOIN tenant_role_permissions rp ON p.id = rp.permission_id
		JOIN tenant_roles r ON rp.role_id = r.id
		JOIN user_tenant_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2 AND ur.is_active = true
	`, actorID, tenantID)
	if err != nil {
		return fmt.Errorf("resolve caller permissions: %w", err)
	}
	defer func() { _ = heldRows.Close() }()

	held := map[uuid.UUID]struct{}{}
	for heldRows.Next() {
		var id uuid.UUID
		if err := heldRows.Scan(&id); err != nil {
			return fmt.Errorf("scan caller permission: %w", err)
		}
		held[id] = struct{}{}
	}
	if err := heldRows.Err(); err != nil {
		return err
	}

	var denied []string
	for _, id := range permissionIDs {
		if _, ok := held[id]; ok {
			continue
		}
		if _, exempt := delegated[rolePermissions[id]]; exempt {
			continue
		}
		denied = append(denied, rolePermissions[id])
	}
	if len(denied) > 0 {
		sort.Strings(denied)
		return &ErrPermissionNotHeld{Names: denied}
	}
	return nil
}
