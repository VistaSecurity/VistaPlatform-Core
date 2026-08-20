package rbac

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// DelegatedPermissionNames resolves which permission names the actor is allowed
// to hand over by ASSIGNING roleID to a user, despite not holding them.
//
// It is the enforcement half of RoleDelegations (role_delegations_gen.go,
// generated from standards/permissions.yaml). The table says WHICH pairings
// are exempt; this says whether THIS call is one of them. Everything not
// matched here stays subject to the unchanged rule that an actor cannot grant
// a permission it does not hold.
//
// Four conditions must all hold, and each one closes a specific way the
// carve-out could be turned into a general loosening:
//
//  1. The grantee role is the tenant's own (id AND tenant_id), so a role id
//     from another tenant cannot be laundered through the exception.
//  2. The grantee role is a SYSTEM role. A tenant-created role that merely
//     shares the name is not the role the exception was written about.
//  3. The actor holds the grantor role, actively, IN THIS TENANT and as a
//     system role. Being tenant_admin of tenant A says nothing about tenant B
//     — the tenant_id conjunct is what makes that true, so keep it attached.
//  4. The permission is named in that pairing's Permissions list.
//
// Returns an empty set (never an error) when no pairing applies, which is the
// pre-existing behaviour: the caller then denies exactly as it did before.
func DelegatedPermissionNames(
	ctx context.Context, tx *sql.Tx, tenantID, actorID, granteeRoleID uuid.UUID,
) (map[string]struct{}, error) {
	if len(RoleDelegations) == 0 {
		return nil, nil
	}

	// (1) + (2) — the grantee role, resolved inside this tenant only.
	var granteeName string
	var granteeIsSystem bool
	err := tx.QueryRowContext(ctx, `
		SELECT name, is_system_role FROM tenant_roles
		WHERE id = $1 AND tenant_id = $2
	`, granteeRoleID, tenantID).Scan(&granteeName, &granteeIsSystem)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("resolve delegation grantee role: %w", err)
	}
	if !granteeIsSystem {
		return nil, nil
	}

	// Cheap exit before touching the DB again: no pairing can name this role.
	applicable := make([]RoleDelegation, 0, len(RoleDelegations))
	for _, d := range RoleDelegations {
		if d.GranteeRole == granteeName {
			applicable = append(applicable, d)
		}
	}
	if len(applicable) == 0 {
		return nil, nil
	}

	// (3) — the actor's active SYSTEM roles in THIS tenant. The r.tenant_id
	// conjunct is the tenant scoping; TestIntegration_RoleDelegation_*
	// CrossTenant proves the exemption disappears when it does not match.
	rows, err := tx.QueryContext(ctx, `
		SELECT r.name
		FROM tenant_roles r
		JOIN user_tenant_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1 AND r.tenant_id = $2
		  AND r.is_system_role = true AND ur.is_active = true
	`, actorID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve delegation grantor roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	actorRoles := map[string]struct{}{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan delegation grantor role: %w", err)
		}
		actorRoles[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// (4) — the named permissions of every pairing that matched.
	out := map[string]struct{}{}
	for _, d := range applicable {
		if _, ok := actorRoles[d.GrantorRole]; !ok {
			continue
		}
		for _, name := range d.Permissions {
			out[name] = struct{}{}
		}
	}
	return out, nil
}
