package handlers

// Platform role assignment authorization.
//
// platform_users.role_id decides everything a platform operator can do, so
// writing it is a privilege grant, not a profile edit. Before this guard the
// three routes that write it (POST /admin/users, POST /admin/users/invite,
// PUT /admin/users/:id) checked only platform_users.manage — which the seed
// grants to platform_admin — so any platform_admin could make any account,
// including their own, super_admin. platform_roles.assign existed in the seed
// ("Assign platform roles to platform users") but nothing enforced it.
//
// The rules, applied to every request that sets a role or changes one:
//
//  1. The caller must hold platform_roles.assign.
//  2. The role being granted must be a subset of the caller's own effective
//     permissions — nobody can hand out more than they hold.
//  3. When changing an existing user's role, that user's CURRENT role must
//     also be a subset of the caller's permissions — a lesser operator cannot
//     demote (and so lock out) someone who outranks them.
//  4. A caller may not change their own role. The one exception is a
//     super_admin, who may step down — but not if they are the last active
//     super_admin, which would leave the platform with nobody able to grant
//     the full permission set again.
//
// Rules 2 and 3 apply to super_admin too; since super_admin is seeded with
// every platform permission they pass trivially, and a drifted database where
// super_admin lacks something fails closed rather than open.
//
// The seed grants platform_roles.assign to platform_admin as well, so stock
// platform admins can manage staff. That is safe only because of rules 2, 3
// and 5: the grant is bounded by what the caller holds, not by who holds it.
//
// The same privilege-escalation class reaches past the role field, so two more
// rules cover every OTHER mutation of an existing platform user — profile
// edits, activate/deactivate, set-password, sending a password reset, delete:
//
//  5. Target rank (authorizeActOnPlatformUser): the target's current role must
//     be a subset of the caller's effective permissions. Setting a superior's
//     password is a takeover of their account, and deactivating or deleting
//     them is a lock-out, so a lesser operator may do neither.
//  6. Nobody deactivates or deletes their own account (the console already
//     hides those actions; the server now refuses them too).
//
// And two invariants are enforced by the store, inside the write itself:
//
//   - no write — role change, deactivation or delete — may leave the platform
//     with zero active super_admins (errLastActiveSuperAdmin → 409). It lives
//     in the store rather than here because a check-then-write in the handler
//     races: two super_admins stepping down at once would each see the other
//     as "still there".
//   - every write to an existing user is conditional on the user still holding
//     the role the rank check saw (role_id IS NOT DISTINCT FROM it); if another
//     operator re-roled them in between, nothing is written
//     (errPlatformUserChanged → 409). Otherwise a user promoted to super_admin
//     after the check could have their password set, or be deactivated or
//     deleted, by someone who no longer outranks them.

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// superAdminRoleName is the seeded system role that holds every platform
// permission. Referenced only for the self-change / last-super-admin rule.
const superAdminRoleName = "super_admin"

// errLastActiveSuperAdmin is returned by a platformUserStore write that would
// leave no active super_admin. The repository decides it under a row lock on
// every active super_admin, in the same transaction as the write.
var errLastActiveSuperAdmin = errors.New("the write would leave no active super administrator")

// respondLastActiveSuperAdmin writes the 409 for errLastActiveSuperAdmin.
func respondLastActiveSuperAdmin(c *gin.Context) {
	c.JSON(http.StatusConflict, gin.H{"error": "This is the only active super administrator. Assign another super administrator first."})
}

// errPlatformUserChanged is returned by a platformUserStore write to an existing
// user when that user no longer holds the role the handler's rank check saw
// (or no longer exists): the write is conditional on it and wrote nothing.
var errPlatformUserChanged = errors.New("the platform user changed after the authorization check")

// respondPlatformUserChanged writes the 409 for errPlatformUserChanged.
func respondPlatformUserChanged(c *gin.Context) {
	c.JSON(http.StatusConflict, gin.H{"error": "This user was changed by someone else while your request was being checked. Reload and try again."})
}

// authorizeActOnPlatformUser enforces rule 5 (target rank) for any mutation of
// an existing platform user. It returns the caller's id and the target's
// current role. On denial it writes the response (401/404/403/500) and returns
// ok=false; the caller must return without writing anything.
//
// The target's role, not its individual permissions, is what is compared: a
// user holds exactly their role's permissions (platform_user_has_permission),
// and a user with no role holds nothing, so anyone may act on them.
func authorizeActOnPlatformUser(c *gin.Context, store platformUserStore, targetID uuid.UUID) (caller uuid.UUID, current platformUserRoleRef, ok bool) {
	ctx := c.Request.Context()
	caller, err := uuid.Parse(c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Managing a platform user requires an authenticated platform user"})
		return uuid.Nil, platformUserRoleRef{}, false
	}

	current, found, err := store.PlatformUserRole(ctx, targetID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
		return uuid.Nil, platformUserRoleRef{}, false
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Platform user not found"})
		return uuid.Nil, platformUserRoleRef{}, false
	}

	if current.RoleID != nil {
		missing, err := store.RolePermissionsNotHeldBy(ctx, caller.String(), current.RoleID.String())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
			return uuid.Nil, platformUserRoleRef{}, false
		}
		if len(missing) > 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"error":               "You cannot manage a platform user whose role holds permissions you do not have",
				"missing_permissions": missing,
			})
			return uuid.Nil, platformUserRoleRef{}, false
		}
	}
	return caller, current, true
}

// roleAssignment describes one attempted write of platform_users.role_id.
type roleAssignment struct {
	// TargetUserID is the user whose role changes; uuid.Nil for create/invite,
	// where the target does not exist yet. A uuid, not a string, so the
	// self-change comparison below cannot be defeated by the id's spelling.
	TargetUserID uuid.UUID
	// CurrentRoleID is the target's role before the change (update only; nil
	// for create/invite or a user with no role).
	CurrentRoleID *uuid.UUID
	// NewRoleID is the role being granted.
	NewRoleID uuid.UUID
}

// authorizeRoleAssignment enforces the rules in the file header. On denial it
// writes the response (403/409/401/500) and returns false; the caller must
// return without writing anything.
func authorizeRoleAssignment(c *gin.Context, store platformUserStore, a roleAssignment) bool {
	ctx := c.Request.Context()

	// Fail closed on an unidentified caller. The route middleware only lets
	// authenticated platform users this far, but role assignment is decided
	// per caller and there is no caller to decide it for.
	callerUUID, err := uuid.Parse(c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Assigning a platform role requires an authenticated platform user"})
		return false
	}
	callerID := callerUUID.String()

	canAssign, err := store.HasPlatformPermission(ctx, callerID, rbac.PermissionPlatformRolesAssign)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permission"})
		return false
	}
	if !canAssign {
		c.JSON(http.StatusForbidden, gin.H{
			"error":               "Assigning a platform role requires the platform_roles.assign permission",
			"required_permission": rbac.PermissionPlatformRolesAssign,
		})
		return false
	}

	if a.TargetUserID != uuid.Nil && a.TargetUserID == callerUUID {
		caller, found, err := store.PlatformUserRole(ctx, callerID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
			return false
		}
		if !found || caller.RoleName != superAdminRoleName {
			c.JSON(http.StatusForbidden, gin.H{"error": "You cannot change your own role. Ask another administrator with platform_roles.assign to change it."})
			return false
		}
		// A super_admin stepping down is allowed here; whether they are the
		// LAST active one is decided by the store inside the write's own
		// transaction (errLastActiveSuperAdmin), where it cannot race.
	}

	if a.CurrentRoleID != nil {
		missing, err := store.RolePermissionsNotHeldBy(ctx, callerID, a.CurrentRoleID.String())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
			return false
		}
		if len(missing) > 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"error":               "You cannot change the role of a user whose current role holds permissions you do not have",
				"missing_permissions": missing,
			})
			return false
		}
	}

	missing, err := store.RolePermissionsNotHeldBy(ctx, callerID, a.NewRoleID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify role"})
		return false
	}
	if len(missing) > 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"error":               "The selected role grants permissions you do not hold",
			"missing_permissions": missing,
		})
		return false
	}

	return true
}
