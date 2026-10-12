package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
)

// Tenant authentication policy (tenants.authentication_policy).
//
// The column exists in BOTH editions (default password_only); only Enterprise
// has a surface that changes it (services/auth-service/ee/sso). The values and
// their meaning live here, in Core, so the Core login/reset paths and the
// Enterprise SSO code read one definition rather than each spelling the
// strings:
//
//	password_only  local password sign-in; no federated option is promoted.
//	prefer_sso     SSO is offered first; local password sign-in still works.
//	enforce_sso    SSO is required for regular users; tenant_admins keep password
//	               access as the break-glass path (this is what the tenant-admin
//	               guide has always documented). The platform social-signup IdP
//	               (Google/Microsoft fallback) is refused for every user.
//	sso_only       local passwords are dead for EVERYONE: password login and
//	               password reset are refused for the tenant's users, admins
//	               included (platform users, who carry no tenant, are exempt).
const (
	PolicyPasswordOnly = "password_only"
	PolicyPreferSSO    = "prefer_sso"
	PolicyEnforceSSO   = "enforce_sso"
	PolicySSOOnly      = "sso_only"
)

// ValidPolicies lists every value the valid_authentication_policy CHECK allows.
func ValidPolicies() []string {
	return []string{PolicyPasswordOnly, PolicyPreferSSO, PolicyEnforceSSO, PolicySSOOnly}
}

// PolicyForbidsLocalPassword reports whether policy refuses local passwords for
// EVERY user (password sign-in, password reset, password-based invitation
// acceptance): true only for sso_only. enforce_sso refuses them per user — see
// localPasswordRefused.
func PolicyForbidsLocalPassword(policy string) bool { return policy == PolicySSOOnly }

// PolicyEnforcesSSO reports whether the tenant requires its own SSO: the
// platform social-signup IdP is refused for its users, and the policy may only
// be set while at least one tenant provider is enabled. True for enforce_sso and
// sso_only; only sso_only additionally refuses local passwords.
func PolicyEnforcesSSO(policy string) bool {
	return policy == PolicyEnforceSSO || policy == PolicySSOOnly
}

// ErrSSORequired is returned by Login when the user's tenant is sso_only and the
// caller proved a local password anyway. It is a *tenantstate.BlockedError so
// every existing login handler (respondTenantBlocked) answers it as a 403 with
// code "sso_required" and a sentence the sign-in page can show, without a new
// handler case in each caller.
var ErrSSORequired error = &tenantstate.BlockedError{Code: tenantstate.CodeSSORequired}

// tenantAuthPolicy reads a tenant's policy. tenants is GLOBAL (no
// tenant_isolation policy), so the plain pool works without a tenant context. A
// missing row or NULL reads as password_only; a read FAILURE is returned so the
// caller fails closed rather than treating "could not look" as "no policy".
func (a *AuthService) tenantAuthPolicy(tenantID uuid.UUID) (string, error) {
	var policy string
	err := a.db.QueryRow(
		`SELECT COALESCE(authentication_policy, $2) FROM tenants WHERE id = $1`,
		tenantID, PolicyPasswordOnly).Scan(&policy)
	if err == sql.ErrNoRows {
		return PolicyPasswordOnly, nil
	}
	if err != nil {
		return "", fmt.Errorf("read tenant authentication policy: %w", err)
	}
	return policy, nil
}

// localPasswordRefused reports whether the tenant's policy refuses a local
// password for THIS user: sso_only refuses everyone, enforce_sso refuses everyone
// who does not hold an active tenant_admin role. A policy-read failure is
// returned so callers refuse rather than wave through.
func (a *AuthService) localPasswordRefused(userID, tenantID uuid.UUID) (bool, error) {
	policy, err := a.tenantAuthPolicy(tenantID)
	if err != nil {
		return false, err
	}
	switch policy {
	case PolicySSOOnly:
		return true, nil
	case PolicyEnforceSSO:
		admin, err := a.holdsTenantAdminRole(userID, tenantID)
		if err != nil {
			return false, err
		}
		return !admin, nil
	default:
		return false, nil
	}
}

// holdsTenantAdminRole reports whether the user has an active, unexpired
// tenant_admin assignment in the tenant.
func (a *AuthService) holdsTenantAdminRole(userID, tenantID uuid.UUID) (bool, error) {
	// RLS-scoped: tenant_roles + user_tenant_roles carry tenant_isolation
	// policies; the tenant is known.
	var held bool
	err := shareddatabase.WithTenantTx(context.Background(), a.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), `
			SELECT EXISTS (
				SELECT 1 FROM user_tenant_roles utr
				JOIN tenant_roles tr ON tr.id = utr.role_id
				WHERE utr.user_id = $1 AND utr.tenant_id = $2 AND tr.tenant_id = $2
				  AND tr.name = 'tenant_admin' AND utr.is_active = true
				  AND (utr.expires_at IS NULL OR utr.expires_at > NOW()))`,
			userID, tenantID).Scan(&held)
	})
	if err != nil {
		return false, fmt.Errorf("read tenant admin role: %w", err)
	}
	return held, nil
}
