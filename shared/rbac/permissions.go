package rbac

// Platform-level permission constants used across admin, monitoring, and auth services.
const (
	PermissionPlatformAnalytics           = "platform.analytics"
	PermissionPlatformHealth              = "platform.health"
	PermissionPlatformLogsRead            = "platform.logs.read"
	PermissionPlatformBilling             = "platform.billing"
	PermissionPlatformSecurity            = "platform.security"
	PermissionPlatformSettings            = "platform.settings"
	PermissionPlatformImpersonate         = "platform.impersonate"
	PermissionPlatformNotificationsManage = "platform.notifications.manage"

	PermissionPlatformUsersRead   = "platform_users.read"
	PermissionPlatformUsersManage = "platform_users.manage"
	PermissionPlatformUsersDelete = "platform_users.delete"

	PermissionPlatformRolesRead = "platform_roles.read"
	// PermissionPlatformRolesAssign gates every write of platform_users.role_id
	// (create, invite, and role change on update). Granting a role is a
	// privilege grant, so it is deliberately separate from
	// platform_users.manage; the handler also requires the granted role to be a
	// subset of the caller's own permissions.
	PermissionPlatformRolesAssign = "platform_roles.assign"
	PermissionPlatformRolesManage = "platform_roles.manage"

	PermissionPlatformPermissionsRead = "platform_permissions.read"

	// PermissionAlgorithmsManage gates writes to the algorithms table (the
	// crypto-assessment source of truth) — create, edit, and deprecate
	// algorithm definitions. Granted to super_admin (auto) + platform_admin.
	PermissionAlgorithmsManage = "algorithms.manage"

	// PermissionCatalogsManage gates the non-crypto platform catalogues —
	// eol_catalogue and vulnerability_catalogue — plus their mirror-feed
	// controls (status, manual sync, offline bundle import). Granted to
	// super_admin (auto) + platform_admin, same as algorithms.manage; kept
	// separate because curating crypto ratings and re-pointing the platform at
	// a vulnerability source are different trust decisions.
	PermissionCatalogsManage = "catalogs.manage"
)

// PermissionPlatformSecurityManage gates every write that decides how staff
// authenticate or where their credential-bearing email goes: identity providers
// (staff SSO and social signup), the SMTP relay, the admin-console link base,
// and the password/session/lockout policy. Seeded to super_admin only;
// platform.settings (held by platform_admin) keeps read access to all of it.
const PermissionPlatformSecurityManage = "platform.security.manage"

// Tenant-level permission constants primarily enforced by admin-service RBAC middleware.
const (
	PermissionTenantsRead   = "tenants.read"
	PermissionTenantsManage = "tenants.manage"
	PermissionTenantsDelete = "tenants.delete"
	PermissionTenantsUpdate = "tenants.update"
)

// Tenant resource permission constants. These are typed references to the rows
// in the tenant_permissions DB table and to the TENANT_PERMISSIONS object in
// packages/primitives/src/rbac/constants.ts (imported by both frontend-v2 and
// admin-ui-v2 as @vistasecurity/primitives/rbac). All three — plus the seed
// catalogue, the seed grant filters, and this service's grant filters — are
// generated from standards/permissions.yaml.
//
// Adding a permission means:
//  1. Add it to standards/permissions.yaml (catalogue + whichever role grants
//     it) and run `make generate`. That covers the DB rows, the grant filters
//     on both reconciliation paths, this constant, and the TS constant.
//  2. Apply RequireTenantPermission(db, rbac.PermissionXxx) on the relevant
//     routes.
//  3. Gate the UI with the TENANT_PERMISSIONS constant if needed.
//
// The permission-parity audit (scripts/audit-permissions.mjs) checks 2; step 3
// has to be done by the feature author.
//
// BEGIN GENERATED: tenant permission constants — from standards/permissions.yaml (make generate)
const (
	PermissionAssetsCreate = "assets.create"
	PermissionAssetsRead   = "assets.read"
	PermissionAssetsUpdate = "assets.update"
	PermissionAssetsDelete = "assets.delete"
	PermissionAssetsManage = "assets.manage"

	PermissionSensorsCreate = "sensors.create"
	PermissionSensorsRead   = "sensors.read"
	PermissionSensorsUpdate = "sensors.update"
	PermissionSensorsDelete = "sensors.delete"
	PermissionSensorsManage = "sensors.manage"

	// reports.read and reports.manage are retained because the web-ui uses
	// them as frontend-only gates for the CBOM page (reports.read) and the
	// scheduled-reports view (reports.manage). reports.{create,update,delete}
	// were retired with the legacy templated-report surface in Phase 5
	// (see CLAUDE.md) — no backend handler exists and no UI references them.
	// The retired-permission cleanup below removes any rows that may have
	// been seeded by an older release.
	PermissionReportsRead   = "reports.read"
	PermissionReportsManage = "reports.manage"

	PermissionUsersCreate = "users.create"
	PermissionUsersRead   = "users.read"
	PermissionUsersUpdate = "users.update"
	PermissionUsersDelete = "users.delete"
	PermissionUsersManage = "users.manage"

	PermissionSettingsRead   = "settings.read"
	PermissionSettingsUpdate = "settings.update"
	PermissionSettingsManage = "settings.manage"

	PermissionBillingRead   = "billing.read"
	PermissionBillingUpdate = "billing.update"

	PermissionComplianceRead   = "compliance.read"
	PermissionComplianceUpdate = "compliance.update"
	PermissionComplianceManage = "compliance.manage"

	// Stateful alert lifecycle. Reads are open to members;
	// acknowledge/snooze/resolve/ticket-create sit behind alerts.manage.
	PermissionAlertsRead   = "alerts.read"
	PermissionAlertsManage = "alerts.manage"

	PermissionDiscoveryRead   = "discovery.read"
	PermissionDiscoveryCreate = "discovery.create"
	PermissionDiscoveryUpdate = "discovery.update"
	PermissionDiscoveryManage = "discovery.manage"

	PermissionPcapRead   = "pcap.read"
	PermissionPcapUpload = "pcap.upload"
	PermissionPcapDelete = "pcap.delete"

	// Audit trail. audit-service previously ran a private permission
	// system: a hardcoded switch on the role NAME inventing audit.read /
	// audit.manage / audit.security / audit.export, none of which existed
	// here, in shared/rbac/permissions.go, or in tenant_role_permissions. No
	// tenant could grant audit access to anyone. Two permissions replace all
	// four — audit.security and audit.export were demanded by no route at all.
	PermissionAuditRead   = "audit.read"
	PermissionAuditManage = "audit.manage"
)

// END GENERATED: tenant permission constants

// PcapPermissions returns all PCAP ingestion permissions.
func PcapPermissions() []string {
	return []string{
		PermissionPcapUpload,
		PermissionPcapRead,
		PermissionPcapDelete,
	}
}

// PlatformCorePermissions returns the baseline platform permission set for dashboards.
func PlatformCorePermissions() []string {
	return []string{
		PermissionPlatformAnalytics,
		PermissionPlatformHealth,
		PermissionPlatformLogsRead,
		PermissionPlatformBilling,
		PermissionPlatformSecurity,
		PermissionPlatformSettings,
	}
}
