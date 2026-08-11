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

	PermissionPlatformRolesRead   = "platform_roles.read"
	PermissionPlatformRolesManage = "platform_roles.manage"

	PermissionPlatformPermissionsRead = "platform_permissions.read"

	// PermissionAlgorithmsManage gates writes to the algorithms table (the
	// crypto-assessment source of truth) — create, edit, and deprecate
	// algorithm definitions. Granted to super_admin (auto) + platform_admin.
	PermissionAlgorithmsManage = "algorithms.manage"
)

// Tenant-level permission constants primarily enforced by admin-service RBAC middleware.
const (
	PermissionTenantsRead   = "tenants.read"
	PermissionTenantsManage = "tenants.manage"
	PermissionTenantsDelete = "tenants.delete"
	PermissionTenantsUpdate = "tenants.update"
)

// PCAP ingestion permission constants for tenant-level pcap upload management.
const (
	PermissionPcapUpload = "pcap.upload"
	PermissionPcapRead   = "pcap.read"
	PermissionPcapDelete = "pcap.delete"
)

// Core tenant resource permission constants. These mirror rows in the
// tenant_permissions DB table and the TENANT_PERMISSIONS object in
// web-ui/src/constants/permissions.ts. Adding a new resource means:
//  1. Add the row(s) to scripts/database/seed.sql tenant_permissions INSERT
//  2. Decide which roles grant it (seed.sql DO block + auth-service
//     assignRolePermissions filter)
//  3. Add the constant here so services can use it in middleware
//  4. Apply RequireTenantPermission(db, rbac.PermissionXxx) on the
//     relevant routes
//  5. Add web-ui constant in TENANT_PERMISSIONS and gate the UI if needed
//
// The permission-parity audit (scripts/audit-permissions.mjs) checks
// 1, 2, and 4 — but step 5 has to be done by the feature author.
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

	// reports.{create,update,delete} were retired with the legacy
	// templated-report surface (Phase 5). reports.read and .manage remain
	// as frontend route gates for the CBOM page and scheduled-reports
	// page respectively.
	PermissionReportsRead   = "reports.read"
	PermissionReportsManage = "reports.manage"

	PermissionComplianceRead   = "compliance.read"
	PermissionComplianceUpdate = "compliance.update"
	PermissionComplianceManage = "compliance.manage"

	// Stateful alert lifecycle. Reads are open to members; acknowledge/
	// snooze/resolve/ticket-create sit behind alerts.manage.
	PermissionAlertsRead   = "alerts.read"
	PermissionAlertsManage = "alerts.manage"

	PermissionDiscoveryCreate = "discovery.create"
	PermissionDiscoveryRead   = "discovery.read"
	PermissionDiscoveryUpdate = "discovery.update"
	PermissionDiscoveryManage = "discovery.manage"

	PermissionSettingsRead   = "settings.read"
	PermissionSettingsUpdate = "settings.update"
	PermissionSettingsManage = "settings.manage"

	PermissionUsersCreate = "users.create"
	PermissionUsersRead   = "users.read"
	PermissionUsersUpdate = "users.update"
	PermissionUsersDelete = "users.delete"
	PermissionUsersManage = "users.manage"

	PermissionBillingRead   = "billing.read"
	PermissionBillingUpdate = "billing.update"
)

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
