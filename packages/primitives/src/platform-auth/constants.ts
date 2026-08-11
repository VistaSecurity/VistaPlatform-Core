// Platform (operator) permission registry — the single source of truth for the
// platform_permissions strings the admin-service emits via /admin/user/permissions
// (see scripts/database/seed.sql `platform_permissions`). Gates check against it
// so the admin UI never hard-codes a bare string that can drift from the backend.
export const PLATFORM_PERMISSIONS = {
  tenants: {
    create: 'tenants.create',
    read: 'tenants.read',
    update: 'tenants.update',
    delete: 'tenants.delete',
    manage: 'tenants.manage',
    activate: 'tenants.activate',
    suspend: 'tenants.suspend',
  },
  platformUsers: {
    create: 'platform_users.create',
    read: 'platform_users.read',
    update: 'platform_users.update',
    delete: 'platform_users.delete',
    manage: 'platform_users.manage',
  },
  platformRoles: {
    read: 'platform_roles.read',
    assign: 'platform_roles.assign',
    manage: 'platform_roles.manage',
  },
  algorithms: {
    manage: 'algorithms.manage',
  },
  platform: {
    settings: 'platform.settings',
    billing: 'platform.billing',
    analytics: 'platform.analytics',
    health: 'platform.health',
    logs: 'platform.logs',
    security: 'platform.security',
    securityManage: 'platform.security.manage',
    audit: 'platform.audit',
    notificationsManage: 'platform.notifications.manage',
    impersonate: 'platform.impersonate',
  },
  support: {
    tenants: 'support.tenants',
    users: 'support.users',
  },
} as const;

type ValueOf<T> = T[keyof T];
type DeepValueOf<T> = T extends object ? DeepValueOf<ValueOf<T>> : T;

export type PlatformPermissionKey = DeepValueOf<typeof PLATFORM_PERMISSIONS>;
