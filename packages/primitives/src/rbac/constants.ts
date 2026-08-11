// Tenant permission registry — extracted verbatim from
// web-ui/src/constants/permissions.ts (Phase 1). This is the single source of
// truth for permission strings shared by both surfaces; gates check against it.

export const TENANT_PERMISSIONS = {
  assets: {
    create: 'assets.create',
    read: 'assets.read',
    update: 'assets.update',
    delete: 'assets.delete',
    manage: 'assets.manage',
  },
  sensors: {
    create: 'sensors.create',
    read: 'sensors.read',
    update: 'sensors.update',
    delete: 'sensors.delete',
    manage: 'sensors.manage',
  },
  // reports.{create,update,delete} were retired with the legacy templated-
  // report surface in Phase 5 (see CLAUDE.md). reports.read and .manage
  // are kept as frontend route gates for the CBOM page and the
  // scheduled-reports page respectively.
  reports: {
    read: 'reports.read',
    manage: 'reports.manage',
  },
  users: {
    create: 'users.create',
    read: 'users.read',
    update: 'users.update',
    delete: 'users.delete',
    manage: 'users.manage',
  },
  settings: {
    read: 'settings.read',
    update: 'settings.update',
    manage: 'settings.manage',
  },
  billing: {
    read: 'billing.read',
    update: 'billing.update',
  },
  compliance: {
    read: 'compliance.read',
    update: 'compliance.update',
    manage: 'compliance.manage',
  },
  alerts: {
    read: 'alerts.read',
    manage: 'alerts.manage',
  },
  discovery: {
    create: 'discovery.create',
    read: 'discovery.read',
    update: 'discovery.update',
    manage: 'discovery.manage',
  },
  pcap: {
    read: 'pcap.read',
    upload: 'pcap.upload',
    delete: 'pcap.delete',
  },
} as const;

type ValueOf<T> = T[keyof T];
type DeepValueOf<T> = T extends object ? DeepValueOf<ValueOf<T>> : T;

export type TenantPermissionKey = DeepValueOf<typeof TENANT_PERMISSIONS>;
