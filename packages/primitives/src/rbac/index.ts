// RBAC primitives.
export { TENANT_PERMISSIONS } from './constants';
export type { TenantPermissionKey } from './constants';
export { PermissionProvider, usePermissions, PermissionGate } from './context';
export type { PermissionState, PermissionProviderProps, PermissionGateProps } from './context';
