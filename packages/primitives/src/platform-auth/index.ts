// Platform-admin auth + RBAC primitives (admin-ui-v2 ADR-0002). The admin
// counterpart to ./auth + ./rbac: same headless rules, built on the
// admin-service contract and the platform_* cookie family. Import via
// '@vistasecurity/primitives/platform-auth'.
export { platformTokenManager, PLATFORM_CSRF_COOKIE } from './token';
export { createPlatformAuthClient } from './client';
export type {
  PlatformAuthClient,
  PlatformLoginResponse,
  PlatformUser,
  CurrentPlatformUser,
} from './client';
export { PlatformAuthProvider, usePlatformAuth } from './context';
export type { PlatformAuthState, PlatformAuthProviderProps } from './context';
export {
  PlatformPermissionProvider,
  usePlatformPermissions,
  PlatformPermissionGate,
} from './rbac';
export type {
  PlatformPermissionState,
  PlatformPermissionProviderProps,
  PlatformPermissionGateProps,
} from './rbac';
export { PLATFORM_PERMISSIONS } from './constants';
export type { PlatformPermissionKey } from './constants';
