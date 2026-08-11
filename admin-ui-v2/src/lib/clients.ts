// Typed service clients — one instance per backend service. Each factory wires
// the gateway base path + cookie auth + CSRF (see @vistasecurity/api-contract).
// In dev, Vite proxies these relative /api paths to the running gateway (:8080).
// This is the ONLY way the new admin UI talks to the backend — no hand-written
// axios calls (the v1 admin-ui's 38 hand-rolled clients are what we're leaving
// behind). See docsv4/internal/developer/design/admin-ui-v2/.
//
// The set below is the platform-admin surface: admin-service is the spine, plus
// the services the admin console reads from. resource-tracker + tenant-health
// were spec'd as part of this prep (they had no contract before).
import {
  createAdminServiceClient,
  createAuthServiceClient,
  createAuditServiceClient,
  createComplianceEngineClient,
  createDeviceInterrogationServiceClient,
  createInventoryServiceClient,
  createMonitoringServiceClient,
  createNotificationServiceClient,
  createResourceTrackerServiceClient,
  createTenantHealthServiceClient,
  createSensorManagerClient,
} from '@vistasecurity/api-contract';

// Platform-admin sessions carry the `platform_csrf_token` cookie (set by
// admin-service login), NOT the tenant `csrf_token`. Every client here must echo
// that cookie as X-CSRF-Token or mutating requests are rejected with
// "CSRF token missing or invalid". (GETs carry no CSRF header, so this is inert
// for read-only clients but correct for any write.)
const ADMIN_CSRF = { csrfCookie: 'platform_csrf_token' } as const;

export const clients = {
  admin: createAdminServiceClient(ADMIN_CSRF),
  auth: createAuthServiceClient(ADMIN_CSRF),
  audit: createAuditServiceClient(ADMIN_CSRF),
  compliance: createComplianceEngineClient(ADMIN_CSRF),
  devices: createDeviceInterrogationServiceClient(ADMIN_CSRF),
  inventory: createInventoryServiceClient(ADMIN_CSRF),
  monitoring: createMonitoringServiceClient(ADMIN_CSRF),
  notifications: createNotificationServiceClient(ADMIN_CSRF),
  resourceTracker: createResourceTrackerServiceClient(ADMIN_CSRF),
  tenantHealth: createTenantHealthServiceClient(ADMIN_CSRF),
  sensors: createSensorManagerClient(ADMIN_CSRF),
};
