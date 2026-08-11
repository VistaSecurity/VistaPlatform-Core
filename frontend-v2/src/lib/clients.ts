// Typed service clients — one instance per backend service. Each factory wires
// the gateway base path + cookie auth + CSRF (see @vistasecurity/api-contract).
// In dev, Vite proxies these relative /api paths to the running gateway (:8080).
// This is the ONLY way the new UI talks to the backend — no hand-written calls.
import {
  createInventoryServiceClient,
  createComplianceEngineClient,
  createCbomServiceClient,
  createSensorManagerClient,
  createAuditServiceClient,
  createDeviceInterrogationServiceClient,
  createMonitoringServiceClient,
  createNotificationServiceClient,
  createAdminServiceClient,
  createAuthServiceClient,
} from '@vistasecurity/api-contract';

export const clients = {
  inventory: createInventoryServiceClient(),
  compliance: createComplianceEngineClient(),
  cbom: createCbomServiceClient(),
  sensors: createSensorManagerClient(),
  audit: createAuditServiceClient(),
  devices: createDeviceInterrogationServiceClient(),
  monitoring: createMonitoringServiceClient(),
  notifications: createNotificationServiceClient(),
  admin: createAdminServiceClient(),
  auth: createAuthServiceClient(),
};
