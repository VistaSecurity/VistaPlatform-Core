// Public entry point for the generated VistaPlatform TypeScript client.
//
// Usage:
//   import { createCbomServiceClient } from "@vistasecurity/api-contract";
//   const cbom = createCbomServiceClient();
//   const { data, error } = await cbom.GET("/scopes");
//   //      ^ ScopeListResponse        ^ LegacyError
export * from "./client";
export type { paths, components, operations } from "./cbom-service";
export type {
  paths as inventoryPaths,
  components as inventoryComponents,
  operations as inventoryOperations,
} from "./inventory-service";
export type {
  paths as complianceEnginePaths,
  components as complianceEngineComponents,
  operations as complianceEngineOperations,
} from "./compliance-engine";
export type {
  paths as authServicePaths,
  components as authServiceComponents,
  operations as authServiceOperations,
} from "./auth-service";
export type {
  paths as sensorManagerPaths,
  components as sensorManagerComponents,
  operations as sensorManagerOperations,
} from "./sensor-manager";
export type {
  paths as auditServicePaths,
  components as auditServiceComponents,
  operations as auditServiceOperations,
} from "./audit-service";
export type {
  paths as deviceInterrogationPaths,
  components as deviceInterrogationComponents,
  operations as deviceInterrogationOperations,
} from "./device-interrogation-service";
export type {
  paths as notificationServicePaths,
  components as notificationServiceComponents,
  operations as notificationServiceOperations,
} from "./notification-service";
export type {
  paths as adminServicePaths,
  components as adminServiceComponents,
  operations as adminServiceOperations,
} from "./admin-service";
export type {
  paths as monitoringServicePaths,
  components as monitoringServiceComponents,
  operations as monitoringServiceOperations,
} from "./monitoring-service";
export type {
  paths as resourceTrackerServicePaths,
  components as resourceTrackerServiceComponents,
  operations as resourceTrackerServiceOperations,
} from "./resource-tracker-service";
export type {
  paths as tenantHealthServicePaths,
  components as tenantHealthServiceComponents,
  operations as tenantHealthServiceOperations,
} from "./tenant-health-service";
