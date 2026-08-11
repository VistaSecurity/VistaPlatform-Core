package services

import "github.com/google/uuid"

// PlatformAlertTenantID is the reserved sentinel tenant that owns platform-track
// stateful alerts (service_down, tenant_health_degraded, …). Platform-track
// alerts are not tenant-scoped, but the alerts table's tenant_id is NOT NULL and
// RLS-isolated, so platform detectors raise under this well-known sentinel and
// platform-admin reads scope to it. There is intentionally NO tenants row for
// this id (alerts.tenant_id has no FK) — it exists only as an RLS partition key.
// Do not change this value once alerts have been written under it.
var PlatformAlertTenantID = uuid.MustParse("11111111-1111-1111-1111-111111111111")
