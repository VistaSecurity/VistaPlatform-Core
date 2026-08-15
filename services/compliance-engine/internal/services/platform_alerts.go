package services

import "github.com/vistasecurity/vistaplatform/shared/events"

// PlatformAlertTenantID is the reserved sentinel tenant that owns platform-track
// stateful alerts (service_down, metric_threshold, tenant_health_degraded, …).
// Platform-track alerts are not tenant-scoped, but the alerts table's tenant_id
// is NOT NULL and RLS-isolated, so platform detectors raise under this
// well-known sentinel and platform-admin reads scope to it. There is
// intentionally NO tenants row for this id (alerts.tenant_id has no FK) — it
// exists only as an RLS partition key. Do not change this value once alerts have
// been written under it.
//
// The value is defined once in shared/events (beside AlertRaiseEvent) so
// out-of-service producers of the alerts.raise rail agree on it; this alias
// keeps the in-service call sites reading naturally.
var PlatformAlertTenantID = events.PlatformAlertTenantID
