// M-2: this used to read /pqc/summary, whose 3-field PqcSummaryRollup shape
// forced callers to compute "not PQC-ready" as total - ready — silently
// lumping Unclassified (implementations with NO algorithm data at all) in
// with NeedsMigration (implementations with a real quantum-vulnerable
// component) under one "on classical crypto" label. classifyTenantImplementationsPQC
// (services/inventory-service/internal/services/pqc_readiness.go) already
// partitions the population into four mutually exclusive categories and
// exposes all of them via /pqc/progress — read that instead so the dashboard
// can show "not yet assessed" as what it is, never as "on classical crypto".
export type PqcProgressRollup = {
  pqc_percentage?: number | null;
  pqc_ready?: number | null;
  symmetric_safe?: number | null;
  non_pqc?: number | null;
  unclassified?: number | null;
  total_implementations?: number | null;
};

export type DashboardPqcMetric = {
  adoptionPercent: number;
  /** PQC-ready + symmetric-only (no asymmetric component to migrate). */
  pqcReady: number;
  total: number;
  /** At least one component is classical asymmetric — a real migration target. */
  needsMigration: number;
  /** Could not be classified — no algorithm data resolved. NOT "on classical crypto". */
  unclassified: number;
};

// The dashboard's critical-finding count comes from compliance-engine, while
// /risk-compliance/findings defaults to the crypto-risk lens. Keep the route
// explicit so click-through lands in the same finding universe it counted.
export const DASHBOARD_COMPLIANCE_FINDINGS_ROUTE = '/risk-compliance/findings?lens=framework';

export function getDashboardPqcMetric(progress: PqcProgressRollup | null | undefined): DashboardPqcMetric {
  const adoptionPercent = progress?.pqc_percentage ?? 0;
  const pqcReadyOnly = progress?.pqc_ready ?? 0;
  const symmetricSafe = progress?.symmetric_safe ?? 0;
  const total = progress?.total_implementations ?? 0;
  const needsMigration = progress?.non_pqc ?? 0;
  const unclassified = progress?.unclassified ?? 0;

  return {
    adoptionPercent,
    pqcReady: pqcReadyOnly + symmetricSafe,
    total,
    needsMigration,
    unclassified,
  };
}

// ---- Discovery fleet -------------------------------------------------------
//
// The Discovery card counted ONLY the sensor-manager /sensors table, so a
// tenant running 2 sensors + 2 agents read "3/3 sensors": the registered device
// agent was missing entirely, and the platform interrogation agent was silently
// counted as a sensor.
//
// Two things have to be right, and they are separate:
//
//  1. BOTH FLEETS. Discovery agents live in device-interrogation-service's own
//     table (GET /agents), not in /sensors. Command Center already combines the
//     two (M-13); this makes the dashboard agree instead of contradicting it.
//  2. SENSOR vs AGENT. "Sensor" is used loosely for both, but they are different
//     things, and the split does not follow the table: the tenant's PLATFORM
//     interrogation agent is a row in the sensors table (profile
//     'device_interrogation', sensor_type 'api', seeded per tenant by
//     create_system_sensors_for_tenant). Classify by profile/type, not by which
//     endpoint the row came from.
//
// Online is "status === active", matching the fleet pages.

/** The subset of a sensor row this module needs. Structural, so it accepts the
 *  generated API type without importing it. */
export interface FleetSensorRow {
  status?: string | null;
  profile?: string | null;
  sensor_type?: string | null;
  tags?: string[] | null;
}

/** The subset of a device-agent row this module needs. */
export interface FleetAgentRow {
  status?: string | null;
}

export interface FleetCount {
  online: number;
  total: number;
}

export interface DiscoveryFleetMetric {
  sensors: FleetCount;
  agents: FleetCount;
  /** Both fleets together — what the card's hero shows. */
  all: FleetCount;
}

function isOnline(row: { status?: string | null }): boolean {
  return (row.status ?? '').toLowerCase() === 'active';
}

/**
 * Is this row from the sensors table actually a discovery AGENT? True for the
 * platform-managed interrogation agent every tenant is seeded with, and for any
 * device-agent registration that landed there. Mirrors the predicates the
 * registration modal (isDeviceAgentProfile) and fleet table already use.
 */
export function isAgentRow(row: FleetSensorRow): boolean {
  const profile = (row.profile ?? '').toLowerCase();
  const type = (row.sensor_type ?? '').toLowerCase();
  const tags = (row.tags ?? []).map((t) => t.toLowerCase());
  return profile === 'device_interrogation' || type === 'api' || tags.includes('device_agent');
}

export function getDiscoveryFleetMetric(
  sensorRows: FleetSensorRow[] | null | undefined,
  agentRows: FleetAgentRow[] | null | undefined,
): DiscoveryFleetMetric {
  const rows = sensorRows ?? [];
  const agentsFromSensorTable = rows.filter(isAgentRow);
  const sensorsOnly = rows.filter((r) => !isAgentRow(r));
  const agentsAll = [...agentsFromSensorTable, ...(agentRows ?? [])];

  const count = (xs: { status?: string | null }[]): FleetCount => ({
    online: xs.filter(isOnline).length,
    total: xs.length,
  });

  const sensors = count(sensorsOnly);
  const agents = count(agentsAll);
  return {
    sensors,
    agents,
    all: { online: sensors.online + agents.online, total: sensors.total + agents.total },
  };
}
