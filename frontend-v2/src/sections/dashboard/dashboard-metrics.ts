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
  /** Whole percent. `pqc_percentage` is a float (ready/total), so a tenant with
   *  4 of 11 implementations read "36.36363636363637%" on the tiles. */
  adoptionPercent: number;
  /** PQC-ready + symmetric-only (no asymmetric component to migrate). */
  pqcReady: number;
  total: number;
  /** At least one component is classical asymmetric — a real migration target. */
  needsMigration: number;
  /** Could not be classified — no algorithm data resolved. NOT "on classical crypto". */
  unclassified: number;
};

// The "Critical findings" tile counts EVERY producer, so it links at the lens
// that shows every producer.
//
// It reads /findings/statistics.all_producer_severity_counts.critical, whose
// query is findingListWhere with no filters — literally the WHERE behind GET
// /findings (services/compliance-engine/internal/services/findings_service.go,
// allProducerSeverityWhere). So the count and this destination read ONE row
// universe by construction, not by two people agreeing about which producers
// and which frameworks are in it.
//
// One universe is not one number, and the tile applies two narrowings to it that
// this route has to carry — "a tile that counts a subset must link to that
// subset", the rule stated below for the sibling tiles.
//
//   - SEVERITY. The tile counts the Critical rung, so the route names it.
//     `?severity=critical` is read by findings-page.tsx and applied by the
//     SERVER (the page caps at five pages of 200, so narrowing in the browser
//     would under-report a large tenant), and rendered as a clearable banner so
//     a filter the reader never chose is one they can see and undo.
//
//   - WORKFLOW. The page opens on its `Open` chip, which hides RESOLVED and
//     SUPPRESSED rows (isOpenWf, sections/findings/model.ts), so the ROLLUP
//     excludes them too — allProducerSeverityWhere sets FindingListFilters
//     .WorkflowOpen, which splices the registry's own definition of open
//     (shared/findings.WorkflowOpenSQL). Nothing in the URL, because it is the
//     page's default rather than a narrowing of it.
//
// Both were documented caveats before v1.0.0 rather than fixed: the tile counted
// every ACTIVE row whatever its workflow status, so a tenant who suppressed a
// Critical end-of-life finding with a reason kept seeing it counted on an
// attention tile and did not find it on the page the tile sent them to.
//
// It used to read `severity_counts`, which is scoped
// `producer = 'compliance' AND kind = 'control_noncompliant'` under the
// licensed-framework gate: failed controls on activated frameworks, nothing
// from `eol`, `vulnerability`, `configuration`, `hygiene`, `drift` or the
// crypto producer. A tenant whose only Criticals were end-of-life findings read
// "0 critical findings" here while Risk & Compliance → Findings showed them —
// the H-2 divergence again, one producer later. Widening the COUNT was the fix
// rather than narrowing the LABEL, because the product's position is that
// findings are one stream (docsv4/core/features/findings.md, "One list, several
// producers"), and a dashboard that silently means "compliance only" is the
// shape this page keeps being wrong in.
//
// Written out even though it is the page default today: a default is a thing
// that changes, and a tile's link has to survive it. FINDINGS_SUBJECT_LENS
// names the same lens for the same reason.
export const DASHBOARD_CRITICAL_FINDINGS_ROUTE = '/risk-compliance/findings?lens=producer&severity=critical';

// A tile that counts a subset must link to that subset. Both of these used to
// link at `/inventory?lens=infrastructure` — a retired lens key that redirects
// to the unfiltered list — so clicking "High-risk assets: 12" landed on every
// asset in the tenant with nothing saying which twelve were meant.
//
// The predicate is the query LANGUAGE, in the canonical form the facet rail
// writes, so the destination opens with the matching facets already ticked and
// the user can widen it from there. `high_risk` is the ≥ High band, which
// includes Critical; `unknown_risk` is the absence of a score, which the
// language spells `not_assessed` (never "low").
export const DASHBOARD_HIGH_RISK_QUERY = 'risk:(critical or high)';
export const DASHBOARD_UNSCORED_QUERY = 'risk:not_assessed';

/** `/inventory?lens=assets` with a query, URL-encoded once, in one place. */
export function inventoryQueryRoute(query: string): string {
  return `/inventory?lens=assets&query=${encodeURIComponent(query)}`;
}

export const DASHBOARD_HIGH_RISK_ASSETS_ROUTE = inventoryQueryRoute(DASHBOARD_HIGH_RISK_QUERY);
export const DASHBOARD_UNSCORED_ASSETS_ROUTE = inventoryQueryRoute(DASHBOARD_UNSCORED_QUERY);

export function getDashboardPqcMetric(progress: PqcProgressRollup | null | undefined): DashboardPqcMetric {
  const adoptionPercent = Math.round(progress?.pqc_percentage ?? 0);
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
