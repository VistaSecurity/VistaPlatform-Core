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
