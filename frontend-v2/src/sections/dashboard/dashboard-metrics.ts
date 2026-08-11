export type PqcSummaryRollup = {
  readiness_percent?: number | null;
  pqc_implementations?: number | null;
  total_implementations?: number | null;
};

export type DashboardPqcMetric = {
  adoptionPercent: number;
  pqcReady: number;
  total: number;
  configsOnClassicalCrypto: number;
};

export function getDashboardPqcMetric(summary: PqcSummaryRollup | null | undefined): DashboardPqcMetric {
  const adoptionPercent = summary?.readiness_percent ?? 0;
  const pqcReady = summary?.pqc_implementations ?? 0;
  const total = summary?.total_implementations ?? 0;

  return {
    adoptionPercent,
    pqcReady,
    total,
    configsOnClassicalCrypto: total - pqcReady,
  };
}
