import { describe, expect, it } from 'vitest';
import { getDashboardPqcMetric } from './dashboard-metrics';

describe('dashboard PQC metric', () => {
  it('uses inventory PQC adoption rather than a framework-style score, and keeps needsMigration/unclassified separate', () => {
    const metric = getDashboardPqcMetric({
      pqc_percentage: 8,
      pqc_ready: 1,
      symmetric_safe: 1,
      non_pqc: 4,
      unclassified: 7,
      total_implementations: 13,
      // This mirrors the old, wrong fallback source. It must not affect the dashboard.
      compliance_percent: 45,
    } as Parameters<typeof getDashboardPqcMetric>[0] & { compliance_percent: number });

    expect(metric).toEqual({
      adoptionPercent: 8,
      pqcReady: 2, // pqc_ready + symmetric_safe
      total: 13,
      needsMigration: 4,
      unclassified: 7,
    });
  });

  // M-2 regression: needsMigration + unclassified must NOT be collapsed into a
  // single "on classical crypto" figure — an implementation with no algorithm
  // data is a data-quality gap, not evidence it uses classical crypto.
  it('never folds unclassified into needsMigration', () => {
    const metric = getDashboardPqcMetric({
      pqc_percentage: 0,
      pqc_ready: 0,
      symmetric_safe: 0,
      non_pqc: 4,
      unclassified: 7,
      total_implementations: 11,
    });

    expect(metric.needsMigration).toBe(4);
    expect(metric.unclassified).toBe(7);
    expect(metric.needsMigration + metric.unclassified).toBe(metric.total - metric.pqcReady);
  });

  it('keeps new-tenant and loading states at zero', () => {
    expect(getDashboardPqcMetric(undefined)).toEqual({
      adoptionPercent: 0,
      pqcReady: 0,
      total: 0,
      needsMigration: 0,
      unclassified: 0,
    });
  });
});
