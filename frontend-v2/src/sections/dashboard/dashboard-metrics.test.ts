import { describe, expect, it } from 'vitest';
import { getDashboardPqcMetric } from './dashboard-metrics';

describe('dashboard PQC metric', () => {
  it('uses inventory PQC adoption rather than a framework-style score', () => {
    const metric = getDashboardPqcMetric({
      readiness_percent: 8,
      pqc_implementations: 2,
      total_implementations: 25,
      // This mirrors the old, wrong fallback source. It must not affect the dashboard.
      compliance_percent: 45,
    } as Parameters<typeof getDashboardPqcMetric>[0] & { compliance_percent: number });

    expect(metric).toEqual({
      adoptionPercent: 8,
      pqcReady: 2,
      total: 25,
      configsOnClassicalCrypto: 23,
    });
  });

  it('keeps new-tenant and loading states at zero', () => {
    expect(getDashboardPqcMetric(undefined)).toEqual({
      adoptionPercent: 0,
      pqcReady: 0,
      total: 0,
      configsOnClassicalCrypto: 0,
    });
  });
});
