import { describe, expect, it } from 'vitest';
import { DASHBOARD_COMPLIANCE_FINDINGS_ROUTE, getDashboardPqcMetric, getDiscoveryFleetMetric, isAgentRow } from './dashboard-metrics';

describe('dashboard findings links', () => {
  it('deep-links compliance-derived finding counts to the compliance lens', () => {
    expect(DASHBOARD_COMPLIANCE_FINDINGS_ROUTE).toBe('/risk-compliance/findings?lens=framework');
  });
});

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

describe('dashboard discovery fleet metric', () => {
  // The exact fleet that produced the bug report: 2 sensors + 2 agents reading
  // "3/3 sensors". Three rows come from /sensors (one of which is the seeded
  // platform interrogation AGENT) and one registered agent from /agents was not
  // counted at all.
  const sensorRows = [
    { name: 'Platform Discovery Sensor', status: 'active', profile: 'discovery', sensor_type: 'network', tags: ['system', 'platform', 'discovery'] },
    { name: 'Platform Device Interrogation Agent', status: 'active', profile: 'device_interrogation', sensor_type: 'api', tags: ['system', 'platform', 'device_interrogation'] },
    { name: 'winsensor1', status: 'active', profile: 'datacenter_host', sensor_type: 'network', tags: [] },
  ];
  const agentRows = [{ name: 'win-device-agent-1', status: 'active' }];

  it('counts both fleets and splits sensors from agents', () => {
    const fleet = getDiscoveryFleetMetric(sensorRows, agentRows);

    expect(fleet.all).toEqual({ online: 4, total: 4 });      // was 3/3
    expect(fleet.sensors).toEqual({ online: 2, total: 2 });
    expect(fleet.agents).toEqual({ online: 2, total: 2 });   // platform agent + registered agent
  });

  it('classifies the platform interrogation agent as an agent, not a sensor', () => {
    expect(isAgentRow(sensorRows[1])).toBe(true);
    expect(isAgentRow(sensorRows[0])).toBe(false);
    expect(isAgentRow(sensorRows[2])).toBe(false);
  });

  it('counts only active rows as online, per fleet', () => {
    const fleet = getDiscoveryFleetMetric(
      [{ ...sensorRows[0], status: 'offline' }, sensorRows[1], sensorRows[2]],
      [{ status: 'inactive' }],
    );

    expect(fleet.sensors).toEqual({ online: 1, total: 2 });
    expect(fleet.agents).toEqual({ online: 1, total: 2 });
    expect(fleet.all).toEqual({ online: 2, total: 4 });
  });

  it('is empty-safe while either query is still loading', () => {
    expect(getDiscoveryFleetMetric(undefined, undefined).all).toEqual({ online: 0, total: 0 });
    expect(getDiscoveryFleetMetric(sensorRows, undefined).agents).toEqual({ online: 1, total: 1 });
  });
});
