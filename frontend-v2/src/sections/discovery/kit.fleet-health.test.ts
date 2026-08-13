import { describe, it, expect } from 'vitest';
import { onlineCount, combinedFleetHealth } from './kit';

// M-13: the Command Center "Sensors online" tile used to be computed from
// sensor-manager rows only (via /sensors/stats), while the Sensors & Agents
// page header counts sensors + device agents. A device agent going offline
// never moved the tile — it stayed "3/3 all healthy" even though a 4th fleet
// member (an agent) had gone dark. combinedFleetHealth is what the tile now
// uses to combine both fleets so the two surfaces can't disagree.

const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();

describe('onlineCount', () => {
  it('counts only members sensorOnline considers up', () => {
    const rows = [
      { status: 'active', last_heartbeat: minutesAgo(1) },
      { status: 'active', last_heartbeat: minutesAgo(60) }, // stale heartbeat
      { status: 'offline', last_heartbeat: minutesAgo(1) },
    ];
    expect(onlineCount(rows)).toBe(1);
  });

  it('is zero for an empty fleet', () => {
    expect(onlineCount([])).toBe(0);
  });
});

describe('combinedFleetHealth', () => {
  it('combines sensors and agents into one online/total pair', () => {
    const sensors = [
      { status: 'active', last_heartbeat: minutesAgo(1) },
      { status: 'active', last_heartbeat: minutesAgo(1) },
      { status: 'active', last_heartbeat: minutesAgo(1) },
    ];
    const agents = [{ status: 'active', last_heartbeat: minutesAgo(1) }];
    expect(combinedFleetHealth(sensors, agents)).toEqual({ online: 4, total: 4, offline: 0 });
  });

  it('reflects a device agent going offline even when every sensor is healthy', () => {
    // This is the exact M-13 scenario: 3/3 sensors online, but the tile must
    // stop reading "all healthy" once the one device agent goes dark.
    const sensors = [
      { status: 'active', last_heartbeat: minutesAgo(1) },
      { status: 'active', last_heartbeat: minutesAgo(1) },
      { status: 'active', last_heartbeat: minutesAgo(1) },
    ];
    const staleAgent = [{ status: 'active', last_heartbeat: minutesAgo(60) }]; // status frozen 'active', heartbeat stale
    const result = combinedFleetHealth(sensors, staleAgent);
    expect(result).toEqual({ online: 3, total: 4, offline: 1 });
    expect(result.offline).toBeGreaterThan(0);
  });

  it('handles an empty agent fleet the same as sensors-only', () => {
    const sensors = [{ status: 'active', last_heartbeat: minutesAgo(1) }];
    expect(combinedFleetHealth(sensors, [])).toEqual({ online: 1, total: 1, offline: 0 });
  });

  it('handles no sensors and no agents', () => {
    expect(combinedFleetHealth([], [])).toEqual({ online: 0, total: 0, offline: 0 });
  });
});
