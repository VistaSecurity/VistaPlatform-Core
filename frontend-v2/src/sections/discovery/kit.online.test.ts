import { describe, it, expect } from 'vitest';
import { sensorOnline } from './kit';

// The fleet list shows sensors and discovery agents side by side, but the two
// runtimes maintain their status columns differently: sensor-manager runs a
// reaper that flips a silent sensor to 'offline', while nothing ever rewrites
// device_agents.status — it is hard-coded 'active' at enrollment. Without a
// heartbeat check a dead agent renders with a green dot indefinitely.

const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();

describe('sensorOnline', () => {
  it('treats a recently-beating active subject as online', () => {
    expect(sensorOnline('active', minutesAgo(1))).toBe(true);
  });

  it('treats a long-silent subject as offline even when status still says active', () => {
    // The device-agent case: the column is frozen at enrollment and never
    // updated, so only the heartbeat reveals the truth.
    expect(sensorOnline('active', minutesAgo(60))).toBe(false);
  });

  it('treats a subject that has never checked in as offline', () => {
    expect(sensorOnline('active', null)).toBe(false);
  });

  it('keeps a non-active status offline regardless of heartbeat freshness', () => {
    expect(sensorOnline('offline', minutesAgo(1))).toBe(false);
    expect(sensorOnline('error', minutesAgo(1))).toBe(false);
    expect(sensorOnline('pending', minutesAgo(1))).toBe(false);
  });

  it('falls back to status alone when no heartbeat is supplied', () => {
    expect(sensorOnline('active')).toBe(true);
    expect(sensorOnline('offline')).toBe(false);
    expect(sensorOnline(undefined)).toBe(false);
  });

  it('accepts the alternate online spellings', () => {
    expect(sensorOnline('online', minutesAgo(1))).toBe(true);
    expect(sensorOnline('connected', minutesAgo(1))).toBe(true);
  });
});
