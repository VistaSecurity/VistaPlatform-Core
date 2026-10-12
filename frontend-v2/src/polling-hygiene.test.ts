// Polling must stop when nothing is in flight.
import { describe, expect, it } from 'vitest';
import { pcapRefetchInterval } from './sections/discovery/queries';
import { reevaluationRefetchInterval } from './sections/posture/queries';

const q = (data: unknown) => ({ state: { data } }) as never;

describe('pcapRefetchInterval', () => {
  it('stops when every job has settled (or there are none)', () => {
    expect(pcapRefetchInterval(q({ jobs: [{ status: 'completed' }, { status: 'failed' }] }))).toBe(false);
    expect(pcapRefetchInterval(q({ jobs: null }))).toBe(false);
    expect(pcapRefetchInterval(q(undefined))).toBe(false);
  });
  it('polls while a job is queued or processing', () => {
    expect(pcapRefetchInterval(q({ jobs: [{ status: 'completed' }, { status: 'processing' }] }))).toBe(15_000);
    expect(pcapRefetchInterval(q({ jobs: [{ status: 'queued' }] }))).toBe(15_000);
  });
});

describe('reevaluationRefetchInterval', () => {
  const now = Date.parse('2026-10-11T12:00:00Z');
  it('does not poll when a run is allowed', () => {
    expect(reevaluationRefetchInterval(q({ allowed: true, next_allowed_at: null }), now)).toBe(false);
  });
  it('polls only while the cooldown is still running', () => {
    expect(reevaluationRefetchInterval(q({ allowed: false, next_allowed_at: '2026-10-11T12:30:00Z' }), now)).toBe(30_000);
    expect(reevaluationRefetchInterval(q({ allowed: false, next_allowed_at: '2026-10-11T11:00:00Z' }), now)).toBe(false);
  });
});
