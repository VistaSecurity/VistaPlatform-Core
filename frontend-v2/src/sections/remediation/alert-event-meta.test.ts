// Which way the severity went, in the timeline's icon.
//
// The alert engine now LOWERS an open alert to the rung its findings actually
// reach, writing a `severity_changed` event with `direction: 'lowered'`. The
// timeline's icon table was written when the only direction was up, so every
// severity change rendered a `trending-up` arrow labelled "Severity changed" —
// a de-escalation drawn as an escalation, on the one row a person reads to find
// out which way it went.
//
// The from → to pills below it were always right, which is why this is worth a
// test rather than a shrug: the row contradicted itself.
import { describe, expect, it } from 'vitest';
import { eventMeta } from './alerts-page';

const ev = (event_type: string, details?: Record<string, unknown>) =>
  ({ event_type, details }) as Parameters<typeof eventMeta>[0];

describe('eventMeta', () => {
  it('draws a lowered severity with a DOWNWARD arrow and says so', () => {
    const m = eventMeta(ev('severity_changed', { from: 'critical', to: 'medium', direction: 'lowered' }));
    expect(m.icon).toBe('trending-down');
    expect(m.label).toBe('Severity lowered');
  });

  it('draws a raised severity with an upward arrow', () => {
    const m = eventMeta(ev('severity_changed', { from: 'medium', to: 'critical', direction: 'raised' }));
    expect(m.icon).toBe('trending-up');
    expect(m.label).toBe('Severity raised');
  });

  // Raise has never stamped a direction, so every escalation already on record
  // carries none. Those keep the neutral label and the old arrow rather than
  // having a direction guessed for them by re-ranking two severity strings —
  // the details block underneath still shows from → to.
  it('leaves a directionless severity change neutral rather than guessing', () => {
    for (const details of [undefined, {}, { from: 'low', to: 'high' }, { direction: 'sideways' }]) {
      const m = eventMeta(ev('severity_changed', details));
      expect(m.icon).toBe('trending-up');
      expect(m.label).toBe('Severity changed');
    }
  });

  it('is unchanged for every other event type, known and unknown', () => {
    expect(eventMeta(ev('opened'))).toEqual({ icon: 'bell', label: 'Opened' });
    expect(eventMeta(ev('resolved'))).toEqual({ icon: 'check-check', label: 'Resolved' });
    expect(eventMeta(ev('something_new'))).toEqual({ icon: 'circle-dot', label: 'something new' });
  });
});
