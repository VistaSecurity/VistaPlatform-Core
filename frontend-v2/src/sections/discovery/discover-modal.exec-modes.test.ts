import { describe, it, expect } from 'vitest';
import { EXEC_MODES } from './discover-modal';

// The wizard does not offer "Sensors — tenant-deployed" as an execution mode.
// Dispatch to a tenant sensor exists, but a `sensors` job names ONE
// sensor, and the wizard has no sensor picker — a bare "sensors" option would
// be a control that can only produce a 400. The sensor choice lives on
// Discovery → Active Scan's "Run from".

describe('EXEC_MODES', () => {
  it('does not offer tenant-sensor dispatch', () => {
    expect(EXEC_MODES.map((m) => m.value)).not.toContain('sensors');
    expect(EXEC_MODES.some((m) => /sensors\b.*tenant|tenant-deployed/i.test(m.label))).toBe(false);
  });

  it('offers exactly the modes the API accepts', () => {
    expect(EXEC_MODES.map((m) => m.value)).toEqual(['auto', 'cloud']);
  });

  it('gives every mode a label', () => {
    for (const m of EXEC_MODES) {
      expect(m.label.trim()).not.toBe('');
    }
  });
});
