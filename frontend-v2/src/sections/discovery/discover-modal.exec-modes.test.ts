import { describe, it, expect } from 'vitest';
import { EXEC_MODES } from './discover-modal';

// The wizard used to offer "Sensors — tenant-deployed" as an execution mode.
// Nothing dispatches a discovery job to a tenant-deployed sensor: no code turns
// a job into a sensor command, the sensor's command switch has no discovery
// case, and requested_sensor_ids is stored but consumed by nothing. Picking it
// produced a scan that ran from the platform cluster instead — unable to reach a
// target only the tenant's sensor can see — and a job that reported `completed`
// with zero findings.
//
// The API now rejects execution_mode "sensors" with 400, so leaving the option
// in the dropdown would be a control that can only produce an error. It is gone
// until dispatch is actually built.

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
