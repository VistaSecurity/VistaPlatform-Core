import { describe, it, expect } from 'vitest';
import { jobTypeLabel } from './kit';

// Job Logs rendered `job_type` raw, so a run showed as `device_interrogation`.
// `host_inventory` (asset-inventory 2.11a) is the first job type whose raw name
// does not read as English at all, which is what forced the map.

describe('jobTypeLabel', () => {
  it('names the three job types', () => {
    expect(jobTypeLabel('device_interrogation')).toBe('Device interrogation');
    expect(jobTypeLabel('cloud_discovery')).toBe('Cloud discovery');
    expect(jobTypeLabel('host_inventory')).toBe('Host inventory');
  });

  it('is case-insensitive and tolerates surrounding space', () => {
    expect(jobTypeLabel('  HOST_INVENTORY ')).toBe('Host inventory');
  });

  // A job type added server-side should be readable before anyone edits this
  // file — the same fall-through deviceTypeLabel uses.
  it('prettifies an unknown type rather than shouting snake_case', () => {
    expect(jobTypeLabel('sbom_import')).toBe('Sbom import');
    expect(jobTypeLabel('rescan')).toBe('Rescan');
  });

  it('returns undefined for nothing, so callers fall back to their own dash', () => {
    expect(jobTypeLabel(undefined)).toBeUndefined();
    expect(jobTypeLabel(null)).toBeUndefined();
    expect(jobTypeLabel('   ')).toBeUndefined();
  });
});
