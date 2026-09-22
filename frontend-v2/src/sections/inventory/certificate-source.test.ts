import { describe, expect, it } from 'vitest';
import { certSourceBadge } from './certificate-source';

describe('certSourceBadge', () => {
  it('names each provenance the inventory can hold', () => {
    expect(certSourceBadge('cloud_api')?.label).toBe('cloud-managed');
    expect(certSourceBadge('manual')?.label).toBe('uploaded');
    expect(certSourceBadge('discovery')?.label).toBe('observed');
  });

  it('says nothing when the provenance was never recorded', () => {
    // "unknown" is the certificate service's default when a row carries no
    // source. It is the absence of an answer, not a fourth kind of certificate,
    // and rendering it as a badge would invent a claim the data does not make.
    for (const v of ['unknown', '', '   ', undefined, null]) {
      expect(certSourceBadge(v)).toBeNull();
    }
  });

  it('gives cloud-managed and observed different tones', () => {
    // The badge has to be readable at a glance; two provenances rendered
    // identically are not distinguishable, which is the requirement.
    expect(certSourceBadge('cloud_api')?.tone).not.toBe(certSourceBadge('discovery')?.tone);
  });
});
