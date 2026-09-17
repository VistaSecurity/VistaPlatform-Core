import { describe, it, expect } from 'vitest';
import { configProvenance } from './asset-page';

/**
 * The provenance chips on the Cryptography tab read `discovery_methods` — the
 * full list of methods that contributed to ONE configuration, now that a
 * passive glimpse and the active probe that completes it are one row rather
 * than two. Rows written before that array existed fall back to the single
 * `discovery_method`, and the chips never invent a method.
 */
describe('configProvenance', () => {
  it('lists every contributing method, primary first, as the API sends them', () => {
    expect(configProvenance({ discovery_method: 'passive', discovery_methods: ['passive', 'active'] }))
      .toEqual(['passive', 'active']);
  });

  it('falls back to the primary method for a row not yet backfilled', () => {
    expect(configProvenance({ discovery_method: 'active', discovery_methods: [] })).toEqual(['active']);
  });

  it('never fabricates a method', () => {
    expect(configProvenance({ discovery_method: '', discovery_methods: [] })).toEqual([]);
    // Tolerates a pre-contract payload where the array is absent entirely.
    expect(configProvenance({ discovery_method: 'manual' } as unknown as Parameters<typeof configProvenance>[0]))
      .toEqual(['manual']);
  });
});
