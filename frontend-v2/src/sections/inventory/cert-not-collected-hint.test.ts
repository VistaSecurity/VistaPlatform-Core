// The Connections lens explains a missing certificate when third-party
// enrichment is off ( W5.13). The helper decides; the second block pins
// that the lens consults it (inventory-page.tsx has no DOM-rendering harness —
// see inventory-page.connections-hygiene.test.ts — so the wiring is checked
// structurally, like that guard).
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { CERT_NOT_COLLECTED_HINT, certNotCollectedHint, thirdPartyEnrichmentOff } from './cert-not-collected-hint';
import type { Setting } from '../discovery/agent-config';

const setting = (value: boolean): Setting => ({
  key: 'third_party_tls_enrichment', value, origin: 'built_in', kind: 'bool', apply: 'immediate', description: '',
});

describe('thirdPartyEnrichmentOff', () => {
  it('is true only when the setting is present and off', () => {
    expect(thirdPartyEnrichmentOff([setting(false)])).toBe(true);
    expect(thirdPartyEnrichmentOff([setting(true)])).toBe(false);
    // Unknown is not "off": not loaded, no permission, or an older platform.
    expect(thirdPartyEnrichmentOff(undefined)).toBe(false);
    expect(thirdPartyEnrichmentOff([])).toBe(false);
  });
});

describe('certNotCollectedHint', () => {
  it('explains a missing certificate when enrichment is off', () => {
    expect(certNotCollectedHint({ cert_not_after: null }, true)).toBe(CERT_NOT_COLLECTED_HINT);
    expect(CERT_NOT_COLLECTED_HINT).toBe('Certificate not collected: active enrichment of third parties is off');
  });
  it('says nothing when there is a certificate, the connection is elevated, or enrichment is on or unknown', () => {
    expect(certNotCollectedHint({ cert_not_after: '2027-01-01T00:00:00Z' }, true)).toBeUndefined();
    expect(certNotCollectedHint({ cert_not_after: null, elevated_asset_id: 'a1' }, true)).toBeUndefined();
    expect(certNotCollectedHint({ cert_not_after: null }, false)).toBeUndefined();
  });
});

describe('Connections lens wiring', () => {
  const src = readFileSync(fileURLToPath(new URL('./inventory-page.tsx', import.meta.url)), 'utf8');
  it('reads the sensor fleet defaults on the Connections lens and decides the hint per row', () => {
    expect(src).toMatch(/useSensorFleetDefaults\(isConn\)/);
    expect(src).toMatch(/thirdPartyEnrichmentOff\(sensorDefaults\.data\?\.settings\)/);
    expect(src).toMatch(/certNotCollectedHint\(cn, enrichmentOff\)/);
    expect(src).toMatch(/title=\{notCollected\}/);
  });
});
