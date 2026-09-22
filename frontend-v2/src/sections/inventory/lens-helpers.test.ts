import { describe, expect, it } from 'vitest';
import {
  configurationRiskGroup, effectiveInventoryRiskFilter, groupConfigurationsByRisk,
  keyAlgorithmLabel, keyCustodyDetail, keyCustodyLabel, serviceConfidence,
  stripEmptyParens, stripInetMask,
} from './lens-helpers';
import type { CryptoConfig } from './drawers';

// The asset-row derivations these tests used to cover moved to
// `asset-shape.test.ts` with ADR-0002: they read `ip_address`, `port`,
// `asset_type` and `operating_system`, none of which are columns any more, and
// the rules they pinned are pinned there against the new shape. The network
// lens's display-time CIDR matcher went with the network lens — segment
// membership is a `segment_id:` term on the class-faceted list now, matched
// server-side.

// M-4: a config with no resolved risk_score is NOT ASSESSED, not "Strong".
describe('configurationRiskGroup', () => {
  it('groups a null risk_score as Not assessed, not Strong', () => {
    const cfg = { risk_score: null } as unknown as CryptoConfig;
    expect(configurationRiskGroup(cfg)).toBe('Not assessed');
  });

  it('groups an unmarked legacy risk_score of 0 as Not assessed', () => {
    const cfg = { risk_score: 0, risk_score_assessed: false } as unknown as CryptoConfig;
    expect(configurationRiskGroup(cfg)).toBe('Not assessed');
  });

  it('groups explicit assessed scores by canonical numeric risk band', () => {
    expect(configurationRiskGroup({ risk_score: 0, risk_score_assessed: true } as unknown as CryptoConfig)).toBe('Informational');
    expect(configurationRiskGroup({ risk_score: 5 } as unknown as CryptoConfig)).toBe('Low');
    expect(configurationRiskGroup({ risk_score: 50 } as unknown as CryptoConfig)).toBe('Medium');
    expect(configurationRiskGroup({ risk_score: 95 } as unknown as CryptoConfig)).toBe('Critical');
  });

  it('does not infer qualitative strength words from the numeric score', () => {
    expect(configurationRiskGroup({ risk_score: 0, risk_score_assessed: true, strength: 'weak' } as unknown as CryptoConfig)).toBe('Informational');
    expect(configurationRiskGroup({ risk_score: 90, strength: 'strong' } as unknown as CryptoConfig)).toBe('Critical');
  });

  it('groups weak score 0 and strong score 90 by numeric risk without strength labels', () => {
    const weakZero = { id: 'weak-zero', risk_score: 0, risk_score_assessed: true, strength: 'weak' } as unknown as CryptoConfig;
    const strongNinety = { id: 'strong-ninety', risk_score: 90, strength: 'strong' } as unknown as CryptoConfig;
    expect(groupConfigurationsByRisk([weakZero, strongNinety])).toEqual([
      { riskGroup: 'Critical', list: [strongNinety] },
      { riskGroup: 'Informational', list: [weakZero] },
    ]);
  });
});

describe('effectiveInventoryRiskFilter', () => {
  it('scopes Not assessed to configuration lenses on the first render after a switch', () => {
    expect(effectiveInventoryRiskFilter('Not assessed', true)).toBe('Not assessed');
    expect(effectiveInventoryRiskFilter('Not assessed', false)).toBe('All');
  });

  it('preserves common risk-band preferences across lens switches', () => {
    expect(effectiveInventoryRiskFilter('High', true)).toBe('High');
    expect(effectiveInventoryRiskFilter('High', false)).toBe('High');
  });
});

// M-11: display-time CIDR matching for the Network lens.
describe('stripInetMask', () => {
  it('strips a trailing /32 from an IPv4 address', () => {
    expect(stripInetMask('192.0.2.173/32')).toBe('192.0.2.173');
  });

  it('strips a trailing /128 from an IPv6 address', () => {
    expect(stripInetMask('::1/128')).toBe('::1');
  });

  it('leaves a bare IP untouched', () => {
    expect(stripInetMask('104.18.4.149')).toBe('104.18.4.149');
  });

  it('leaves a real subnet mask (not a bare host) untouched', () => {
    expect(stripInetMask('192.0.2.0/24')).toBe('192.0.2.0/24');
  });

  it('passes through null/undefined', () => {
    expect(stripInetMask(null)).toBeUndefined();
    expect(stripInetMask(undefined)).toBeUndefined();
  });
});

describe('stripEmptyParens', () => {
  it('strips a trailing empty-parens artifact', () => {
    expect(stripEmptyParens('QUIC v1 ()')).toBe('QUIC v1');
  });

  it('leaves a populated parenthetical untouched', () => {
    expect(stripEmptyParens('QUIC v1 (TLS 1.3)')).toBe('QUIC v1 (TLS 1.3)');
  });

  it('leaves a value with no parens untouched', () => {
    expect(stripEmptyParens('TLS 1.3')).toBe('TLS 1.3');
  });
});

// L-8: Keys lens Algorithm cell falls back to key_type when algorithm_ref is null.
describe('keyAlgorithmLabel', () => {
  it('falls back to key_type when algorithm_ref is null', () => {
    expect(keyAlgorithmLabel(null, 'ECDSA', '256-bit')).toBe('ECDSA · 256-bit');
  });

  it('prefers algorithm_ref when present', () => {
    expect(keyAlgorithmLabel('ECDSA-P256', 'ECDSA', '256-bit')).toBe('ECDSA-P256 · 256-bit');
  });

  it('falls back to em dash when nothing is available', () => {
    expect(keyAlgorithmLabel(null, null, '')).toBe('—');
  });
});

// The backend has always sent confidence + method; the drawer showed neither,
// so a name guessed from a port number looked exactly as solid as one read out
// of a banner. These pin that the two now READ differently.
describe('serviceConfidence', () => {
  it('labels a port-heuristic name as a guess', () => {
    const { qualifier, title } = serviceConfidence({
      service_confidence: 'low', service_identification_method: 'port_heuristic',
    });
    expect(qualifier).toBe('Best guess · from port');
    expect(title).toMatch(/port number alone/i);
  });

  it('labels a banner match more strongly than a port guess', () => {
    expect(serviceConfidence({
      service_confidence: 'high', service_identification_method: 'banner',
    }).qualifier).toBe('Confirmed · from banner');
    expect(serviceConfidence({
      service_confidence: 'medium', service_identification_method: 'ja3s',
    }).qualifier).toBe('Likely · from TLS fingerprint');
  });

  it('says a manual name was entered, not discovered', () => {
    expect(serviceConfidence({
      service_confidence: 'high', service_identification_method: 'manual',
    }).qualifier).toBe('Set manually');
  });

  it('claims nothing when the backend sent no method', () => {
    expect(serviceConfidence({})).toEqual({ qualifier: null, title: null });
    expect(serviceConfidence({ service_confidence: 'low' })).toEqual({ qualifier: null, title: null });
  });

  it('is case-insensitive about what the backend sends', () => {
    expect(serviceConfidence({
      service_confidence: 'LOW', service_identification_method: 'Port_Heuristic',
    }).qualifier).toBe('Best guess · from port');
  });
});

// Cloud KMS keys reach the Keys lens carrying `key_custody`. The badge is the
// one place a person sees the difference between a key THEY control and one the
// provider holds — the same distinction the Data Protection lens's protection
// ladder is built on — so the two states must read differently, and an ABSENT
// custody must read as nothing at all rather than as either answer.
describe('keyCustodyLabel', () => {
  it('names both custody states, distinctly', () => {
    expect(keyCustodyLabel('customer')).toBe('Customer-managed');
    expect(keyCustodyLabel('provider')).toBe('Provider-managed');
    expect(keyCustodyLabel('customer')).not.toBe(keyCustodyLabel('provider'));
  });

  it('claims nothing when custody was not established', () => {
    // A certificate-derived key, or a cloud key whose manager the provider did
    // not report. Absent is NOT "provider": rendering a guess there would be the
    // same overclaim the not-assessed risk state exists to avoid.
    expect(keyCustodyLabel(undefined)).toBeNull();
    expect(keyCustodyLabel(null)).toBeNull();
    expect(keyCustodyLabel('')).toBeNull();
    expect(keyCustodyLabel('unknown')).toBeNull();
    // The RAW provider wording is not a custody value — the backend normalises
    // it, and the UI must not start accepting a second vocabulary.
    expect(keyCustodyLabel('AWS')).toBeNull();
  });

  it('explains what each state means on hover, and explains nothing when there is no badge', () => {
    expect(keyCustodyDetail('customer')).toMatch(/you control this key/i);
    expect(keyCustodyDetail('provider')).toMatch(/you do not control the key/i);
    expect(keyCustodyDetail(undefined)).toBeNull();
  });
});
