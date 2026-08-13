import { describe, expect, it } from 'vitest';
import {
  configStrength, ipInCidr, ipv4ToInt, keyAlgorithmLabel, segmentForAsset,
  stripEmptyParens, stripInetMask,
} from './lens-helpers';
import type { CryptoConfig } from './drawers';

// M-4: a config with no resolved risk_score is NOT ASSESSED, not "Strong".
describe('configStrength', () => {
  it('groups a null risk_score as Not assessed, not Strong', () => {
    const cfg = { risk_score: null } as unknown as CryptoConfig;
    expect(configStrength(cfg)).toBe('Not assessed');
  });

  it('groups a risk_score of 0 as Not assessed (score 0 == NOT ASSESSED convention)', () => {
    const cfg = { risk_score: 0 } as unknown as CryptoConfig;
    expect(configStrength(cfg)).toBe('Not assessed');
  });

  it('groups a genuinely low-but-assessed score as Strong', () => {
    const cfg = { risk_score: 5 } as unknown as CryptoConfig;
    expect(configStrength(cfg)).toBe('Strong');
  });

  it('groups a critical score as Weak and a medium score as Acceptable', () => {
    expect(configStrength({ risk_score: 95 } as unknown as CryptoConfig)).toBe('Weak');
    expect(configStrength({ risk_score: 50 } as unknown as CryptoConfig)).toBe('Acceptable');
  });
});

// M-11: display-time CIDR matching for the Network lens.
describe('ipv4ToInt / ipInCidr', () => {
  it('parses a plain IPv4 address', () => {
    expect(ipv4ToInt('192.0.2.173')).toBe(192 * 2 ** 24 + 0 * 2 ** 16 + 2 * 2 ** 8 + 173);
  });

  it('rejects malformed input', () => {
    expect(ipv4ToInt('not-an-ip')).toBeNull();
    expect(ipv4ToInt('999.1.1.1')).toBeNull();
  });

  it('matches an address inside the CIDR block', () => {
    expect(ipInCidr('192.0.2.173', '192.0.2.0/24')).toBe(true);
  });

  it('rejects an address outside the CIDR block', () => {
    expect(ipInCidr('10.0.0.5', '192.0.2.0/24')).toBe(false);
  });

  it('rejects a malformed CIDR rather than throwing', () => {
    expect(ipInCidr('192.0.2.173', 'garbage')).toBe(false);
  });
});

describe('segmentForAsset', () => {
  const segs = [{ name: 'Lab', segment_type: 'cidr', value: '192.0.2.0/24' }];

  it('finds the segment an unassigned asset IP belongs to (#M-11)', () => {
    expect(segmentForAsset('192.0.2.42', segs)).toBe('Lab');
  });

  it('returns null when the IP matches no known segment', () => {
    expect(segmentForAsset('10.0.0.1', segs)).toBeNull();
  });

  it('returns null for a null/undefined IP', () => {
    expect(segmentForAsset(null, segs)).toBeNull();
    expect(segmentForAsset(undefined, segs)).toBeNull();
  });

  it('ignores non-cidr segment types (not yet supported at display time)', () => {
    const domainSeg = [{ name: 'DMZ', segment_type: 'domain', value: 'example.com' }];
    expect(segmentForAsset('192.0.2.42', domainSeg)).toBeNull();
  });
});

// L-1: strip /32 and /128 masks, and a dangling empty-parens artifact.
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
