import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  configStrength, ipInCidr, ipv4ToInt, keyAlgorithmLabel, segmentForAsset,
  stripEmptyParens, stripInetMask,
  assetIdentity, assetLocation, assetService, serviceConfidence, assetRisk, protocolBadges,
  configCount, certCount, assetStatusBadge, relativeTime,
  type InfraRowAsset,
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

// ---- Infrastructure lens Tier-1 row -----------------------------------------
// The case that motivated this work: a sensor-discovered asset with nothing but
// an IP. Every helper must degrade to an explicit absence, never to a
// confident-looking value.
const BARE: InfraRowAsset = {
  hostname: null, ip_address: '192.0.2.41', port: null, asset_type: null,
  operating_system: null, environment: null, network_segment_name: null,
  business_unit: null, service_name: null, service_version: null,
  asset_status: 'monitoring', stale_status: null, last_seen_at: null,
  risk_score: 0, risk_level: 'Informational', certificate_count: 0,
  crypto_implementation_count: 0, protocol_summary: [],
};

describe('assetIdentity', () => {
  it('titles by hostname and puts the address + type/OS on the sub-line', () => {
    expect(assetIdentity({ hostname: 'edge-01', ip_address: '192.0.2.10', port: 443, asset_type: 'server', operating_system: 'Linux' }))
      .toEqual({ primary: 'edge-01', secondary: '192.0.2.10:443 · server · Linux' });
  });

  it('falls back to the address as the TITLE when there is no hostname, and does not repeat it below', () => {
    expect(assetIdentity(BARE)).toEqual({ primary: '192.0.2.41', secondary: '' });
  });

  it('strips a /32 host mask from the address', () => {
    expect(assetIdentity({ ip_address: '198.51.100.7/32' }).primary).toBe('198.51.100.7');
  });

  it('renders an em dash when neither hostname nor address is known', () => {
    expect(assetIdentity({}).primary).toBe('—');
  });

  it('treats whitespace-only fields as absent rather than as a value', () => {
    expect(assetIdentity({ hostname: '   ', ip_address: '192.0.2.9' }).primary).toBe('192.0.2.9');
  });
});

describe('assetLocation', () => {
  it('returns the environment and a segment path when known', () => {
    expect(assetLocation({ environment: 'production', network_segment_name: 'DMZ', region: 'us-east-1' }))
      .toEqual({ environment: 'production', path: 'DMZ · us-east-1' });
  });

  it('falls back to business unit when there is no segment', () => {
    expect(assetLocation({ business_unit: 'Payments' }).path).toBe('Payments');
  });

  it('returns nulls (→ em dash in the row) when nothing is known', () => {
    expect(assetLocation(BARE)).toEqual({ environment: null, path: null });
  });
});

describe('assetService', () => {
  it('normalises the version to a single v prefix', () => {
    expect(assetService({ service_name: 'nginx', service_version: '1.25.3' })).toEqual({ name: 'nginx', version: 'v1.25.3' });
    expect(assetService({ service_name: 'nginx', service_version: 'v1.25.3' }).version).toBe('v1.25.3');
  });

  it('drops a version with no service name — a bare "v1.2" is not a service', () => {
    expect(assetService({ service_version: '1.2' })).toEqual({ name: null, version: null });
  });

  it('returns nulls for an unidentified service', () => {
    expect(assetService(BARE)).toEqual({ name: null, version: null });
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

// The core honesty guard: score 0 means NOT ASSESSED, not "safe".
describe('assetRisk', () => {
  it('marks a score of 0 as UNassessed, labels it em dash, and says so', () => {
    const r = assetRisk(BARE);
    expect(r.assessed).toBe(false);
    expect(r.label).toBe('—');
    expect(r.title).toMatch(/not assessed/i);
  });

  it('does not let a missing risk_score become an assessed result', () => {
    expect(assetRisk({}).assessed).toBe(false);
    expect(assetRisk({ risk_score: null }).assessed).toBe(false);
  });

  it('reports an assessed score with the backend-supplied level', () => {
    const r = assetRisk({ risk_score: 75, risk_level: 'High' });
    expect(r).toMatchObject({ assessed: true, score: 75, level: 'High', label: '75' });
  });

  it('bands with the shared CVSS ladder when the backend sent no level', () => {
    expect(assetRisk({ risk_score: 95 }).level).toBe('Critical');
    expect(assetRisk({ risk_score: 70 }).level).toBe('High');
    expect(assetRisk({ risk_score: 40 }).level).toBe('Medium');
    expect(assetRisk({ risk_score: 1 }).level).toBe('Low');
  });
});

describe('protocolBadges', () => {
  const summary = [
    { protocol: 'TLS', count: 6, max_risk_score: 82 },
    { protocol: 'SSH', count: 2, max_risk_score: 0 },
    { protocol: 'SMB', count: 1, max_risk_score: 30 },
    { protocol: 'MODBUS', count: 1, max_risk_score: 95 },
  ];

  it('caps the badges and reports the overflow', () => {
    const { badges, overflow } = protocolBadges({ protocol_summary: summary });
    expect(badges.map((b) => b.label)).toEqual(['TLS', 'SSH', 'SMB']);
    expect(overflow).toBe(1);
  });

  it('honours a tighter cap (the row passes 2 so the cell does not overflow)', () => {
    const { badges, overflow } = protocolBadges({ protocol_summary: summary }, 2);
    expect(badges.map((b) => b.label)).toEqual(['TLS', 'SSH']);
    expect(overflow).toBe(2);
  });

  it('bands a badge by its worst score', () => {
    const { badges } = protocolBadges({ protocol_summary: summary });
    expect(badges[0]).toMatchObject({ label: 'TLS', level: 'High', assessed: true });
  });

  it('keeps a max_risk_score of 0 UNassessed rather than claiming Informational safety', () => {
    const { badges } = protocolBadges({ protocol_summary: summary });
    expect(badges[1].assessed).toBe(false);
    expect(badges[1].title).toMatch(/not assessed/i);
  });

  it('returns nothing when the service sent no summary at all', () => {
    expect(protocolBadges({})).toEqual({ badges: [], overflow: 0 });
    expect(protocolBadges(BARE).badges).toEqual([]);
  });

  it('ignores blank protocol names', () => {
    expect(protocolBadges({ protocol_summary: [{ protocol: '  ', count: 3, max_risk_score: 10 }] }).badges).toEqual([]);
  });
});

describe('configCount / certCount', () => {
  it('returns null for a config count the service did not send (omit, do not assert zero)', () => {
    expect(configCount({})).toBeNull();
  });

  it('returns a genuine zero when the service counted zero', () => {
    expect(configCount(BARE)).toBe(0);
  });

  it('treats a missing certificate_count as 0 — the list query always counts it', () => {
    expect(certCount({})).toBe(0);
    expect(certCount({ certificate_count: 3 })).toBe(3);
  });
});

describe('assetStatusBadge', () => {
  it('shows no badge for the steady state', () => {
    expect(assetStatusBadge(BARE)).toBeNull();
  });

  it('badges a pending-approval asset', () => {
    expect(assetStatusBadge({ asset_status: 'pending_approval' })?.text).toBe('pending');
  });

  it('lets archived win over the underlying status', () => {
    expect(assetStatusBadge({ asset_status: 'pending_approval', stale_status: 'archived' })?.text).toBe('archived');
  });

  it('surfaces a stale warning on an otherwise-normal asset', () => {
    expect(assetStatusBadge({ asset_status: 'monitoring', stale_status: 'warning' })?.text).toBe('stale');
  });

  it('humanises an unexpected status rather than hiding it', () => {
    expect(assetStatusBadge({ asset_status: 'decommissioned' })?.text).toBe('decommissioned');
    expect(assetStatusBadge({ asset_status: 'needs_review' })?.text).toBe('needs review');
  });
});

describe('relativeTime', () => {
  afterEach(() => vi.useRealTimers());

  it('renders an em dash for a missing or unparseable timestamp', () => {
    expect(relativeTime(null)).toBe('—');
    expect(relativeTime(undefined)).toBe('—');
    expect(relativeTime('not-a-date')).toBe('—');
  });

  it('renders an em dash for Go’s zero time instead of "24000mo ago"', () => {
    expect(relativeTime('0001-01-01T00:00:00Z')).toBe('—');
  });

  it('scales the unit with the age', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-01T12:00:00Z'));
    expect(relativeTime('2026-06-01T11:59:30Z')).toBe('just now');
    expect(relativeTime('2026-06-01T11:20:00Z')).toBe('40m ago');
    expect(relativeTime('2026-06-01T04:00:00Z')).toBe('8h ago');
    expect(relativeTime('2026-05-20T12:00:00Z')).toBe('12d ago');
    expect(relativeTime('2026-01-01T12:00:00Z')).toBe('5mo ago');
  });
});
