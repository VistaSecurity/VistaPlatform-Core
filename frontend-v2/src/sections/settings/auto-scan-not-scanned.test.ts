import { describe, expect, it } from 'vitest';
import {
  SEGMENTS_SETTINGS_PATH, describeNotScanned, notScannedHeadline, notScannedTotal,
} from './auto-scan-not-scanned';

describe('describeNotScanned', () => {
  it('names each reason in plain language and keeps the count', () => {
    const rows = describeNotScanned([
      { reason: 'public', count: 3 },
      { reason: 'excluded', count: 1 },
    ]);
    expect(rows.map((r) => [r.label, r.count])).toEqual([
      ['Public addresses', 3],
      ['Excluded by your operator', 1],
    ]);
  });

  it('names carrier-grade NAT by its range and the networks that use it', () => {
    // The row this panel exists for. A Tailscale or ZeroTier estate lives
    // entirely in 100.64/10; calling that "public" sends the tenant to look
    // at the wrong thing.
    const [row] = describeNotScanned([{ reason: 'carrier_grade_nat', count: 40 }]);
    expect(row.label).toContain('100.64.0.0/10');
    expect(row.detail).toMatch(/Tailscale/);
    expect(row.detail).toMatch(/ZeroTier/);
  });

  it('offers the register-the-segment action ONLY where a segment would help', () => {
    const rows = describeNotScanned([
      { reason: 'public', count: 1 },
      { reason: 'carrier_grade_nat', count: 1 },
      { reason: 'excluded', count: 1 },
      { reason: 'link_local', count: 1 },
      { reason: 'loopback', count: 1 },
      { reason: 'multicast', count: 1 },
      { reason: 'unspecified', count: 1 },
      { reason: 'zoned', count: 1 },
      { reason: 'unparseable', count: 1 },
    ]);
    const actionable = rows.filter((r) => r.registerSegmentsHref).map((r) => r.reason).sort();
    expect(actionable).toEqual(['carrier_grade_nat', 'public']);
    for (const r of rows.filter((r) => r.registerSegmentsHref)) {
      expect(r.registerSegmentsHref).toBe(SEGMENTS_SETTINGS_PATH);
    }
    // The platform's own addresses can never be brought into scope by a
    // segment — exclusions are checked before segments on purpose — so a
    // link there would promise something the sweep refuses to do.
    expect(rows.find((r) => r.reason === 'excluded')?.registerSegmentsHref).toBeUndefined();
  });

  it('puts the actionable rows first, then larger counts', () => {
    const rows = describeNotScanned([
      { reason: 'link_local', count: 99 },
      { reason: 'public', count: 2 },
      { reason: 'carrier_grade_nat', count: 5 },
      { reason: 'loopback', count: 7 },
    ]);
    expect(rows.map((r) => r.reason)).toEqual(['carrier_grade_nat', 'public', 'link_local', 'loopback']);
  });

  it('drops zero and malformed counts', () => {
    const rows = describeNotScanned([
      { reason: 'public', count: 0 },
      { reason: 'loopback', count: -1 },
      { reason: 'excluded', count: Number.NaN },
      { reason: 'zoned', count: 2 },
    ]);
    expect(rows.map((r) => r.reason)).toEqual(['zoned']);
  });

  it('KEEPS a reason this build has never heard of, under a generated label', () => {
    // A newer server naming a new refusal must not vanish from a panel whose
    // whole job is to say what was left out.
    const [row] = describeNotScanned([{ reason: 'satellite_uplink', count: 4 }]);
    expect(row.label).toBe('Satellite uplink');
    expect(row.count).toBe(4);
    expect(row.registerSegmentsHref).toBeUndefined();
  });

  it('tolerates an absent list', () => {
    expect(describeNotScanned(undefined)).toEqual([]);
    expect(describeNotScanned(null)).toEqual([]);
  });
});

describe('notScannedHeadline', () => {
  it('distinguishes "no pass yet" from "nothing refused" — they are different facts', () => {
    expect(notScannedHeadline([], undefined)).toMatch(/No pass has run yet/);
    expect(notScannedHeadline([], '2026-09-17T06:00:00Z')).toBe('Every eligible host was scanned.');
  });

  it('totals the refused hosts and gets the grammar right', () => {
    const one = describeNotScanned([{ reason: 'public', count: 1 }]);
    const many = describeNotScanned([{ reason: 'public', count: 3 }, { reason: 'carrier_grade_nat', count: 12 }]);
    expect(notScannedTotal(many)).toBe(15);
    expect(notScannedHeadline(one, '2026-09-17T06:00:00Z')).toBe('1 host was not scanned on the last pass.');
    expect(notScannedHeadline(many, '2026-09-17T06:00:00Z')).toBe('15 hosts were not scanned on the last pass.');
  });
});
