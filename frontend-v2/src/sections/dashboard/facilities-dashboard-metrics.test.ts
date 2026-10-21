import { describe, expect, it } from 'vitest';
import {
  CAPACITY_CRITICAL, CAPACITY_WARN, ageText, assetPortsHref, cableHref, cablingHref, fillColor, fmtPct, fmtSize, fmtUnits,
  isEmptyEstate, prefixHref, racksHref, sortSites,
} from './facilities-dashboard-metrics';
import type { CapacitySite } from './facilities-queries';
import { report } from './facilities-test-fixture';

const site = (name: string, over: Partial<CapacitySite> = {}): CapacitySite => ({
  site_id: name.toLowerCase(), site_name: name, racks: 1, total_units: 42, used_units: 10, reserved_units: 0,
  free_units: 32, utilization: 24, racks_over_80: 0, racks_over_95: 0, racks_with_power: 0, racks_over_power_budget: 0, ...over,
});

describe('fillColor', () => {
  it('is strictly greater, as the server counts: exactly 80 and exactly 95 are not over', () => {
    expect(fillColor(CAPACITY_WARN)).toBe('var(--accent)');
    expect(fillColor(CAPACITY_WARN + 0.01)).toBe('var(--warn-strong)');
    expect(fillColor(CAPACITY_CRITICAL)).toBe('var(--warn-strong)');
    expect(fillColor(CAPACITY_CRITICAL + 0.01)).toBe('var(--danger-text)');
  });
});

describe('formatting', () => {
  it('shows whole and half units, never more than one decimal', () => {
    expect(fmtUnits(42)).toBe('42 U');
    expect(fmtUnits(0.5)).toBe('0.5 U');
    expect(fmtUnits(10.4999)).toBe('10.5 U');
    expect(fmtPct(97.5)).toBe('97.5%');
    expect(fmtPct(0)).toBe('0%');
  });
  it('keeps an IPv6 address count a string, abbreviated rather than rounded to a wrong number', () => {
    expect(fmtSize('256')).toBe('256');
    expect(fmtSize('18446744073709551616')).toBe('~10^19');
  });
  it('words ages', () => {
    expect(ageText(1)).toBe('1 day');
    expect(ageText(91)).toBe('91 days');
  });
});

describe('drill-through routes', () => {
  it('link to the lens that counted the number', () => {
    expect(racksHref('s1')).toBe('/inventory?lens=racks&site=s1');
    expect(prefixHref('p1')).toBe('/inventory/prefixes/p1');
    expect(cableHref('c1')).toBe('/inventory/cables/c1');
    expect(assetPortsHref('a1')).toBe('/inventory/assets/a1/ports');
    expect(cablingHref('planned')).toBe('/inventory?lens=cabling&status=planned');
  });
  it('encodes ids rather than trusting them', () => {
    expect(racksHref('a&b')).toBe('/inventory?lens=racks&site=a%26b');
  });
});

describe('sortSites', () => {
  const rows = [site('Beta', { utilization: 50, free_units: 5 }), site('Alpha', { utilization: 50, free_units: 9 }), site('Gamma', { utilization: 90, free_units: 1 })];
  it('sorts numerically, both ways, tie-breaking on name, without mutating its input', () => {
    expect(sortSites(rows, 'utilization', 'desc').map((s) => s.site_name)).toEqual(['Gamma', 'Alpha', 'Beta']);
    expect(sortSites(rows, 'free_units', 'asc').map((s) => s.site_name)).toEqual(['Gamma', 'Beta', 'Alpha']);
    expect(sortSites(rows, 'site_name', 'desc').map((s) => s.site_name)).toEqual(['Gamma', 'Beta', 'Alpha']);
    expect(rows.map((s) => s.site_name)).toEqual(['Beta', 'Alpha', 'Gamma']);
  });
});

describe('isEmptyEstate', () => {
  it('is empty only when racks, switches, prefixes and cables are all absent', () => {
    expect(isEmptyEstate(report())).toBe(true);
    expect(isEmptyEstate(report({ prefixes: { ...report().prefixes, total: 1 } }))).toBe(false);
    expect(isEmptyEstate(report({ cables: { ...report().cables, proposed_pending: 1 } }))).toBe(false);
    expect(isEmptyEstate(report({ ports: { ...report().ports, switches: 1 } }))).toBe(false);
  });
});
