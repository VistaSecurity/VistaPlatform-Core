import { describe, expect, it } from 'vitest';
import { INVENTORY_LENSES, findLens, lensesInGroup } from '../lenses';
import { facetTerm, groupByAccount, placementSteps, scopedCloudQuery, toggleTerm, type CloudPlacement } from './cloud-model';
import type { Asset } from '@vistasecurity/api-contract';

// ADR-0009 D7: Inventory → Cloud is a registered lens in the Assets group.
// MUTATION-VERIFIED: remove the `cloud` entry from lenses.ts and this is red.
describe('lens registration', () => {
  it('registers `cloud` in the Assets group, live and asset-anchored', () => {
    const lens = INVENTORY_LENSES.find((l) => l.key === 'cloud');
    expect(lens).toMatchObject({ label: 'Cloud', anchor: 'asset', live: true, group: 'assets' });
    expect(findLens('cloud').key).toBe('cloud');
    expect(lensesInGroup('assets').map((l) => l.key)).toContain('cloud');
  });
});

describe('the query', () => {
  it('scopes every run to cloud resources and keeps the user query whole', () => {
    expect(scopedCloudQuery('')).toBe('class:cloud_resource');
    expect(scopedCloudQuery('provider:aws or region:x')).toBe('class:cloud_resource and (provider:aws or region:x)');
  });
  it('writes and removes facet terms', () => {
    expect(facetTerm('cloud.type', 'AWS::EC2::Instance')).toBe('cloud.type:"AWS::EC2::Instance"');
    expect(facetTerm('class', 'dns_zone')).toBe('class=dns_zone');
    expect(toggleTerm('', 'provider:aws')).toBe('provider:aws');
    expect(toggleTerm('provider:aws', 'region:x')).toBe('provider:aws and region:x');
    expect(toggleTerm('provider:aws and region:x', 'provider:aws')).toBe('region:x');
  });
});

describe('grouping and placement', () => {
  const a = (id: string, account?: string) => ({ id, attributes: account ? { account_id: account } : {} }) as unknown as Asset;
  it('groups by account in first-seen order, with an explicit no-account group', () => {
    expect(groupByAccount([a('1', 'x'), a('2'), a('3', 'x')]).map((g) => [g.account, g.rows.length])).toEqual([['x', 2], ['', 1]]);
  });
  it('omits steps the resource does not have', () => {
    const p = { account_id: '', account_asset_id: null, account_name: '', region: 'global', network: null, prefix: null } as unknown as CloudPlacement;
    expect(placementSteps(p).map((s) => s.kind)).toEqual(['region']);
  });
});
