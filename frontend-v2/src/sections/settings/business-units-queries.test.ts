import { describe, expect, it } from 'vitest';
import { descendantIds, flattenTree, levelOf, type BusinessUnit } from './business-units-queries';

const u = (id: string, name: string, parent_id: string | null = null): BusinessUnit => ({
  id, tenant_id: 't', name, slug: name.toLowerCase(), parent_id, external_ids: {}, source_kind: 'declared',
  custom_fields: {}, created_at: '', updated_at: '', asset_count: 0,
});

describe('business unit tree helpers', () => {
  const units = [u('3', 'Finance', '1'), u('1', 'Corporate'), u('2', 'Retail'), u('4', 'Payroll', '3')];

  it('lists parents before children, siblings by name, with depth', () => {
    expect(flattenTree(units).map((r) => `${r.depth}:${r.unit.name}`)).toEqual(['0:Corporate', '1:Finance', '2:Payroll', '0:Retail']);
  });

  it('never drops a unit whose parent is missing or that sits in a cycle', () => {
    const odd = [u('a', 'Orphan', 'gone'), u('b', 'B', 'c'), u('c', 'C', 'b')];
    expect(flattenTree(odd).map((r) => r.unit.name).sort()).toEqual(['B', 'C', 'Orphan']);
  });

  it('knows a unit and everything beneath it, and how deep a unit sits', () => {
    expect([...descendantIds(units, '1')].sort()).toEqual(['1', '3', '4']);
    expect(levelOf(units, '4')).toBe(3);
    expect(levelOf(units, '2')).toBe(1);
  });
});
