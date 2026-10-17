// Business Units (DCIM 1.1): the list query and the pure helpers around it.
import { useQuery } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type BusinessUnit = inventoryComponents['schemas']['BusinessUnit'];

export const BUSINESS_UNITS_KEY = ['settings', 'business-units'] as const;

/** All of the tenant's Business Units (flat; build the tree with flattenTree). */
export function useBusinessUnits(enabled = true) {
  return useQuery({
    queryKey: BUSINESS_UNITS_KEY,
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/dcim/business-units', {});
      if (error || !data) throw new Error('Failed to load business units');
      return data.business_units ?? [];
    },
  });
}

export interface BusinessUnitRow { unit: BusinessUnit; depth: number }

/**
 * Parents before children, siblings by name, with each row's depth. A unit
 * whose parent is missing from the list (or part of a cycle) is shown at the
 * top level rather than dropped: a hidden unit is one nobody can fix.
 */
export function flattenTree(units: readonly BusinessUnit[]): BusinessUnitRow[] {
  const ids = new Set(units.map((u) => u.id));
  const kids = new Map<string | null, BusinessUnit[]>();
  for (const u of units) {
    const key = u.parent_id && ids.has(u.parent_id) ? u.parent_id : null;
    kids.set(key, [...(kids.get(key) ?? []), u]);
  }
  for (const list of kids.values()) list.sort((a, b) => a.name.localeCompare(b.name));
  const out: BusinessUnitRow[] = [];
  const seen = new Set<string>();
  const walk = (parent: string | null, depth: number) => {
    for (const u of kids.get(parent) ?? []) {
      if (seen.has(u.id)) continue;
      seen.add(u.id);
      out.push({ unit: u, depth });
      walk(u.id, depth + 1);
    }
  };
  walk(null, 0);
  for (const u of units) if (!seen.has(u.id)) out.push({ unit: u, depth: 0 });
  return out;
}

/** Ids of a unit and everything beneath it (a unit cannot be re-parented into these). */
export function descendantIds(units: readonly BusinessUnit[], id: string): Set<string> {
  const out = new Set<string>([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const u of units) {
      if (u.parent_id && out.has(u.parent_id) && !out.has(u.id)) { out.add(u.id); grew = true; }
    }
  }
  return out;
}

/** Levels from the root down to `id`, inclusive (the API caps the tree at 4). */
export function levelOf(units: readonly BusinessUnit[], id: string): number {
  const byId = new Map(units.map((u) => [u.id, u]));
  let n = 0;
  for (let cur = byId.get(id); cur && n < 32; cur = cur.parent_id ? byId.get(cur.parent_id) : undefined) n++;
  return n;
}

export const MAX_BUSINESS_UNIT_DEPTH = 4;
