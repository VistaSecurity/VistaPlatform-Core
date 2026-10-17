// Inventory → Cloud (asset-inventory ADR-0009 D7; DCIM row 4.6): the pure
// parts of the lens — the base scope, the facet terms it writes into the
// query, the account grouping, and the placement breadcrumb's steps. Kept out
// of the components so every rule is a table test.
import type { Asset, inventoryComponents } from '@vistasecurity/api-contract';
import { quoteValue } from '../facet-query';

export type CloudPlacement = inventoryComponents['schemas']['CloudPlacement'];

/** Every cloud resource, whatever else the user typed. */
export const CLOUD_SCOPE = 'class:cloud_resource';

/** The query the lens actually runs: the cloud scope AND the user's query. */
export function scopedCloudQuery(query: string): string {
  const q = query.trim();
  return q ? `${CLOUD_SCOPE} and (${q})` : CLOUD_SCOPE;
}

/** The facets the lens shows, by the server's level name and the query field
 *  a click writes. */
export const CLOUD_FACETS = [
  { level: 'class', field: 'class', label: 'Class' },
  { level: 'cloud_provider', field: 'provider', label: 'Provider' },
  { level: 'cloud_account', field: 'account', label: 'Account' },
  { level: 'region', field: 'region', label: 'Region' },
  { level: 'cloud_type', field: 'cloud.type', label: 'Provider type' },
] as const;

/** The term a facet bucket writes: `field:value`, value quoted when needed.
 *  `class` uses `=` — a facet bucket names one class exactly, and `:` would
 *  also select its subclasses. */
export function facetTerm(field: string, value: string): string {
  return `${field}${field === 'class' ? '=' : ':'}${quoteValue(value)}`;
}

/** Toggle one term in the user's query: append it with `and`, or remove an
 *  exact occurrence. The query stays the state (ADR-0006 D2). */
export function toggleTerm(query: string, term: string): string {
  const q = query.trim();
  if (!q) return term;
  const parts = q.split(/\s+and\s+/i);
  if (parts.includes(term)) return parts.filter((p) => p !== term).join(' and ');
  return `${q} and ${term}`;
}

export function hasTerm(query: string, term: string): boolean {
  return query.trim().split(/\s+and\s+/i).includes(term);
}

const attr = (a: Asset, k: string): string => {
  const v = (a.attributes as Record<string, unknown> | undefined)?.[k];
  return typeof v === 'string' ? v : '';
};

export const assetProvider = (a: Asset): string => attr(a, 'provider');
export const assetAccount = (a: Asset): string => attr(a, 'account_id');
export const assetRegion = (a: Asset): string => attr(a, 'region');
export const assetProviderType = (a: Asset): string => attr(a, 'provider_type');

/** The page's rows grouped by account, accounts in first-seen order. Rows
 *  that state no account are one explicit group, never folded into another. */
export function groupByAccount(assets: Asset[]): { account: string; rows: Asset[] }[] {
  const out: { account: string; rows: Asset[] }[] = [];
  const idx = new Map<string, number>();
  for (const a of assets) {
    const key = assetAccount(a);
    let i = idx.get(key);
    if (i === undefined) {
      i = out.length;
      idx.set(key, i);
      out.push({ account: key, rows: [] });
    }
    out[i].rows.push(a);
  }
  return out;
}

export interface BreadcrumbStep {
  kind: 'account' | 'region' | 'network' | 'prefix';
  label: string;
  /** Where the step links, when it is a thing with a page. */
  href?: string;
}

/**
 * The Placement breadcrumb: account › region › network prefix › child prefix.
 * A step the resource does not have is left out — never drawn as a blank or a
 * guessed value.
 */
export function placementSteps(p: CloudPlacement): BreadcrumbStep[] {
  const steps: BreadcrumbStep[] = [];
  if (p.account_id || p.account_asset_id) {
    steps.push({
      kind: 'account',
      label: p.account_name || p.account_id,
      href: p.account_asset_id ? `/inventory/assets/${p.account_asset_id}` : undefined,
    });
  }
  if (p.region) {
    steps.push({ kind: 'region', label: p.region, href: `/inventory?lens=cloud&query=${encodeURIComponent(facetTerm('region', p.region))}` });
  }
  if (p.network) {
    steps.push({ kind: 'network', label: p.network.prefix, href: `/inventory?lens=networks&prefix=${p.network.prefix_id}` });
  }
  if (p.prefix) {
    steps.push({ kind: 'prefix', label: p.prefix.prefix, href: `/inventory?lens=networks&prefix=${p.prefix.prefix_id}` });
  }
  return steps;
}
