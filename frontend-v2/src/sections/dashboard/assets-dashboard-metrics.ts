// The Assets dashboard's arithmetic and drill-through routes.
//
// Separated from the JSX for the reason `dashboard-metrics.ts` was: every number
// on this page has a way of being subtly wrong that looks perfectly fine on
// screen, and none of those ways is visible in a typecheck.
//
// Two rules run through the whole file.
//
//  1. A COUNT IS THREE-VALUED. A facet level that failed returns no buckets,
//     which renders identically to a tenant that genuinely has none. The hero
//     tiles on the shared Dashboard already learned this (B-28); repeating the
//     collapse here would be the same bug in a new room.
//
//  2. A TILE THAT COUNTS A SUBSET MUST LINK TO THAT SUBSET. Every row on this
//     page is a facet bucket, so every row's link has to select exactly the
//     rows the bucket counted — which is why nothing here writes a query term
//     by hand. See `drillThrough`.
import {
  emptyFacets, facetFieldTerm, facetsToQuery, UNSET_BUCKET, type FacetState,
} from '../inventory/facet-query';
import type { AssetFacetBucket, FacetData } from '../inventory/asset-queries';

// ---------------------------------------------------------------- panels ---

/**
 * One facet level shown as a panel, in page order.
 *
 * `level` is the server's facet name; `field` is the QUERY field its buckets
 * drill through on. They are not always the same word and are not always both
 * present — see `drillThrough`.
 */
export interface FacetPanelSpec {
  level: string;
  title: string;
  /** One line under the title saying what the reader is looking at. */
  caption: string;
  icon: string;
  /** How many bucket rows before the rest roll into "Other". */
  limit?: number;
}

export const COMPOSITION_PANELS: FacetPanelSpec[] = [
  { level: 'class', title: 'By class', caption: 'What kind of thing each asset is', icon: 'layers' },
  { level: 'environment', title: 'By environment', caption: 'Where it runs', icon: 'globe' },
  { level: 'business_unit', title: 'By business unit', caption: 'Who owns it in the organization', icon: 'building-2' },
  { level: 'ownership', title: 'By ownership', caption: 'Whether we operate it or someone else does', icon: 'user-round' },
];

export const LIFECYCLE_PANELS: FacetPanelSpec[] = [
  { level: 'status', title: 'By status', caption: 'Where each asset sits in its lifecycle', icon: 'activity' },
  { level: 'stale_status', title: 'Freshness', caption: 'Assets we have stopped seeing', icon: 'clock' },
  { level: 'source', title: 'How we found it', caption: 'The discovery path that produced the record', icon: 'radar' },
  { level: 'risk', title: 'By risk band', caption: 'Highest risk scored on the asset', icon: 'shield-alert' },
];

// ------------------------------------------------------------ class rows ---

/**
 * The class facet is HIERARCHICAL: a `hardware.computer.server` asset counts
 * under `hardware`, `hardware.computer` AND `hardware.computer.server`, so the
 * rail can select a whole branch.
 *
 * That is right for a rail and fatal for a total. `inventory-health.ts` takes
 * the ROOT buckets for the same reason, and this page shows the full depth in a
 * separate panel — but only ever sums the roots.
 */
export function rootClassBuckets(buckets: AssetFacetBucket[] | undefined): AssetFacetBucket[] {
  return (buckets ?? []).filter((b) => !b.value.includes('.'));
}

// --------------------------------------------------------------- buckets ---

export interface BucketRow {
  value: string;
  label: string;
  count: number;
  /** null when this bucket has no honest drill-through — see `drillThrough`. */
  href: string | null;
  /** The "Other" roll-up. Not a bucket, so never clickable. */
  other?: boolean;
}

/**
 * Bucket rows for one panel, biggest first, with a bounded tail.
 *
 * `total` is the denominator the bars are drawn against. It is the SUM OF THE
 * SHOWN LEVEL, not the tenant's asset count: `business_unit` buckets partition
 * the estate but `class` buckets (see above) do not, and drawing a bar as
 * "share of all assets" on a level that double-counts produces bars past 100%.
 */
export function bucketRows(
  level: string,
  buckets: AssetFacetBucket[] | undefined,
  limit = 6,
): { rows: BucketRow[]; total: number } {
  const source = level === 'class' ? rootClassBuckets(buckets) : (buckets ?? []);
  const sorted = [...source].sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
  const total = sorted.reduce((n, b) => n + b.count, 0);

  const toRow = (b: AssetFacetBucket): BucketRow => ({
    value: b.value,
    // `||` not `??`: the server omits `label` when it equals the value, but an
    // EMPTY label is also not a label, and a blank row is worse than a raw key.
    label: b.label === undefined || b.label === '' ? b.value : b.label,
    count: b.count,
    href: drillThrough(level, b.value),
  });

  if (sorted.length <= limit) return { rows: sorted.map(toRow), total };

  const head = sorted.slice(0, limit).map(toRow);
  const rest = sorted.slice(limit).reduce((n, b) => n + b.count, 0);
  // A "0 Other" row is noise.
  return {
    rows: rest > 0 ? [...head, { value: '', label: 'Other', count: rest, href: null, other: true }] : head,
    total,
  };
}

// --------------------------------------------------------- drill-through ---

/**
 * Facet levels whose buckets map onto a facet the Inventory RAIL can represent.
 *
 * These go through `facetsToQuery`, the canonical writer, so the query text the
 * dashboard produces is byte-identical to what the rail would have written —
 * and the destination opens with the matching checkbox already ticked instead
 * of showing an opaque "extra" term the user cannot undo.
 */
const RAIL_FACET: Readonly<Record<string, keyof FacetState>> = {
  class: 'class',
  status: 'status',
  environment: 'environment',
  site: 'site',
  business_unit: 'business_unit',
  owner_email: 'owner',
  source: 'provenance',
  risk: 'risk',
};

/**
 * Facet levels with a real query FIELD but no rail checkbox.
 *
 * They still drill through — the language serves them — but they land in the
 * Inventory page's "extra terms" box rather than as a ticked facet. That is the
 * honest rendering: the query is exact, and the page says plainly that it holds
 * a term the rail cannot draw.
 *
 * The term is written by `facetFieldTerm`, the same function the rail uses, so
 * the `Unknown` bucket becomes `not exists(field)` rather than the literal
 * string — the failure that made `owner_email:Unknown` match nothing and
 * `environment:Unknown` a 400.
 */
const PLAIN_FIELD: Readonly<Record<string, string>> = {
  ownership: 'ownership',
  stale_status: 'stale_status',
  region: 'region',
  support_group: 'support_group',
  proposed_by: 'proposed_by',
};

/**
 * The Inventory URL a bucket row opens, or **null** when this level has no
 * query field at all.
 *
 * Null is the important return. `operating_system`, `has_endpoints` and
 * `has_findings` are facet levels the server counts but the asset query
 * language has no field for (`has_findings` has a form, but it is a nested
 * `finding:(…)` predicate rather than a column, and the facet's two buckets do
 * not map onto it one-for-one). Linking those rows at the unfiltered list —
 * which is what a best-effort guess degrades to — is precisely the bug the
 * Dashboard's high-risk tile shipped with: a row reading "12" that opens every
 * asset in the tenant, with nothing on the page saying which twelve were meant.
 * A non-clickable row is worse-looking and better.
 */
export function drillThrough(level: string, value: string): string | null {
  const railKey = RAIL_FACET[level];
  if (railKey) {
    const facets = emptyFacets();
    if (railKey === 'class') {
      // Single-valued: the taxonomy is a tree and a multi-select over it reads
      // as nonsense. The facet writer turns the key into the class PATH.
      facets.class = value;
    } else {
      (facets[railKey] as string[]) = [value];
    }
    return inventoryQueryHref(facetsToQuery(facets));
  }

  const field = PLAIN_FIELD[level];
  if (!field) return null;
  const term = facetFieldTerm(field, [value]);
  return term ? inventoryQueryHref(term) : null;
}

/** `/inventory?lens=assets` with a query, URL-encoded once, in one place. */
export function inventoryQueryHref(query: string): string {
  return query
    ? `/inventory?lens=assets&query=${encodeURIComponent(query)}`
    : '/inventory?lens=assets';
}

// ------------------------------------------------------------ data quality --

/**
 * The "needs a decision" counts, three-valued.
 *
 * `bucketCount` in `inventory-health.ts` does the same job for the shared
 * Dashboard's hero; this re-exports the rule rather than restating it so the
 * two pages cannot disagree about what a failed facet level looks like.
 */
export function facetBucketCount(
  facets: FacetData | undefined,
  level: string,
  value: string,
  failed = false,
): number | null {
  if (failed || !facets) return null;
  if (facets.failed.includes(level)) return null;
  const buckets = facets.buckets[level];
  if (!buckets) return null;
  return buckets.find((b) => b.value === value)?.count ?? 0;
}

/** Every asset the facets saw, summed over the ROOT class buckets. */
export function totalAssets(buckets: AssetFacetBucket[] | undefined): number {
  return rootClassBuckets(buckets).reduce((n, b) => n + b.count, 0);
}

/**
 * How much of the estate carries an attribute at all.
 *
 * "Coverage" is the share of assets NOT in the level's unset bucket. It is the
 * data-quality question the ops persona actually asks — "do I know who owns
 * these?" — and it is not derivable from the panel bars, which show the split
 * among the assets that DO have a value.
 *
 * Returns null rather than 0 when the level did not answer, for the usual
 * reason: a reassuring "0% missing" is exactly what a reader takes at face
 * value.
 */
export function attributeCoverage(
  facets: FacetData | undefined,
  level: string,
): { known: number; total: number; percent: number } | null {
  if (!facets || facets.failed.includes(level)) return null;
  const buckets = facets.buckets[level];
  if (!buckets) return null;
  const total = buckets.reduce((n, b) => n + b.count, 0);
  if (total === 0) return null;
  const unknown = buckets.find((b) => b.value === UNSET_BUCKET)?.count ?? 0;
  const known = total - unknown;
  return { known, total, percent: Math.round((known / total) * 100) };
}
