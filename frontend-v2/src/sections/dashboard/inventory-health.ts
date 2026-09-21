// The Inventory health hero's arithmetic (ADR-0006 D5, workstream 3.8).
//
// D5: "The hero becomes Inventory health (assets by class with pending and
// stale counts, data-quality score from the ADR-0005 health checks) beside the
// existing Cryptographic posture index. … The ops persona reads the left half,
// the compliance persona the right, and both see the same page. No new
// dashboard."
//
// Everything with a decision in it lives here rather than in the JSX, because
// every one of these numbers has a way of being subtly wrong that looks fine on
// screen:
//
//   - the class facet counts EVERY ancestor of a class, so summing its buckets
//     counts most assets three times;
//   - a facet level that FAILED returns no buckets, which reads identically to
//     a tenant that genuinely has none;
//   - the hygiene score is null both before anything has been evaluated and
//     when nothing could be — and rendering either as a number is the
//     three-valued collapse this platform keeps paying for.
import type { AssetFacetBucket, FacetData } from '../inventory/asset-queries';

/** How many class rows the hero shows before it rolls the rest into "Other". */
export const HERO_CLASS_LIMIT = 5;

/** One row of the class breakdown. */
export interface ClassSlice {
  /** The class PATH — what a `class:` query term matches (QUERY_LANGUAGE §5.3). */
  path: string;
  label: string;
  count: number;
  /** The "Other" roll-up row, which is not a class and is not clickable. */
  other?: boolean;
}

/**
 * The class breakdown, from the `class` facet.
 *
 * ROOT classes only — the buckets whose path has no dot.
 *
 * The facet is hierarchical by design: a `hardware.computer.server` asset
 * contributes a count to `hardware`, to `hardware.computer` AND to
 * `hardware.computer.server`, so that picking "Hardware" in the rail shows the
 * whole branch. That is right for a rail and fatal for a hero: summing every
 * bucket counts most of the estate three times, and the two biggest rows would
 * be a parent and its own child.
 *
 * The roots partition the estate exactly — every asset has one `class_path` and
 * therefore exactly one root — so these counts sum to the total and "Other" is
 * a real remainder rather than an artefact.
 */
export function classSlices(
  buckets: AssetFacetBucket[] | undefined,
  limit = HERO_CLASS_LIMIT,
): ClassSlice[] {
  const roots = (buckets ?? [])
    .filter((b) => !b.value.includes('.'))
    // `||` rather than `??`: the server omits `label` when it is the same as
    // the value, but an EMPTY string is also not a label — a blank row is worse
    // than one showing the raw key.
    .map((b) => ({ path: b.value, label: b.label === undefined || b.label === '' ? b.value : b.label, count: b.count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));

  if (roots.length <= limit) return roots;
  const head = roots.slice(0, limit);
  const tail = roots.slice(limit);
  const rest = tail.reduce((n, r) => n + r.count, 0);
  // Only worth a row if it holds something. A "0 Other" row is noise.
  return rest > 0 ? [...head, { path: '', label: 'Other', count: rest, other: true }] : head;
}

/**
 * A count from one facet bucket, as THREE states.
 *
 * `null` means the level did not answer. The facet hook records which levels
 * failed rather than flattening them into empty buckets, precisely so a reader
 * can tell "no stale assets" from "we could not ask" — and a hero tile is the
 * worst place to guess, because a reassuring zero is exactly what a person
 * takes at face value.
 */
export function bucketCount(
  facets: FacetData | undefined,
  level: string,
  value: string,
): number | null {
  if (!facets) return null;
  if (facets.failed.includes(level)) return null;
  const buckets = facets.buckets[level];
  if (!buckets) return null;
  return buckets.find((b) => b.value === value)?.count ?? 0;
}

/** Every asset the facets saw, summed over the ROOT class buckets. */
export function totalFromClasses(buckets: AssetFacetBucket[] | undefined): number {
  return (buckets ?? []).filter((b) => !b.value.includes('.')).reduce((n, b) => n + b.count, 0);
}

/** The data-quality half of the hero. */
export interface HygieneScore {
  /** null when nothing has been evaluated — rendered "Not assessed", never 0 or 100. */
  score: number | null;
  passing: number | null;
  failing: number | null;
  notAssessed: number | null;
  /** True once the tenant has activated the framework. */
  activated: boolean;
  /** The framework exists in the catalogue at all. */
  present: boolean;
}

/** The Core framework whose score IS the data-quality number (ADR-0005 D5). */
export const HYGIENE_FRAMEWORK_CODE = 'inventory-hygiene';

/**
 * The Inventory Hygiene framework's materialized score.
 *
 * Read from the same `/frameworks/available` rollup the Posture page reads, so
 * the number in the hero and the number on the framework's own page cannot
 * disagree. It is a Core framework seeded for every tenant, so this is not an
 * Enterprise-gated tile — an ops buyer who never buys a compliance framework
 * still gets a data-quality score on day one.
 *
 * `preview_score` is null in TWO different situations and both must read as
 * "Not assessed": the engine has not produced a rollup yet, and it has but no
 * control could be assessed. Neither is 100%, and neither is 0.
 */
/**
 * `code` defaults to Inventory Hygiene, which is what this function was written
 * for. It is a parameter because the null-handling below — a null score means
 * BOTH "no rollup yet" and "nothing could be assessed", and is never 0 and never
 * 100 — is the same for every framework, and the PQC dashboard reads the
 * `pqc-readiness` row the same way. One implementation of that rule, not two.
 */
export function hygieneScore(
  rows: { platform_framework: { code: string }; is_licensed: boolean; preview_score?: number | null;
          controls_passing?: number | null; controls_failing?: number | null;
          controls_not_assessed?: number | null }[] | undefined,
  code: string = HYGIENE_FRAMEWORK_CODE,
): HygieneScore {
  const row = (rows ?? []).find((r) => r.platform_framework.code === code);
  if (!row) {
    return { score: null, passing: null, failing: null, notAssessed: null, activated: false, present: false };
  }
  return {
    score: typeof row.preview_score === 'number' ? row.preview_score : null,
    passing: row.controls_passing ?? null,
    failing: row.controls_failing ?? null,
    notAssessed: row.controls_not_assessed ?? null,
    activated: row.is_licensed,
    present: true,
  };
}

/**
 * The query a hero number links through to, so the list it opens is the set it
 * counted.
 *
 * Written with the same spellings `facetsToQuery` produces — `status:`,
 * `stale_status:`, `class:` — rather than a second vocabulary, because the
 * Inventory page parses the query back into its rail and an unrecognised term
 * would land there as an opaque "extra".
 */
export const HERO_STALE_QUERY = 'stale_status:stale';

/**
 * The query that COUNTS assets awaiting approval — and the reason a plain facet
 * call cannot.
 *
 * `GET /infrastructure-assets/facets` with no `query` runs the asset list's
 * DEFAULT SCOPE, which is the single term `status:monitoring`
 * (`defaultStatusTerm`, services/inventory-service/internal/services/
 * asset_query.go). The server's own comment explains why: "An asset that is
 * still pending approval is not part of inventory: every lens excludes it, and
 * counting it here made the dashboard disagree with the list."
 *
 * That default is right for the list. It is fatal for this count, because it
 * means the `status` facet can NEVER contain a `pending_approval` bucket —
 * reading one out of an unqueried facet is a lookup whose answer is 0 by
 * construction, whatever the tenant's actual queue looks like. Verified live on
 *: a tenant with **10** assets in Approvals rendered "0 Pending
 * approval" on the Dashboard hero, beside a Pending link that opened a queue
 * with ten rows in it.
 *
 * That is the exact failure this file's own header warns about — a reassuring
 * zero is what a reader takes at face value — and a tile hard-wired to 0 is
 * also a check that cannot fail.
 *
 * The scope is dropped "the moment the caller says something about status", so
 * naming the status is what makes the bucket appear. `pendingCount` below reads
 * it back out of a facet fetched with THIS query, never a bare one.
 */
export const HERO_PENDING_QUERY = 'status:pending_approval';

/**
 * The pending-approval count, from a facet fetched with `HERO_PENDING_QUERY`.
 *
 * Deliberately not a thin alias for `bucketCount`: the whole point is that the
 * caller must pass the RIGHT facet payload, and a differently-named function is
 * the thing that makes a reviewer ask which one they have. Still three-valued —
 * a failed level is null, never 0.
 */
export function pendingCount(facets: FacetData | undefined): number | null {
  return bucketCount(facets, 'status', 'pending_approval');
}

/**
 * Where the "Pending approval" count links.
 *
 * The APPROVALS QUEUE, not a filtered asset list. ADR-0006 D1 makes Pending a
 * cross-link in the Inventory nav for the same reason: assets are accepted or
 * denied in exactly one place, and a second surface that lists them invites a
 * second way to act on them — the second inbox D6 rules out.
 */
export const HERO_PENDING_HREF = '/discovery/approvals';

/** `/inventory?lens=assets&query=…`, encoded once, in one place. */
export function inventoryQueryHref(query: string): string {
  return query
    ? `/inventory?lens=assets&query=${encodeURIComponent(query)}`
    : '/inventory?lens=assets';
}
