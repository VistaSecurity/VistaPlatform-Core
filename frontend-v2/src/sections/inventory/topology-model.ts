// The topology view's model (ADR-0006 D4 second half, workstream 3.8).
//
// The map's OTHER view. Neighbourhood answers "what does this one thing touch";
// Topology answers "where is everything" — and D4 is explicit that the second
// question must NOT be answered with a force graph:
//
//	"not a force graph of thousands of nodes, which is unreadable everywhere it
//	 is tried. A hierarchical view by site → prefix → class with counts …
//	 The topology view needs no graph library; it is a tree with counts and can
//	 be built with the existing components."
//
// So this file holds the pure parts — the drill-through queries, the expansion
// key, the edge phrasing — and `topology-view.tsx` is the markup. Everything
// here is unit-testable in node, which matters because the drill-through query
// is the one thing that can be wrong in a way nothing on screen shows: a link
// that opens a DIFFERENT set from the count it was clicked on looks perfectly
// fine until somebody counts the rows.
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { quoteValue } from './facet-query';

export type TopologyPayload = inventoryComponents['schemas']['AssetTopology'];
export type TopologySite = inventoryComponents['schemas']['AssetTopologySite'];
export type TopologyPrefix = inventoryComponents['schemas']['AssetTopologyPrefix'];
export type TopologyClass = inventoryComponents['schemas']['AssetTopologyClass'];
export type TopologyEdge = inventoryComponents['schemas']['AssetTopologyEdge'];
export type TopologyCloudAccount = inventoryComponents['schemas']['AssetTopologyCloudAccount'];
export type TopologyCloudRegion = inventoryComponents['schemas']['AssetTopologyCloudRegion'];
/** Physical cable runs between two prefixes, aggregated (DCIM row 3.6). */
export type TopologyCablePaths = inventoryComponents['schemas']['AssetTopologyCablePaths'];

/** "4 cable runs · 1 proposed". */
export function cablePathsSummary(c: TopologyCablePaths): string {
  const runs = `${c.count.toLocaleString()} cable run${c.count === 1 ? '' : 's'}`;
  return c.pending_count > 0 ? `${runs} · ${c.pending_count.toLocaleString()} proposed` : runs;
}

/**
 * The scope of one region of one cloud account in the topology's cloud
 * hierarchy (asset-inventory ADR-0009 D7): every drill-through under it ANDs
 * this in, so a "No prefix" count under a region opens that region's
 * prefix-less resources — not every prefix-less asset in the estate.
 */
export function cloudRegionScope(account: { account_id: string }, region: { region: string }): string {
  const parts = ['class:cloud_resource', `account:${quoteValue(account.account_id)}`];
  // `No region` is the server's label for an absence, not a region.
  parts.push(region.region === 'No region' ? 'not exists(attr.region)' : `region:${quoteValue(region.region)}`);
  return parts.join(' and ');
}

/** `/inventory?lens=cloud&query=…` — a cloud region's resources. */
export function cloudLensHref(query: string): string {
  return `/inventory?lens=cloud&query=${encodeURIComponent(query)}`;
}

/** The map views, as they appear in the URL (`?view=`). */
export const MAP_VIEWS = ['network', 'neighbourhood', 'topology'] as const;
export type MapView = (typeof MAP_VIEWS)[number];

/** The default when nothing is focused: the whole estate. The lens
 *  opens on a picture of everything rather than on a picker. */
export const DEFAULT_MAP_VIEW: MapView = 'network';

/**
 * Read the view out of a URL parameter.
 *
 * With no (or an unknown) `view`, a URL that carries `focus=` is a
 * neighbourhood link — every map link written before the Network view existed
 * has that shape — so it still lands on the neighbourhood. Without a focus it
 * is the estate. A typo in a pasted link still shows a map.
 */
export function readMapView(raw: string | null, hasFocus = false): MapView {
  if ((MAP_VIEWS as readonly string[]).includes(raw ?? '')) return raw as MapView;
  return hasFocus ? 'neighbourhood' : DEFAULT_MAP_VIEW;
}

/**
 * A stable key for one prefix inside one site, for the expansion state.
 *
 * Keyed on the prefix's ID, with a marker for the no-prefix bucket — NOT on
 * its name: the bucket's name is a label, and the same CIDR can be a prefix in
 * two cloud networks (DCIM row 1.6), so keying on the name would make
 * expanding one expand the other.
 */
export function prefixKey(site: string, prefix: { prefix_id?: string | null }): string {
  // `::` as the separator, and the bucket spelled `~none~`: a site name cannot
  // collide with a uuid, but writing the join explicitly keeps the key readable
  // in a debugger, which a control character would not be.
  return `${site}::${prefix.prefix_id ?? '~none~'}`;
}

/**
 * The no-prefix bucket, as a predicate.
 *
 * `not exists(prefix_id)`, because the language has no null literal (§1) —
 * absence is spelled with `exists`, which is what keeps SQL's `= NULL` trap off
 * the surface.
 */
export const NO_PREFIX_QUERY = 'not exists(prefix_id)';

/**
 * The query that selects exactly the assets a class node counted.
 *
 * This is the load-bearing function in the file. The tree is an INDEX into the
 * asset list, so a click has to land on the same rows the number came from —
 * and the two halves of that are easy to get subtly wrong:
 *
 *   - the class term is `class=<key>`, the EXACT form, not `class:<key>`.
 *     QUERY_LANGUAGE §5.3 gives the two operators different meanings: `:` is a
 *     SUBTREE match on the materialised path, `=` is the class itself. The
 *     topology groups by `class_key`, so a node counts assets whose class is
 *     exactly that — and plenty of classes are not leaves. The classification
 *     rules assign `network_device` to devices they cannot narrow further,
 *     while switches and routers sit beneath it, so on a real estate a chip
 *     reading 4,167 opened a list of 12,500 under the subtree form. Same
 *     question, two answers, and the list is the one people believe.
 *   - the no-prefix bucket is `not exists(prefix_id)`, not
 *     `prefix_id:null` — the language has NO null literal, deliberately
 *     (§1): absence is `exists(field)` / `not exists(field)`, which removes
 *     SQL's `= NULL` trap from the surface entirely.
 *
 * The dashboard hero uses `class:` and is right to: its bars come from the
 * hierarchical `class` facet, whose root bucket IS the whole subtree, and its
 * tooltip says so. Two surfaces, two counts, two operators.
 *
 * Values go through the query language's own quoting rule, not
 * `JSON.stringify`: they agree on backslash and double quote and disagree on
 * everything else.
 */
export function classDrillThroughQuery(
  prefix: { prefix_id?: string | null },
  cls: { class_key: string },
): string {
  const scope = prefix.prefix_id
    ? `prefix_id:${quoteValue(prefix.prefix_id)}`
    : NO_PREFIX_QUERY;
  return `${scope} and class=${quoteValue(cls.class_key)}`;
}

/** The query for a whole prefix, for the "N assets" link on the prefix row. */
export function prefixDrillThroughQuery(prefix: { prefix_id?: string | null }): string {
  return prefix.prefix_id
    ? `prefix_id:${quoteValue(prefix.prefix_id)}`
    : NO_PREFIX_QUERY;
}

/** `/inventory?lens=assets&query=…` — where every drill-through lands. */
export function topologyAssetsHref(query: string): string {
  return `/inventory?lens=assets&query=${encodeURIComponent(query)}`;
}

/**
 * What a truncated topology admits to, in words.
 *
 * Returns null when nothing was cut. The caps are a refusal to guess, not a
 * performance knob — an answer that was shortened must say so, because a
 * diagram that looks complete and is not is worse than no diagram.
 */
export function topologyTruncationNotice(t: TopologyPayload | undefined): string | null {
  if (!t?.truncated) return null;
  const shown = (t.sites ?? []).reduce(
    (n, s) => n + (s.prefixes ?? []).reduce((m, g) => m + (g.classes ?? []).length, 0), 0);
  const edges = (t.edges ?? []).length;
  const parts: string[] = [];
  if (t.total_nodes > shown) parts.push(`${shown.toLocaleString()} of ${t.total_nodes.toLocaleString()} groups`);
  if (t.total_edges > edges) parts.push(`${edges.toLocaleString()} of ${t.total_edges.toLocaleString()} connection summaries`);
  if (parts.length === 0) return 'This topology was truncated.';
  return `Showing ${parts.join(' and ')}. Narrow the estate to see the rest.`;
}

/**
 * The cross-prefix-link headline: the number, and whether it is the whole
 * answer.
 *
 * It reads `total_edges` — what the SERVER counted — not `edges.length`, which
 * is how many survived the cap. Those are the same number only until an estate
 * is big enough to truncate, and at that point the headline was quietly
 * reporting the size of the PICTURE as the size of the ESTATE: a tenant with
 * 900 cross-prefix links and a cap of 200 read "200 cross-prefix links" in
 * 24-point type, which is a wrong answer to the question the number asks.
 *
 * `truncated` is carried out with it rather than left to the notice below,
 * because the notice explains a diagram and this explains a number — a reader
 * who only takes in the headline must still be told it is a floor. The words
 * are the caller's to render; what is settled here is which field is read and
 * when the qualifier applies.
 */
export function topologyEdgeHeadline(t: TopologyPayload | undefined): {
  count: number;
  label: string;
  /** True when more links exist than were drawn, so the count is a total the
   *  picture does not show in full. */
  partial: boolean;
} {
  const count = t?.total_edges ?? 0;
  const drawn = (t?.edges ?? []).length;
  return {
    count,
    label: count === 1 ? 'cross-prefix link' : 'cross-prefix links',
    partial: !!t?.truncated && count > drawn,
  };
}

/**
 * How many of the tenant's assets the tree actually accounts for.
 *
 * The server counts `total_assets` INDEPENDENTLY of the grouping, so this is a
 * real check rather than a restatement: if the two disagree, a branch was lost
 * (or the cap cut one off), and the view says so instead of drawing a tidy
 * picture of a subset.
 */
export function treeAssetTotal(t: TopologyPayload | undefined): number {
  return (t?.sites ?? []).reduce((n, s) => n + s.asset_count, 0);
}

/**
 * The edge line's phrasing.
 *
 * `connects_to` (observed traffic) and `depends_on` (a declared dependency) are
 * different claims, and a single "9 connections" would hide which. Ordered so
 * the reading is stable rather than dependent on map iteration order.
 */
const EDGE_TYPE_WORD: Readonly<Record<string, { one: string; many: string }>> = {
  connects_to: { one: 'connection', many: 'connections' },
  depends_on: { one: 'dependency', many: 'dependencies' },
};

export function edgeSummary(edge: TopologyEdge): string {
  const parts = Object.keys(edge.by_type)
    .sort()
    .map((type) => {
      const n = edge.by_type[type];
      // A type the registry gained after this build falls back to its key with
      // the underscores opened out, plus a naive plural. It reads a little
      // clumsily and it is never "undefined", which is the trade.
      const opened = type.replace(/_/g, ' ');
      const word = EDGE_TYPE_WORD[type] ?? { one: opened, many: `${opened}s` };
      return `${n} ${n === 1 ? word.one : word.many}`;
    });
  return parts.length ? parts.join(' · ') : `${edge.count} connections`;
}
