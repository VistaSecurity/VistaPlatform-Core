// Dagre layout for the map (workstream 2.9).
//
// A thin, PURE wrapper: graph model in, positions out. It imports dagre and
// nothing else — no React, no `@xyflow/react` — so the layout can be tested
// for determinism in the node environment, and so the expensive part of
// drawing a graph is a function the renderer can memoise on its inputs rather
// than an effect that re-runs on every hover.
//
// Hierarchical rather than force-directed on purpose. A force layout settles
// somewhere different every time it is run, which means the same neighbourhood
// looks like a different system on each visit and a screenshot in a ticket
// cannot be matched to what the reader sees. Dagre is deterministic: the same
// graph and direction give byte-identical coordinates, which is what
// `map-layout.test.ts` pins.
import dagre from '@dagrejs/dagre';
import type { MapGraph } from './map-model';

/** Left-to-right reads like a dependency chain; top-to-bottom like a hierarchy.
 *  Both are offered because which one is legible depends on the shape of the
 *  neighbourhood, and the user can see that and we cannot. */
export type LayoutDirection = 'LR' | 'TB';

/** Node box, in the same units the renderer draws in. Layout needs the size to
 *  keep boxes apart, so this is the one place the two have to agree. */
export const NODE_WIDTH = 188;
export const NODE_HEIGHT = 56;

export interface LayoutOptions {
  nodeWidth?: number;
  nodeHeight?: number;
  /** Distance between ranks (hops). */
  rankSep?: number;
  /** Distance between siblings within a rank. */
  nodeSep?: number;
}

export interface LayoutResult {
  /** Top-left corner per node id — xyflow positions from the corner, dagre
   *  from the centre, so the conversion happens here rather than at the call
   *  site where it would be re-derived (and mis-derived) per renderer. */
  positions: Readonly<Record<string, { x: number; y: number }>>;
  width: number;
  height: number;
}

/**
 * Lay the graph out.
 *
 * Self-edges and edges with a missing end are skipped rather than fed to dagre:
 * both make it emit a dummy node, which shows up as a node the model never had.
 * `buildMapGraph` already drops dangling edges, so this is the second belt.
 */
export function layoutGraph(
  graph: MapGraph,
  direction: LayoutDirection = 'LR',
  opts: LayoutOptions = {},
): LayoutResult {
  const nodeWidth = opts.nodeWidth ?? NODE_WIDTH;
  const nodeHeight = opts.nodeHeight ?? NODE_HEIGHT;

  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({
    rankdir: direction,
    // Ranks are hops, so they need room for an edge label between them;
    // siblings only need to not touch.
    ranksep: opts.rankSep ?? 96,
    nodesep: opts.nodeSep ?? 26,
    marginx: 24,
    marginy: 24,
  });
  g.setDefaultEdgeLabel(() => ({}));

  const ids = new Set<string>();
  for (const n of graph.nodes) {
    ids.add(n.id);
    g.setNode(n.id, { width: nodeWidth, height: nodeHeight });
  }
  for (const e of graph.edges) {
    if (e.source === e.target) continue;
    if (!ids.has(e.source) || !ids.has(e.target)) continue;
    // Multigraph + the edge id as the name: two assets can be joined by more
    // than one relationship (`runs_on` and `connects_to` both exist between an
    // app and its host), and a simple graph would silently collapse them into
    // one line.
    g.setEdge(e.source, e.target, {}, e.id);
  }

  dagre.layout(g);

  const positions: Record<string, { x: number; y: number }> = {};
  for (const id of ids) {
    const n = g.node(id) as { x?: number; y?: number } | undefined;
    // A node dagre did not position (it cannot happen for a node we set, but a
    // missing coordinate silently becoming NaN would put the node at the origin
    // and look like a bug in the data) falls back to 0,0 explicitly.
    positions[id] = {
      x: Math.round((n?.x ?? 0) - nodeWidth / 2),
      y: Math.round((n?.y ?? 0) - nodeHeight / 2),
    };
  }

  // dagre computes the graph box from the extent of its nodes, so an EMPTY
  // graph comes back with a non-finite width and height rather than zero. That
  // is not hypothetical and it is not harmless: `Math.round(NaN)` is NaN, a NaN
  // in a style attribute is dropped silently by the browser, and the result is
  // a container that collapses with no error anywhere. A graph with no nodes is
  // a real state here — it is what "this asset has no relationships" looks like.
  const label = g.graph() as { width?: number; height?: number };
  const finite = (n: number | undefined) => (Number.isFinite(n) ? Math.round(n as number) : 0);
  return { positions, width: finite(label?.width), height: finite(label?.height) };
}

/** Which side of a node box an edge attaches to. Named as sides rather than as
 *  `Position` values so this stays in the dagre-only module — the renderer maps
 *  them onto xyflow's enum, and the graph library stays out of here. */
export type HandleSide = 'top' | 'right' | 'bottom' | 'left';

/**
 * The sides edges leave and arrive on, per layout direction.
 *
 * This has to follow the rank axis, and it is not cosmetic when it does not.
 * `rankdir: 'TB'` stacks ranks DOWNWARDS, so an edge that leaves the right of a
 * node and enters the left of the one directly beneath it is drawn as a loop
 * back over the stack — the picture says "these two are beside each other" about
 * a parent and its child. The renderer's handles were fixed left/right, which is
 * right for LR and wrong for every TB graph.
 */
export const HANDLE_SIDES: Readonly<Record<LayoutDirection, { source: HandleSide; target: HandleSide }>> = {
  LR: { source: 'right', target: 'left' },
  TB: { source: 'bottom', target: 'top' },
};

/** The other direction. A toggle rather than a free choice: two orientations
 *  cover every neighbourhood shape we have seen, and four would be a setting. */
export const flipDirection = (d: LayoutDirection): LayoutDirection => (d === 'LR' ? 'TB' : 'LR');

export const DIRECTION_LABEL: Readonly<Record<LayoutDirection, string>> = {
  LR: 'Left to right',
  TB: 'Top to bottom',
};

/**
 * How far apart parallel edges are spread, in the same units the renderer draws
 * in. About half a node width, so two lines between the same pair of boxes read
 * as two lines at any zoom the map is legible at.
 */
export const PARALLEL_EDGE_SPREAD = 30;

/**
 * A lateral offset per edge, so edges between the SAME pair of nodes do not sit
 * on top of each other.
 *
 * Two assets are routinely joined by more than one relationship — an
 * application `runs_on` its host AND `connects_to` it — and both were drawn
 * along the same spline. The result is one visible line: the second edge is
 * hidden, its label overprints the first's, and it cannot be hovered or clicked
 * at all, so its provenance and confidence are unreachable. The graph silently
 * under-reports how two things are related, which is the one thing a
 * relationship map exists to say.
 *
 * Grouped on the UNORDERED pair, not the directed one. A→B and B→A are drawn
 * along the same geometry too — only the arrowhead differs — so grouping by
 * direction would leave that pair coincident, which is the same bug with a
 * narrower fixture.
 *
 * Offsets are symmetric about zero, so a single edge is undisplaced (the common
 * case must look exactly as it did) and a pair straddles the straight line
 * rather than both bending the same way. Ordered by edge ID, which is stable
 * across renders — ordering by array position would move lines about whenever
 * the server returned the same edges in a different order, and this map is
 * deterministic on purpose (see layoutGraph).
 */
export function parallelEdgeOffsets(
  edges: readonly { id: string; source: string; target: string }[],
  spread: number = PARALLEL_EDGE_SPREAD,
): Record<string, number> {
  const groups = new Map<string, { id: string }[]>();
  for (const e of edges) {
    // Self-edges are not drawn (layoutGraph skips them), so they are not
    // grouped either — they would otherwise form a group of their own and be
    // offset off a line that does not exist.
    if (e.source === e.target) continue;
    const [a, b] = e.source < e.target ? [e.source, e.target] : [e.target, e.source];
    // A separator no node id can contain. Ids here are uuids, optionally
    // prefixed by a kind; `|` appears in neither, and writing the join
    // explicitly keeps the key readable in a debugger.
    const key = `${a}|${b}`;
    const list = groups.get(key);
    if (list) list.push(e); else groups.set(key, [e]);
  }
  const out: Record<string, number> = {};
  for (const list of groups.values()) {
    if (list.length === 1) {
      out[list[0].id] = 0;
      continue;
    }
    const sorted = [...list].sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
    sorted.forEach((e, i) => {
      out[e.id] = (i - (sorted.length - 1) / 2) * spread;
    });
  }
  return out;
}

/**
 * The SVG path for one edge, displaced sideways by `offset`.
 *
 * A quadratic bezier whose control point sits `2 * offset` off the midpoint
 * along the perpendicular: a quadratic curve passes through half its control
 * point's displacement, so doubling it puts the curve's deepest point exactly
 * `offset` from the straight line — which is what makes the spacing
 * `parallelEdgeOffsets` computes the spacing actually drawn.
 *
 * An offset of zero returns the straight line rather than a degenerate curve,
 * so the overwhelmingly common single-edge case is unchanged.
 *
 * Returns the path AND the point a label belongs on, because the midpoint of a
 * displaced curve is not the midpoint of the straight line, and a label placed
 * there would sit off its own edge.
 */
export function offsetEdgePath(
  sx: number, sy: number, tx: number, ty: number, offset: number,
): { path: string; labelX: number; labelY: number } {
  const mx = (sx + tx) / 2;
  const my = (sy + ty) / 2;
  const dx = tx - sx;
  const dy = ty - sy;
  const len = Math.hypot(dx, dy);
  // Two endpoints at the same point have no perpendicular to displace along.
  // The straight (zero-length) path is odd-looking but finite; dividing by zero
  // would put NaN in a `d` attribute, which the browser drops silently — the
  // edge would vanish with no error anywhere.
  if (offset === 0 || len === 0) {
    return { path: `M ${sx},${sy} L ${tx},${ty}`, labelX: mx, labelY: my };
  }
  const nx = -dy / len;
  const ny = dx / len;
  return {
    path: `M ${sx},${sy} Q ${mx + nx * offset * 2},${my + ny * offset * 2} ${tx},${ty}`,
    labelX: mx + nx * offset,
    labelY: my + ny * offset,
  };
}
