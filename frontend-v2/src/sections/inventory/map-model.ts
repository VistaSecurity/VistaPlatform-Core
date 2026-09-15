// The map's view model (ADR-0006 D4, workstream 2.9).
//
// Everything in this file is PURE: it turns the neighbourhood payload
// `useAssetNeighbourhood` already returns into the nodes, edges, styles and
// overlays the renderer draws, and nothing here imports `@xyflow/react`. That
// split is deliberate on two counts. It keeps the parts that are easy to get
// quietly wrong — which edges are drawn at all, which class a node is coloured
// by, what a truncated graph admits to — unit-testable in the node environment
// this project's vitest runs in; and it keeps the graph library out of the main
// bundle, since the only module that imports it is the lazily-loaded renderer.
//
// The exporters (map-export.ts) serialise THIS model, not xyflow's internal
// one, so a GraphML file describes the graph the user was looking at rather
// than a layout engine's idea of it.
import { ASSET_CLASSES, type AssetClassKey } from '@vistasecurity/primitives/assets';
import {
  TYPE_LABEL, edgeLabel,
  type Impact, type Neighbourhood, type Relationship, type RelationshipType,
} from './relationships';

// ------------------------------------------------------------- the model --

/** One asset, as the map draws it. */
export interface MapNode {
  id: string;
  /** What the node is labelled with — never a bare uuid (see `nodeLabel`). */
  label: string;
  /** The raw `class_key` the server sent, or '' when it sent none. */
  classKey: string;
  /** The class's own label ('' when the key is unknown to this build). */
  classLabel: string;
  /** Which top-level class group styles it (ADR-0002 taxonomy roots). */
  group: ClassGroupKey;
  /** Lifecycle status — drives the ring, not the fill. */
  status: string;
  riskScore?: number;
  /** Shortest hop count from the focus asset; 0 is the focus itself. */
  depth: number;
  isRoot: boolean;
}

/** One relationship, as the map draws it. */
export interface MapEdge {
  id: string;
  source: string;
  target: string;
  type: RelationshipType;
  /** How the edge reads left-to-right, from the `from` end. */
  label: string;
  status: Relationship['status'];
  /** Pending edges are drawn DASHED — proposed, not agreed (ADR-0003 D3). */
  pending: boolean;
  sourceKind: Relationship['source_kind'];
  confidence: number;
  firstSeenAt: string;
  lastSeenAt: string;
  observationCount: number;
}

export interface MapGraph {
  rootId: string;
  nodes: MapNode[];
  edges: MapEdge[];
}

// ------------------------------------------------- the class-group styles --

/**
 * The top-level roots of the ADR-0002 class taxonomy, plus `other`.
 *
 * The seven are the `class_path` roots — `hardware.computer.server` groups as
 * `hardware`. `other` is NOT an eighth class: it is what an unrecognised
 * `class_key` resolves to, which is a real and ordinary case, because tenant
 * leaf subclasses are runtime data and deliberately absent from the generated
 * union. Folding those into `unknown_host` would have been the tempting
 * shortcut and the wrong one — `unknown_host` means "a reachable address
 * nothing has identified", which is a finding, while an unrecognised subclass
 * key means "this build does not know that word". Colouring the second as the
 * first would invent a data-quality problem out of a client-side gap.
 */
export type ClassGroupKey =
  | 'hardware' | 'virtual' | 'cloud_resource' | 'application'
  | 'service' | 'external' | 'unknown_host' | 'other';

export interface ClassGroupStyle {
  label: string;
  /** A design token, never a literal — the map has to survive a brand retune
   *  and both themes like everything else does. */
  color: string;
  /** A kebab-case name in components/ui/icon.tsx's MAP. */
  icon: string;
}

/**
 * Icon and colour per group.
 *
 * The icons match what the class picker shows for the same root, so a node on
 * the map and a row in the facet rail are recognisably the same thing. The
 * colours come from the categorical + status token set rather than fresh hexes.
 */
export const CLASS_GROUP_STYLES: Readonly<Record<ClassGroupKey, ClassGroupStyle>> = {
  hardware: { label: 'Hardware', color: 'var(--chart-2)', icon: 'circuit-board' },
  virtual: { label: 'Virtual', color: 'var(--chart-1)', icon: 'layers' },
  cloud_resource: { label: 'Cloud resource', color: 'var(--chart-3)', icon: 'cloud' },
  application: { label: 'Application', color: 'var(--ok)', icon: 'app-window' },
  service: { label: 'Service', color: 'var(--ok-lime)', icon: 'workflow' },
  external: { label: 'External party', color: 'var(--warn-strong)', icon: 'external-link' },
  // Amber, not grey: an unidentified host inside the estate is the gap the
  // inventory exists to close, and greying it would read as "nothing to see".
  unknown_host: { label: 'Unknown host', color: 'var(--warn)', icon: 'circle-help' },
  other: { label: 'Other', color: 'var(--neutral)', icon: 'circle-dashed' },
};

/** Every group the styles cover, in the order the legend lists them. */
export const CLASS_GROUP_KEYS = Object.keys(CLASS_GROUP_STYLES) as ClassGroupKey[];

/**
 * Which group a class key belongs to.
 *
 * Resolved through the generated taxonomy's materialised `path`, so a class
 * added to the YAML lands in the right group with no edit here — the only
 * thing this file has to own is a style per ROOT, and the roots change about
 * once a product.
 */
export function classGroupOf(classKey?: string | null): ClassGroupKey {
  const key = (classKey ?? '').trim();
  if (!key) return 'other';
  const cls = ASSET_CLASSES[key as AssetClassKey];
  if (!cls) return 'other';
  const root = cls.path.split('.')[0];
  return (root in CLASS_GROUP_STYLES ? root : 'other') as ClassGroupKey;
}

export const classGroupStyle = (group: ClassGroupKey): ClassGroupStyle =>
  CLASS_GROUP_STYLES[group] ?? CLASS_GROUP_STYLES.other;

// ------------------------------------------------------ the status ring ---

export type StatusRing = 'monitoring' | 'pending' | 'muted';

/**
 * The ring drawn around a node.
 *
 * Status is shown as a RING rather than as the fill because the fill already
 * carries the class, and a pending server must still read as a server. Only
 * three rings, because only three answers change what a person does: it is
 * live, it is waiting on somebody, or it is out of service.
 */
export function statusRing(status?: string | null): StatusRing {
  switch ((status ?? '').trim()) {
    case 'monitoring': return 'monitoring';
    case 'pending_approval': return 'pending';
    default: return 'muted';
  }
}

export const STATUS_RING_COLOR: Readonly<Record<StatusRing, string>> = {
  monitoring: 'var(--ok)',
  pending: 'var(--warn)',
  muted: 'var(--app-border2)',
};

export const STATUS_RING_HELP: Readonly<Record<StatusRing, string>> = {
  monitoring: 'Monitored — part of the live inventory.',
  pending: 'Waiting for approval. Not yet counted anywhere.',
  muted: 'Archived, denied, or otherwise not in service.',
};

// -------------------------------------------------------- node and edge ---

/**
 * What to call a node.
 *
 * Display name, then the class label, then a shortened id — never the bare
 * uuid, for the same reason `peerName` never shows one: a node a person cannot
 * read is a node they cannot decide anything about, and a freshly discovered
 * asset usually has no display name at all.
 */
export function nodeLabel(node: { display_name?: string; class_key?: string; asset_id: string }): string {
  if (node.display_name?.trim()) return node.display_name.trim();
  const cls = ASSET_CLASSES[(node.class_key ?? '') as AssetClassKey];
  if (cls) return `${cls.label} ${node.asset_id.slice(0, 8)}`;
  return `${node.asset_id.slice(0, 8)}…`;
}

/**
 * Turn the neighbourhood payload into the map's model.
 *
 * Three rules, each of which is a thing that has gone wrong in a graph UI
 * before:
 *
 *  1. **Rejected edges are never drawn.** Somebody decided that relationship
 *     was wrong; redrawing it puts the decision back up for grabs. The server
 *     already excludes them unless asked for by name, so this is the client
 *     half of a rule both ends keep.
 *  2. **An edge needs both ends present.** The endpoint promises it only sends
 *     edges whose ends survived the node cap, but an edge to a missing node
 *     draws as a line into empty space, and "the API promised" is not a reason
 *     to render one if it ever stops being true.
 *  3. **Dedupe by id.** A node reachable by several routes must be placed once,
 *     at the shortest depth — which is what the server's `depth` already is, so
 *     first-wins over a stable payload is enough, and the test pins it.
 */
export function buildMapGraph(nbh: Neighbourhood | undefined): MapGraph {
  if (!nbh) return { rootId: '', nodes: [], edges: [] };

  const nodes: MapNode[] = [];
  const seenNodes = new Set<string>();
  for (const n of nbh.nodes ?? []) {
    if (!n?.asset_id || seenNodes.has(n.asset_id)) continue;
    seenNodes.add(n.asset_id);
    nodes.push({
      id: n.asset_id,
      label: nodeLabel(n),
      classKey: n.class_key ?? '',
      classLabel: ASSET_CLASSES[(n.class_key ?? '') as AssetClassKey]?.label ?? '',
      group: classGroupOf(n.class_key),
      status: n.asset_status ?? '',
      riskScore: n.risk_score,
      depth: n.depth,
      isRoot: n.is_root === true || n.asset_id === nbh.root_asset_id,
    });
  }

  const edges: MapEdge[] = [];
  const seenEdges = new Set<string>();
  for (const e of nbh.edges ?? []) {
    if (!e?.id || seenEdges.has(e.id)) continue;
    if (e.status === 'rejected') continue;
    if (!seenNodes.has(e.from_asset_id) || !seenNodes.has(e.to_asset_id)) continue;
    seenEdges.add(e.id);
    edges.push({
      id: e.id,
      source: e.from_asset_id,
      target: e.to_asset_id,
      // No end is privileged on a neighbourhood edge, so this is the forward
      // reading of the type — `edgeLabel` with no asset id returns exactly that.
      label: edgeLabel(e) || TYPE_LABEL[e.type],
      type: e.type,
      status: e.status,
      pending: e.status === 'pending',
      sourceKind: e.source_kind,
      confidence: e.confidence,
      firstSeenAt: e.first_seen_at,
      lastSeenAt: e.last_seen_at,
      observationCount: e.observation_count,
    });
  }

  return { rootId: nbh.root_asset_id, nodes, edges };
}

/**
 * Hard-cap the graph at what the API said it would send.
 *
 * The server caps at 500 nodes / 2000 edges and sets `truncated`. This is the
 * client refusing to draw more than that even if a future server sends more —
 * the browser tab is the thing that dies, and "the graph got slow" is a much
 * worse bug report than "the graph said it was truncated".
 */
export function capGraph(graph: MapGraph, nodeCap: number, edgeCap: number): MapGraph {
  if (graph.nodes.length <= nodeCap && graph.edges.length <= edgeCap) return graph;
  const nodes = graph.nodes.slice(0, Math.max(0, nodeCap));
  const kept = new Set(nodes.map((n) => n.id));
  const edges = graph.edges
    .filter((e) => kept.has(e.source) && kept.has(e.target))
    .slice(0, Math.max(0, edgeCap));
  return { rootId: graph.rootId, nodes, edges };
}

// ---------------------------------------------------------- truncation ----

export interface TruncationNotice {
  nodesShown: number;
  nodesFound: number;
  edgesShown: number;
  edgesFound: number;
  text: string;
}

/**
 * What the truncation banner says, or null when nothing was cut.
 *
 * A capped graph is a PREFIX of the real one, and the counts are the point:
 * "500 assets" next to a map that is actually a corner of an 800-asset
 * neighbourhood is the same class of lie as an impact total that silently
 * floors. `impactHeadline` says "at least" for the same reason.
 */
export function truncationNotice(nbh: Neighbourhood | undefined, shown: { nodes: number; edges: number }): TruncationNotice | null {
  if (!nbh?.truncated) return null;
  const notice = {
    nodesShown: shown.nodes,
    nodesFound: nbh.total_nodes,
    edgesShown: shown.edges,
    edgesFound: nbh.total_edges,
  };
  return {
    ...notice,
    text:
      `Showing ${notice.nodesShown} of ${notice.nodesFound} assets and `
      + `${notice.edgesShown} of ${notice.edgesFound} relationships. `
      + 'This neighbourhood is larger than the map draws at once — reduce the depth, '
      + 'or focus on a node closer to what you are looking for.',
  };
}

// ------------------------------------------------------- impact overlay ---

export interface ImpactOverlay {
  direction: Impact['direction'];
  /** Hop count per asset id. The focus asset is NOT in here — the impact
   *  closure excludes its own root — and is handled by the renderer. */
  depthById: Readonly<Record<string, number>>;
  maxDepth: number;
  total: number;
  truncated: boolean;
}

export function buildImpactOverlay(impact: Impact | undefined): ImpactOverlay | null {
  if (!impact) return null;
  const depthById: Record<string, number> = {};
  let maxDepth = 0;
  for (const n of impact.nodes ?? []) {
    if (!n?.asset_id) continue;
    // Shortest wins, matching the server's own rule for `depth`: a node
    // reachable by two routes is at the distance a person would say it is.
    const prev = depthById[n.asset_id];
    if (prev === undefined || n.depth < prev) depthById[n.asset_id] = n.depth;
    if (n.depth > maxDepth) maxDepth = n.depth;
  }
  return {
    direction: impact.direction,
    depthById,
    maxDepth,
    total: impact.total,
    truncated: impact.truncated,
  };
}

export interface NodeTint {
  /** In the closure (or the focus itself). */
  inImpact: boolean;
  /** Hop count; 0 for the focus, null for a node outside the closure. */
  depth: number | null;
  /** 1 at the first hop, fading with distance. 0 when outside. */
  strength: number;
  /** What the node is drawn at while the overlay is on — outside-the-closure
   *  nodes are dimmed rather than hidden, because "nothing else is affected"
   *  is only readable if the something-else is still on screen. */
  opacity: number;
}

export const IMPACT_DIMMED_OPACITY = 0.22;

/**
 * How strongly to tint one node, given the overlay.
 *
 * Depth 1 is full strength and it fades with distance, floored at 0.3 so the
 * furthest hop is still visibly in the closure rather than indistinguishable
 * from a dimmed bystander. The focus node is strength 1: it is the thing being
 * asked about.
 */
export function impactTint(overlay: ImpactOverlay | null, nodeId: string, rootId: string): NodeTint {
  if (!overlay) return { inImpact: true, depth: null, strength: 0, opacity: 1 };
  if (nodeId === rootId) return { inImpact: true, depth: 0, strength: 1, opacity: 1 };
  const depth = overlay.depthById[nodeId];
  if (depth === undefined) {
    return { inImpact: false, depth: null, strength: 0, opacity: IMPACT_DIMMED_OPACITY };
  }
  // A single-hop closure has maxDepth 1 and must not divide by zero.
  const span = Math.max(1, overlay.maxDepth);
  const strength = Math.max(0.3, 1 - (depth - 1) / span);
  return { inImpact: true, depth, strength, opacity: 1 };
}

/** The overlay's own headline — direction in words, and a floor when the
 *  closure was capped, for the same reason `impactHeadline` says "at least". */
export function impactOverlayHeadline(overlay: ImpactOverlay | null): string {
  if (!overlay) return '';
  const noun = overlay.total === 1 ? 'asset' : 'assets';
  const verb = overlay.direction === 'upstream' ? 'this depends on' : 'depend on this';
  if (overlay.total === 0) {
    return overlay.direction === 'upstream'
      ? 'Nothing recorded that this depends on'
      : 'Nothing recorded depends on this';
  }
  return `${overlay.truncated ? 'At least ' : ''}${overlay.total} ${noun} ${verb}`;
}

// --------------------------------------------------------- canvas state ---

/** What the canvas is actually showing. Exactly one of four. */
export type CanvasState = 'loading' | 'error' | 'empty' | 'graph';

/**
 * Which of the four the map is in.
 *
 * The order is the whole point, and it is `loading` then `error` before either
 * of the two that make a claim about the estate. `graph` is derived from a
 * payload react-query is HOLDING, and react-query holds the last successful one
 * through a failure — so a read that just 404'd or 500'd still has nodes in
 * hand. Deciding "empty" or "graph" from that would say "no relationships yet"
 * about an asset nobody managed to ask about, which is the same lie in the same
 * shape as a score of 0 meaning "not assessed".
 *
 * Everything that describes "the graph on screen" — the Export menu and the
 * truncation banner both do — has to follow THIS rather than the payload, or it
 * describes a picture the user is not looking at: exporting the previous
 * asset's neighbourhood from under an error card, under a filename naming that
 * asset, is a file that cannot be told apart from a real one afterwards.
 */
export function canvasState(
  query: { isLoading: boolean; isError: boolean },
  graph: MapGraph,
): CanvasState {
  if (query.isLoading) return 'loading';
  if (query.isError) return 'error';
  // One node and no edges is the root by itself — the commonest neighbourhood
  // there is, and an ordinary answer rather than a failure.
  if (graph.nodes.length <= 1 && graph.edges.length === 0) return 'empty';
  return 'graph';
}

// ------------------------------------------------------- keyboard + a11y ---

/**
 * What a screen reader is told a node is.
 *
 * The sighted reading of a node is three channels at once — the class in the
 * fill and icon, the lifecycle in the ring, the blast radius in the tint — and
 * none of them survive as text. Without this every node announces as "node",
 * which is the one thing the reader already knew. The order matches how the
 * side panel reads the same asset, so the two do not describe it differently.
 */
export function nodeAriaLabel(node: MapNode, impactDepth: number | null): string {
  const parts = [node.label, node.classLabel || classGroupStyle(node.group).label];
  parts.push(STATUS_RING_HELP[statusRing(node.status)].replace(/\.$/, ''));
  if (node.isRoot) parts.push('the focus of this map');
  else if (impactDepth !== null && impactDepth > 0) {
    parts.push(`${impactDepth} hop${impactDepth === 1 ? '' : 's'} from the focus`);
  }
  return parts.join(', ');
}

/** The shape of a React Flow node change this cares about. Declared
 *  structurally rather than imported, because `@xyflow/react` must not reach
 *  this module — see the header. */
export interface NodeSelectionChange {
  type: string;
  id?: string;
  selected?: boolean;
}

/**
 * What a batch of React Flow node changes says the selection is now.
 *
 * `undefined` means "this batch said nothing about selection, leave it alone";
 * `null` means it was cleared; a string is the node now selected.
 *
 * This exists because the map's node panel — the only route to **Open asset**
 * and **Focus here** — was reachable by mouse only. React Flow makes every node
 * a tab stop and handles Enter, Space and Escape on it, but it reports the
 * result as a change through `onNodesChange`; with `nodes` passed as a
 * controlled prop and no handler, `triggerNodeChanges` dropped it on the floor.
 * The nodes were focusable and activating one did nothing at all, which is a
 * worse state than not being focusable: a few hundred tab stops that lead
 * nowhere.
 *
 * A positive selection wins outright over the deselections in the same batch —
 * React Flow emits "deselect everything else" and "select this one" together,
 * and in whichever order they come out of the lookup.
 */
export function selectionAfterNodeChanges(
  changes: readonly NodeSelectionChange[],
): string | null | undefined {
  let next: string | null | undefined;
  for (const c of changes) {
    if (c?.type !== 'select') continue;
    if (c.selected && c.id) return c.id;
    next = null;
  }
  return next;
}

// ----------------------------------------------------------- the legend ---

/** The groups actually present in this graph, so the legend describes the
 *  picture rather than the taxonomy. */
export function legendFor(graph: MapGraph): { group: ClassGroupKey; style: ClassGroupStyle; count: number }[] {
  const counts = new Map<ClassGroupKey, number>();
  for (const n of graph.nodes) counts.set(n.group, (counts.get(n.group) ?? 0) + 1);
  return CLASS_GROUP_KEYS
    .filter((g) => counts.has(g))
    .map((group) => ({ group, style: CLASS_GROUP_STYLES[group], count: counts.get(group)! }));
}
