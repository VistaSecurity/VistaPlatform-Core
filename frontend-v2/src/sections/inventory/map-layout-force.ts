// Scalable layout for large maps (frontend-v2 ADR-0018).
//
// Dagre is the right tool for a neighbourhood a person can read, and the wrong
// one for 500 nodes and 2000 edges: its network-simplex ranker and crossing
// minimisation take seconds and never finish on dense cyclic graphs. This is the
// large-graph path: a force simulation with a FIXED tick budget, so the cost is
// bounded by (nodes + edges) x ticks no matter how tangled the graph is, and a
// cycle is just another spring.
//
// It keeps what dagre gave the map: ranks. Every node is pulled toward its hop
// depth along the layout axis, so the root still sits at one end and "how far
// from here" still reads left-to-right (or top-to-bottom). Within a rank the
// forces settle the cross axis.
//
// DETERMINISTIC, because a map pasted into a ticket must match what the reader
// sees (see map-layout.test.ts): nodes are processed in id order, the starting
// positions are computed (no phyllotaxis, no Math.random), and the simulation's
// random source — used only to break exact coincidences — is a seeded LCG.
// Pure: no React, no xyflow, so it runs unchanged in the layout worker.
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from 'd3-force';
import type { LayoutDirection, LayoutInput, LayoutOptions, LayoutResult } from './map-layout';

/** Simulation ticks. Fixed rather than "until alpha settles" so the cost, and
 *  the output, depend only on the input. */
export const FORCE_TICKS = 120;

const MARGIN = 24;

const lcg = (seed: number) => {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 4294967296);
};

interface Sim { id: string; depth: number; x: number; y: number }

/**
 * Push apart boxes that still overlap after the simulation. The collide force
 * works on circles, so on 188x56 boxes it leaves a residue where two boxes are
 * side by side; this relaxes exactly that, on the true rectangles. A grid keyed
 * on the box size keeps each pass linear. Fixed pass count, ordered iteration:
 * deterministic.
 */
function separateBoxes(p: Sim[], w: number, h: number, gap: number): void {
  const bw = w + gap; const bh = h + gap;
  for (let pass = 0; pass < 8; pass++) {
    const grid = new Map<string, Sim[]>();
    for (const s of p) {
      const k = `${Math.floor(s.x / bw)},${Math.floor(s.y / bh)}`;
      const l = grid.get(k); if (l) l.push(s); else grid.set(k, [s]);
    }
    let moved = false;
    for (const a of p) {
      const cx = Math.floor(a.x / bw); const cy = Math.floor(a.y / bh);
      for (let i = -1; i <= 1; i++) for (let j = -1; j <= 1; j++) {
        for (const b of grid.get(`${cx + i},${cy + j}`) ?? []) {
          if (b.id <= a.id) continue;
          const dx = b.x - a.x; const dy = b.y - a.y;
          const ox = bw - Math.abs(dx); const oy = bh - Math.abs(dy);
          if (ox <= 0 || oy <= 0) continue;
          moved = true;
          // Resolve along the axis needing the smaller move; an exact tie
          // separates by id order rather than by chance.
          if (oy <= ox) { const m = oy / 2 * (dy < 0 ? -1 : 1); a.y -= m; b.y += m; }
          else { const m = ox / 2 * (dx < 0 ? -1 : 1); a.x -= m; b.x += m; }
        }
      }
    }
    if (!moved) break;
  }
}

export function layoutForce(
  graph: LayoutInput,
  direction: LayoutDirection,
  nodeWidth: number,
  nodeHeight: number,
  opts: LayoutOptions = {},
): LayoutResult {
  const rankSep = opts.rankSep ?? 96;
  const nodeSep = opts.nodeSep ?? 26;
  // `rank` runs along the layout axis, `cross` across it. Simulated in (rank,
  // cross) and mapped to (x, y) at the end, so LR and TB share one code path.
  const rankStep = (direction === 'LR' ? nodeWidth : nodeHeight) + rankSep;
  const crossStep = (direction === 'LR' ? nodeHeight : nodeWidth) + nodeSep;

  const sorted = [...graph.nodes].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const nodes: Sim[] = [];
  const byId = new Map<string, Sim>();
  const perRank = new Map<number, number>();
  for (const n of sorted) {
    const depth = Math.max(0, Math.trunc(n.depth ?? 0));
    const k = perRank.get(depth) ?? 0;
    perRank.set(depth, k + 1);
    // Starting cross position: stacked in id order. Deterministic and already
    // collision-free, so the simulation refines rather than untangles.
    const s: Sim = { id: n.id, depth, x: depth * rankStep, y: k * crossStep };
    nodes.push(s);
    byId.set(n.id, s);
  }
  // Centre each rank on the cross axis so no rank starts offset from the others.
  for (const s of nodes) s.y -= ((perRank.get(s.depth) ?? 1) - 1) * crossStep / 2;

  const links: { source: Sim; target: Sim }[] = [];
  for (const e of graph.edges) {
    const a = byId.get(e.source);
    const b = byId.get(e.target);
    if (!a || !b || a === b) continue;
    links.push({ source: a, target: b });
  }

  if (nodes.length > 0) {
    const radius = Math.hypot(nodeWidth, nodeHeight) / 2 + nodeSep / 2;
    const sim = forceSimulation<Sim>(nodes)
      .randomSource(lcg(0x9e3779b9))
      .stop()
      .force('link', forceLink<Sim, { source: Sim; target: Sim }>(links).distance(rankStep).strength(0.08).iterations(1))
      // distanceMax bounds the many-body work for sparse far-apart pairs.
      .force('charge', forceManyBody<Sim>().strength(-260).theta(0.9).distanceMax(rankStep * 4))
      .force('collide', forceCollide<Sim>(radius).iterations(3))
      // The rank pull: strong enough that depth stays the dominant reading,
      // weak enough that a node tied to many neighbours can drift off its rank.
      .force('rank', forceX<Sim>((d) => d.depth * rankStep).strength(0.15))
      .force('cross', forceY<Sim>(0).strength(0.02));
    // d3 maps x to the first axis: it is the rank axis here.
    sim.tick(FORCE_TICKS);
  }

  // Back to drawing axes before the box pass, which is about real rectangles.
  if (direction === 'TB') for (const s of nodes) [s.x, s.y] = [s.y, s.x];
  separateBoxes(nodes, nodeWidth, nodeHeight, nodeSep / 2);

  let minX = Infinity; let minY = Infinity; let maxX = -Infinity; let maxY = -Infinity;
  for (const s of nodes) {
    if (!Number.isFinite(s.x)) s.x = 0;
    if (!Number.isFinite(s.y)) s.y = 0;
    minX = Math.min(minX, s.x); maxX = Math.max(maxX, s.x);
    minY = Math.min(minY, s.y); maxY = Math.max(maxY, s.y);
  }
  const positions: Record<string, { x: number; y: number }> = {};
  for (const s of nodes) {
    positions[s.id] = { x: Math.round(s.x - minX + MARGIN), y: Math.round(s.y - minY + MARGIN) };
  }
  if (nodes.length === 0) return { positions, width: 0, height: 0 };
  return {
    positions,
    width: Math.round(maxX - minX + nodeWidth + MARGIN * 2),
    height: Math.round(maxY - minY + nodeHeight + MARGIN * 2),
  };
}
