// The large-graph layout. Pins the three things that matter at the
// server's cap: it FINISHES (dagre took 10-17 s on 500/2000 and never ended on
// cycles), it is DETERMINISTIC, and it leaves no NaN or overlapping boxes.
import { describe, expect, it } from 'vitest';
import {
  FORCE_LAYOUT_THRESHOLD, NODE_HEIGHT, NODE_WIDTH, layoutGraph, usesForceLayout,
} from './map-layout';
import { randomGraph } from './map-layout-fixtures';

// Generous: the measured time is about a second; the budget only has to be far
// below dagre's 10+ s while tolerating a loaded CI runner.
const BUDGET_MS = 10_000;

const overlaps = (positions: Record<string, { x: number; y: number }>) => {
  const p = Object.values(positions);
  let n = 0;
  for (let i = 0; i < p.length; i++) for (let j = i + 1; j < p.length; j++) {
    if (Math.abs(p[i].x - p[j].x) < NODE_WIDTH && Math.abs(p[i].y - p[j].y) < NODE_HEIGHT) n++;
  }
  return n;
};

describe('layoutGraph at scale', () => {
  for (const dir of ['LR', 'TB'] as const) {
    it(`lays out 500 nodes / 2000 CYCLIC edges (${dir}) inside the time budget, finite and non-overlapping`, () => {
      const g = randomGraph(500, 2000, true);
      expect(usesForceLayout(g)).toBe(true);
      const t = performance.now();
      const r = layoutGraph(g, dir);
      expect(performance.now() - t).toBeLessThan(BUDGET_MS);
      expect(Object.keys(r.positions)).toHaveLength(500);
      for (const p of Object.values(r.positions)) {
        expect(Number.isFinite(p.x)).toBe(true);
        expect(Number.isFinite(p.y)).toBe(true);
        expect(p.x).toBeGreaterThanOrEqual(0);
        expect(p.y).toBeGreaterThanOrEqual(0);
      }
      expect(Number.isFinite(r.width) && r.width > 0).toBe(true);
      expect(Number.isFinite(r.height) && r.height > 0).toBe(true);
      expect(overlaps(r.positions)).toBe(0);
    }, 60_000);
  }

  it('is deterministic — identical input gives identical coordinates', () => {
    const a = layoutGraph(randomGraph(300, 1200, true), 'LR');
    const b = layoutGraph(randomGraph(300, 1200, true), 'LR');
    expect(b).toEqual(a);
  });

  it('keeps hop depth as the rank axis: deeper nodes sit further along it', () => {
    const g = randomGraph(300, 900, false);
    const { positions } = layoutGraph(g, 'LR');
    const mean = (d: number) => {
      const xs = g.nodes.filter((n) => n.depth === d).map((n) => positions[n.id].x);
      return xs.reduce((s, x) => s + x, 0) / xs.length;
    };
    expect(mean(0)).toBeLessThan(mean(1));
    expect(mean(1)).toBeLessThan(mean(2));
  });

  it('tolerates self-edges, edges to missing nodes, duplicate edges and nodes without depth', () => {
    const g = {
      nodes: Array.from({ length: 130 }, (_, i) => ({ id: `n${i}` })),
      edges: [
        { id: 's', source: 'n0', target: 'n0' },
        { id: 'd', source: 'n0', target: 'missing' },
        { id: 'a', source: 'n1', target: 'n2' },
        { id: 'b', source: 'n1', target: 'n2' },
      ],
    };
    const r = layoutGraph(g, 'TB');
    expect(Object.keys(r.positions)).toHaveLength(130);
    expect(Object.values(r.positions).every((p) => Number.isFinite(p.x) && Number.isFinite(p.y))).toBe(true);
  });

  it('leaves small graphs on dagre: the threshold is the existing one', () => {
    expect(FORCE_LAYOUT_THRESHOLD).toBe(120);
    expect(usesForceLayout(randomGraph(30, 90, true))).toBe(false); // 120, not above
    expect(usesForceLayout(randomGraph(30, 91, true))).toBe(true);
  });
});
