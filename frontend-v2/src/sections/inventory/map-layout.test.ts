// The dagre layout wrapper (workstream 2.9).
//
// The property that matters most here is DETERMINISM, and it is the one a
// screenshot cannot check. A force-directed layout settles somewhere different
// on every run, so the same neighbourhood looks like a different system on each
// visit and a map pasted into a ticket cannot be matched to what the reader
// sees. Dagre does not do that — and this file is what stops a later "let's try
// elk / a force layout" from quietly reintroducing it.
//
// The golden coordinates are pinned against @dagrejs/dagre 3.1.1, which the
// package.json pins exactly. A dagre upgrade that moves them is a real change
// to what every user sees, and should have to be looked at rather than
// absorbed.
import { describe, expect, it } from 'vitest';
import {
  DIRECTION_LABEL, HANDLE_SIDES, NODE_HEIGHT, NODE_WIDTH, PARALLEL_EDGE_SPREAD,
  flipDirection, layoutGraph, offsetEdgePath, parallelEdgeOffsets,
} from './map-layout';
import type { MapEdge, MapGraph, MapNode } from './map-model';

const node = (id: string, depth: number): MapNode => ({
  id, label: id, classKey: '', classLabel: '', group: 'other',
  status: 'monitoring', depth, isRoot: id === 'a',
});

const edge = (id: string, source: string, target: string): MapEdge => ({
  id, source, target, type: 'runs_on', label: 'runs on', status: 'active',
  pending: false, sourceKind: 'measured', confidence: 1,
  firstSeenAt: '', lastSeenAt: '', observationCount: 1,
});

/** a → b → c, plus a → d. A chain with one branch: enough to see both the
 *  rank axis and the sibling axis move. */
const FIXTURE: MapGraph = {
  rootId: 'a',
  nodes: [node('a', 0), node('b', 1), node('c', 2), node('d', 1)],
  edges: [edge('e1', 'a', 'b'), edge('e2', 'b', 'c'), edge('e3', 'a', 'd')],
};

describe('layoutGraph', () => {
  it('places every node, and only the nodes it was given', () => {
    const { positions } = layoutGraph(FIXTURE, 'LR');
    expect(Object.keys(positions).sort()).toEqual(['a', 'b', 'c', 'd']);
  });

  it('is DETERMINISTIC — the same graph lays out identically every time', () => {
    // Run it three times, including with a freshly-rebuilt (but equal) graph
    // object, so a hidden dependency on object identity or on iteration order
    // would show up.
    const a = layoutGraph(FIXTURE, 'LR');
    const b = layoutGraph(FIXTURE, 'LR');
    const c = layoutGraph({ ...FIXTURE, nodes: [...FIXTURE.nodes], edges: [...FIXTURE.edges] }, 'LR');
    expect(b).toEqual(a);
    expect(c).toEqual(a);
  });

  it('matches the golden LR layout', () => {
    const { positions, width, height } = layoutGraph(FIXTURE, 'LR');
    expect(positions).toEqual({
      a: { x: 24, y: 65 },
      b: { x: 308, y: 106 },
      c: { x: 592, y: 106 },
      d: { x: 308, y: 24 },
    });
    expect({ width, height }).toEqual({ width: 804, height: 186 });
  });

  it('matches the golden TB layout', () => {
    const { positions, width, height } = layoutGraph(FIXTURE, 'TB');
    expect(positions).toEqual({
      a: { x: 131, y: 24 },
      b: { x: 238, y: 176 },
      c: { x: 238, y: 328 },
      d: { x: 24, y: 176 },
    });
    expect({ width, height }).toEqual({ width: 450, height: 408 });
  });

  it('actually swings the axis when the direction is toggled', () => {
    // The property, stated independently of the golden numbers: LR advances
    // hops along X and keeps a rank's members level; TB does the opposite. A
    // toggle that changed nothing would pass a golden test written from its own
    // output, so this is asserted as a relationship rather than as coordinates.
    const lr = layoutGraph(FIXTURE, 'LR').positions;
    expect(lr.a.x).toBeLessThan(lr.b.x);
    expect(lr.b.x).toBeLessThan(lr.c.x);
    expect(lr.b.x).toBe(lr.d.x); // same hop → same rank → same column

    const tb = layoutGraph(FIXTURE, 'TB').positions;
    expect(tb.a.y).toBeLessThan(tb.b.y);
    expect(tb.b.y).toBeLessThan(tb.c.y);
    expect(tb.b.y).toBe(tb.d.y); // same hop → same rank → same row

    expect(tb).not.toEqual(lr);
  });

  it('honours a node size override, because the renderer owns the box', () => {
    const wide = layoutGraph(FIXTURE, 'LR', { nodeWidth: NODE_WIDTH * 2, nodeHeight: NODE_HEIGHT });
    const normal = layoutGraph(FIXTURE, 'LR');
    expect(wide.width).toBeGreaterThan(normal.width);
  });

  it('survives a self-edge and an edge to a node that is not there', () => {
    // Either one makes dagre emit a dummy node, which would surface as a node
    // the model never had. `buildMapGraph` drops dangling edges already; this
    // is the second belt, and it is cheap.
    const weird: MapGraph = {
      rootId: 'a',
      nodes: [node('a', 0), node('b', 1)],
      edges: [edge('self', 'a', 'a'), edge('gone', 'a', 'ghost'), edge('ok', 'a', 'b')],
    };
    const { positions } = layoutGraph(weird, 'LR');
    expect(Object.keys(positions).sort()).toEqual(['a', 'b']);
    expect(Number.isFinite(positions.a.x)).toBe(true);
    expect(Number.isFinite(positions.b.y)).toBe(true);
  });

  it('keeps two relationships between the same pair as two edges', () => {
    // An application both `runs_on` and `connects_to` its host. A simple
    // (non-multi) graph collapses those into one line, and the map then shows
    // fewer relationships than the count beside it claims.
    const parallel: MapGraph = {
      rootId: 'a',
      nodes: [node('a', 0), node('b', 1)],
      edges: [edge('r1', 'a', 'b'), { ...edge('r2', 'a', 'b'), type: 'connects_to' }],
    };
    expect(() => layoutGraph(parallel, 'LR')).not.toThrow();
    expect(Object.keys(layoutGraph(parallel, 'LR').positions)).toHaveLength(2);
  });

  it('reports a FINITE size for an empty graph, not NaN', () => {
    // dagre derives the graph box from the extent of its nodes, so with no
    // nodes it hands back a non-finite width. `Math.round(NaN)` is NaN, a NaN
    // in a style attribute is dropped silently by the browser, and the
    // container then collapses with no error anywhere. "This asset has no
    // relationships" is the single commonest state on this page, so the empty
    // graph is the one that has to be right.
    const empty = layoutGraph({ rootId: '', nodes: [], edges: [] }, 'LR');
    expect(empty.positions).toEqual({});
    expect(Number.isFinite(empty.width)).toBe(true);
    expect(Number.isFinite(empty.height)).toBe(true);
    expect(empty).toEqual({ positions: {}, width: 0, height: 0 });
  });

  it('lays out a lone node — the commonest neighbourhood there is', () => {
    // Most of an inventory is a leaf. A single-node graph must place it rather
    // than divide by a rank count of zero.
    const { positions } = layoutGraph({ rootId: 'a', nodes: [node('a', 0)], edges: [] }, 'LR');
    expect(positions.a).toEqual({ x: 24, y: 24 });
  });
});

describe('HANDLE_SIDES', () => {
  it('anchors edges on the axis the ranks actually advance along', () => {
    // Derived from dagre's real output rather than restated, so this fails if
    // either half moves: flip a side and the expectation no longer matches the
    // layout; change `rankdir` and the layout no longer matches the sides.
    //
    // Getting this wrong is not cosmetic. In TB the ranks stack DOWNWARDS, so
    // an edge leaving the right of a node and entering the left of the one
    // directly beneath it is drawn as a loop back over the stack — a parent and
    // its child read as two things side by side.
    const sidesForAxis = {
      x: { source: 'right', target: 'left' },
      y: { source: 'bottom', target: 'top' },
    } as const;

    for (const direction of ['LR', 'TB'] as const) {
      const p = layoutGraph(FIXTURE, direction).positions;
      // `a → b` is one hop, so whichever axis it advances on IS the rank axis.
      const axis = Math.abs(p.b.x - p.a.x) > Math.abs(p.b.y - p.a.y) ? 'x' : 'y';
      expect(HANDLE_SIDES[direction]).toEqual(sidesForAxis[axis]);
      // ...and the source side is the FORWARD end of it, not merely on it.
      expect(p.b[axis]).toBeGreaterThan(p.a[axis]);
    }
  });

  it('covers both directions and never puts both ends on the same side', () => {
    for (const direction of ['LR', 'TB'] as const) {
      const { source, target } = HANDLE_SIDES[direction];
      expect(source).not.toBe(target);
    }
    expect(HANDLE_SIDES.LR).not.toEqual(HANDLE_SIDES.TB);
  });
});

describe('flipDirection', () => {
  it('is an involution, and both directions have a label', () => {
    expect(flipDirection('LR')).toBe('TB');
    expect(flipDirection('TB')).toBe('LR');
    expect(flipDirection(flipDirection('LR'))).toBe('LR');
    expect(DIRECTION_LABEL.LR).toBeTruthy();
    expect(DIRECTION_LABEL.TB).toBeTruthy();
  });
});


// --- parallel edges ---------------------------------------------------------
//
// Two assets are routinely joined by more than one relationship — an
// application `runs_on` its host AND `connects_to` it — and both used to be
// drawn along the same spline. One line was visible; the second was hidden
// underneath with its label overprinted and no way to hover it, so its
// provenance, confidence and observation count were unreachable. A map whose
// job is to say how two things are related was silently saying "one way".

describe('parallel edge offsets', () => {
  const e = (id: string, source: string, target: string) => ({ id, source, target });

  it('leaves a lone edge exactly where it was', () => {
    // The overwhelmingly common case. Displacing it would bend every edge in
    // every neighbourhood to fix a problem almost none of them have.
    expect(parallelEdgeOffsets([e('x', 'a', 'b')])).toEqual({ x: 0 });
  });

  it('spreads two edges between the same pair symmetrically about the line', () => {
    const got = parallelEdgeOffsets([e('e1', 'a', 'b'), e('e2', 'a', 'b')]);
    expect(got).toEqual({ e1: -PARALLEL_EDGE_SPREAD / 2, e2: PARALLEL_EDGE_SPREAD / 2 });
    // Symmetric, not "both bend right": the pair should straddle where the
    // single line used to be, so neither reads as the real one.
    expect(got.e1 + got.e2).toBe(0);
  });

  it('separates an OPPOSITE-direction pair too', () => {
    // a→b and b→a are drawn along the same geometry; only the arrowhead
    // differs. Grouping by the directed pair would leave them coincident,
    // which is the same bug with a narrower fixture.
    const got = parallelEdgeOffsets([e('e1', 'a', 'b'), e('e2', 'b', 'a')]);
    expect(got.e1).not.toBe(got.e2);
  });

  it('puts the middle of an odd group on the straight line', () => {
    const got = parallelEdgeOffsets([e('e1', 'a', 'b'), e('e2', 'a', 'b'), e('e3', 'a', 'b')]);
    expect(got).toEqual({ e1: -PARALLEL_EDGE_SPREAD, e2: 0, e3: PARALLEL_EDGE_SPREAD });
  });

  it('is stable under a reordering of the input', () => {
    // The server does not promise an order. Offsetting by array position would
    // make the same two edges swap sides between two renders of one graph.
    const a = parallelEdgeOffsets([e('e1', 'a', 'b'), e('e2', 'a', 'b')]);
    const b = parallelEdgeOffsets([e('e2', 'a', 'b'), e('e1', 'a', 'b')]);
    expect(a).toEqual(b);
  });

  it('does not let a different pair share a group', () => {
    const got = parallelEdgeOffsets([e('e1', 'a', 'b'), e('e2', 'a', 'c')]);
    expect(got).toEqual({ e1: 0, e2: 0 });
  });

  it('skips self-edges, which are never drawn', () => {
    expect(parallelEdgeOffsets([e('loop', 'a', 'a'), e('x', 'a', 'b')])).toEqual({ x: 0 });
  });
});

describe('the offset edge path', () => {
  it('is a straight line at zero offset', () => {
    const { path, labelX, labelY } = offsetEdgePath(0, 0, 100, 0, 0);
    expect(path).toBe('M 0,0 L 100,0');
    expect([labelX, labelY]).toEqual([50, 0]);
  });

  it('bends the curve so its deepest point is exactly `offset` from the line', () => {
    // A quadratic bezier passes through HALF its control point's displacement,
    // so the control point has to be twice as far out. Getting this wrong
    // halves every gap, which is invisible in a screenshot and wrong in the
    // one case the spacing exists for.
    const { path, labelX, labelY } = offsetEdgePath(0, 0, 100, 0, 30);
    expect(path).toBe('M 0,0 Q 50,60 100,0');
    expect([labelX, labelY]).toEqual([50, 30]);
  });

  it('displaces perpendicular to the line, not along an axis', () => {
    // A vertical edge must be pushed horizontally.
    const { labelX, labelY } = offsetEdgePath(0, 0, 0, 100, 10);
    expect(labelX).toBe(-10);
    // …and still sit at the midpoint along the line itself.
    expect(labelY).toBe(50);
  });

  it('never emits NaN for coincident endpoints', () => {
    // Dividing by a zero length would put NaN in a `d` attribute, which the
    // browser drops with no error — the edge would simply vanish.
    const { path, labelX, labelY } = offsetEdgePath(5, 5, 5, 5, 30);
    expect(path).not.toContain('NaN');
    expect(Number.isFinite(labelX) && Number.isFinite(labelY)).toBe(true);
  });
});
