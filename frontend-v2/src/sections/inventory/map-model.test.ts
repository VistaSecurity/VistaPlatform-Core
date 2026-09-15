// The map's view model (workstream 2.9).
//
// Everything the map decides before it draws anything: which edges exist, what
// colours a node, what the truncation banner admits to, and how the impact
// overlay fades with distance. None of it needs a DOM, and all of it is the
// kind of thing that is invisible when it is wrong — a rejected edge redrawn,
// a class silently reading as "unknown", a capped graph presented as a total.
import { describe, expect, it } from 'vitest';
import { ASSET_CLASSES, ASSET_CLASS_KEYS } from '@vistasecurity/primitives/assets';
import type { Impact, Neighbourhood, Relationship } from './relationships';
import {
  CLASS_GROUP_KEYS, CLASS_GROUP_STYLES, IMPACT_DIMMED_OPACITY,
  buildImpactOverlay, buildMapGraph, canvasState, capGraph, classGroupOf, classGroupStyle,
  impactOverlayHeadline, impactTint, legendFor, nodeAriaLabel, nodeLabel,
  selectionAfterNodeChanges, statusRing, truncationNotice, type ClassGroupKey,
} from './map-model';

const ROOT = '11111111-1111-1111-1111-111111111111';
const HOST = '22222222-2222-2222-2222-222222222222';
const DB = '33333333-3333-3333-3333-333333333333';

function edge(over: Partial<Relationship> & Pick<Relationship, 'id' | 'from_asset_id' | 'to_asset_id'>): Relationship {
  return {
    tenant_id: 'tenant',
    type: 'runs_on',
    source_kind: 'measured',
    confidence: 0.9,
    status: 'active',
    first_seen_at: '2026-01-01T00:00:00Z',
    last_seen_at: '2026-09-01T00:00:00Z',
    observation_count: 4,
    ...over,
  };
}

function neighbourhood(over: Partial<Neighbourhood> = {}): Neighbourhood {
  return {
    root_asset_id: ROOT,
    depth: 2,
    include_pending: false,
    nodes: [
      { asset_id: ROOT, display_name: 'app-01', class_key: 'web_application', asset_status: 'monitoring', depth: 0, is_root: true },
      { asset_id: HOST, display_name: 'host-01', class_key: 'server', asset_status: 'monitoring', depth: 1 },
      { asset_id: DB, display_name: 'db-01', class_key: 'managed_database', asset_status: 'pending_approval', depth: 2 },
    ],
    edges: [
      edge({ id: 'e1', from_asset_id: ROOT, to_asset_id: HOST, type: 'runs_on' }),
      edge({ id: 'e2', from_asset_id: ROOT, to_asset_id: DB, type: 'depends_on', status: 'pending', source_kind: 'inferred' }),
    ],
    truncated: false,
    total_nodes: 3,
    total_edges: 2,
    node_cap: 500,
    edge_cap: 2000,
    ...over,
  };
}

describe('buildMapGraph', () => {
  it('turns the payload into nodes and edges, keeping the root marked', () => {
    const g = buildMapGraph(neighbourhood());
    expect(g.rootId).toBe(ROOT);
    expect(g.nodes.map((n) => n.id)).toEqual([ROOT, HOST, DB]);
    expect(g.nodes.find((n) => n.id === ROOT)!.isRoot).toBe(true);
    expect(g.nodes.find((n) => n.id === HOST)!.isRoot).toBe(false);
    expect(g.edges.map((e) => e.id)).toEqual(['e1', 'e2']);
  });

  it('NEVER draws a rejected edge', () => {
    // Somebody decided that relationship was wrong. Redrawing it puts a settled
    // decision back up for grabs, and it is the one edge status the map must be
    // unable to show even if the server sends it.
    const g = buildMapGraph(neighbourhood({
      edges: [
        edge({ id: 'e1', from_asset_id: ROOT, to_asset_id: HOST }),
        edge({ id: 'rejected', from_asset_id: ROOT, to_asset_id: DB, status: 'rejected' }),
      ],
    }));
    expect(g.edges.map((e) => e.id)).toEqual(['e1']);
  });

  it('flags a pending edge so it can be drawn dashed, and does not flag the others', () => {
    const g = buildMapGraph(neighbourhood());
    expect(g.edges.find((e) => e.id === 'e2')!.pending).toBe(true);
    expect(g.edges.find((e) => e.id === 'e1')!.pending).toBe(false);
    // A stale edge is still agreed fact — it just has not been seen lately —
    // so it must not pick up the "proposed" dash.
    const stale = buildMapGraph(neighbourhood({
      edges: [edge({ id: 's1', from_asset_id: ROOT, to_asset_id: HOST, status: 'stale' })],
    }));
    expect(stale.edges[0].pending).toBe(false);
  });

  it('dedupes nodes and edges by id, first occurrence winning', () => {
    const n = neighbourhood();
    const g = buildMapGraph({
      ...n,
      nodes: [...n.nodes, { asset_id: HOST, display_name: 'host-01 (again)', depth: 3 }],
      edges: [...n.edges, edge({ id: 'e1', from_asset_id: ROOT, to_asset_id: HOST })],
    });
    expect(g.nodes.filter((x) => x.id === HOST)).toHaveLength(1);
    // The SHORTEST depth survives, because that is the one the server sent
    // first and the distance a person would say the node is at.
    expect(g.nodes.find((x) => x.id === HOST)!.depth).toBe(1);
    expect(g.edges.filter((x) => x.id === 'e1')).toHaveLength(1);
  });

  it('drops an edge whose other end is not on the map', () => {
    // The endpoint only sends edges with both ends in `nodes`, but an edge to a
    // node the cap removed draws as a line into empty space, and "the API
    // promised" is not a reason to render one if that ever stops being true.
    const g = buildMapGraph(neighbourhood({
      edges: [edge({ id: 'dangling', from_asset_id: ROOT, to_asset_id: 'not-on-the-map' })],
    }));
    expect(g.edges).toEqual([]);
  });

  it('is empty, not broken, with no payload', () => {
    expect(buildMapGraph(undefined)).toEqual({ rootId: '', nodes: [], edges: [] });
  });

  it('labels the edge with the relationship vocabulary, not the raw type', () => {
    const g = buildMapGraph(neighbourhood());
    expect(g.edges.find((e) => e.id === 'e1')!.label).toBe('runs on');
    expect(g.edges.find((e) => e.id === 'e2')!.label).toBe('depends on');
  });

  it('carries the provenance an edge hover has to show', () => {
    const e = buildMapGraph(neighbourhood()).edges.find((x) => x.id === 'e2')!;
    expect(e.sourceKind).toBe('inferred');
    expect(e.confidence).toBe(0.9);
    expect(e.firstSeenAt).toBe('2026-01-01T00:00:00Z');
    expect(e.lastSeenAt).toBe('2026-09-01T00:00:00Z');
    expect(e.observationCount).toBe(4);
  });
});

describe('capGraph', () => {
  it('leaves a graph inside the caps alone, by identity', () => {
    const g = buildMapGraph(neighbourhood());
    expect(capGraph(g, 500, 2000)).toBe(g);
  });

  it('never renders more than the cap, and drops the edges that lose an end', () => {
    const g = buildMapGraph(neighbourhood());
    const capped = capGraph(g, 2, 2000);
    expect(capped.nodes).toHaveLength(2);
    // e2 pointed at the node that was cut, so it goes with it rather than
    // becoming a line to nowhere.
    expect(capped.edges.map((e) => e.id)).toEqual(['e1']);
  });

  it('caps edges independently of nodes', () => {
    const g = buildMapGraph(neighbourhood());
    expect(capGraph(g, 500, 1).edges).toHaveLength(1);
  });
});

describe('the class-group style registry', () => {
  it('has a style for EVERY top-level class in the taxonomy', () => {
    // The mutation check: delete one entry from CLASS_GROUP_STYLES and this
    // fails. The roots are read from the generated taxonomy rather than
    // restated, so a class added to standards/asset-classes.yaml lands here as
    // a failure rather than as a grey node nobody can explain.
    const roots = ASSET_CLASS_KEYS.filter((k) => ASSET_CLASSES[k].parent === null);
    expect(roots.length).toBeGreaterThan(4); // a scan that finds nothing must fail
    for (const root of roots) {
      expect(CLASS_GROUP_KEYS, `no map style for top-level class "${root}"`).toContain(root);
      // Looked up through `classGroupStyle`, not by indexing the record: the
      // record's key type is the union this test exists to check, so indexing
      // it with a taxonomy key would be the type system assuming the answer.
      const style = classGroupStyle(root as ClassGroupKey);
      expect(style.color).toBeTruthy();
      expect(style.icon).toBeTruthy();
      expect(style.label).toBeTruthy();
    }
  });

  it('has no style for something that is not a real root (bar the explicit fallback)', () => {
    // The other polarity. A typo'd key would otherwise sit in the registry
    // forever, styling nothing, while the class it was meant for fell through
    // to `other`.
    const roots = new Set(ASSET_CLASS_KEYS.filter((k) => ASSET_CLASSES[k].parent === null) as string[]);
    for (const key of CLASS_GROUP_KEYS) {
      if (key === 'other') continue;
      expect(roots, `"${key}" is styled but is not a top-level class`).toContain(key);
    }
  });

  it('uses design tokens rather than literal colours', () => {
    // A hex here survives a brand retune and a theme switch unchanged, which is
    // how a map ends up unreadable in light mode.
    for (const key of CLASS_GROUP_KEYS) {
      expect(CLASS_GROUP_STYLES[key].color).toMatch(/^var\(--/);
    }
  });

  it('groups a class by the ROOT of its path, however deep it is', () => {
    expect(classGroupOf('server')).toBe('hardware');            // hardware.computer.server
    expect(classGroupOf('access_point')).toBe('hardware');      // hardware.network_device.access_point
    expect(classGroupOf('container')).toBe('virtual');
    expect(classGroupOf('object_storage')).toBe('cloud_resource');
    expect(classGroupOf('web_application')).toBe('application');
    expect(classGroupOf('hardware')).toBe('hardware');          // a root is its own group
  });

  it('sends an unrecognised class to `other`, NOT to `unknown_host`', () => {
    // Tenant leaf subclasses are runtime data and deliberately absent from the
    // generated union, so this is an ordinary case, not an error. Folding it
    // into `unknown_host` — which means "a reachable address nothing has
    // identified" — would invent a data-quality finding out of a client-side
    // vocabulary gap.
    expect(classGroupOf('acme_custom_appliance')).toBe('other');
    expect(classGroupOf('')).toBe('other');
    expect(classGroupOf(null)).toBe('other');
    expect(classGroupOf(undefined)).toBe('other');
    // ...and the real unknown_host class still groups as itself.
    expect(classGroupOf('unknown_host')).toBe('unknown_host');
  });
});

describe('statusRing', () => {
  it('says live, waiting, or out of service — and nothing else', () => {
    expect(statusRing('monitoring')).toBe('monitoring');
    expect(statusRing('pending_approval')).toBe('pending');
    expect(statusRing('archived')).toBe('muted');
    expect(statusRing('denied')).toBe('muted');
    // An absent status is NOT "monitoring": a node whose lifecycle we cannot
    // state must not be drawn as if it were confirmed live.
    expect(statusRing(undefined)).toBe('muted');
    expect(statusRing('')).toBe('muted');
  });
});

describe('nodeLabel', () => {
  it('prefers the display name', () => {
    expect(nodeLabel({ asset_id: ROOT, display_name: 'app-01', class_key: 'server' })).toBe('app-01');
  });

  it('falls back to the class plus a short id, never a bare uuid', () => {
    expect(nodeLabel({ asset_id: ROOT, class_key: 'server' })).toBe('Server 11111111');
    expect(nodeLabel({ asset_id: ROOT })).toBe('11111111…');
    // Whitespace is not a name.
    expect(nodeLabel({ asset_id: ROOT, display_name: '   ' })).toBe('11111111…');
  });
});

describe('truncationNotice', () => {
  it('is null when nothing was cut', () => {
    expect(truncationNotice(neighbourhood(), { nodes: 3, edges: 2 })).toBeNull();
    expect(truncationNotice(undefined, { nodes: 0, edges: 0 })).toBeNull();
  });

  it('reports BOTH counts when the graph is a prefix of the real one', () => {
    const notice = truncationNotice(
      neighbourhood({ truncated: true, total_nodes: 812, total_edges: 3104 }),
      { nodes: 500, edges: 2000 },
    )!;
    expect(notice).not.toBeNull();
    expect(notice.nodesShown).toBe(500);
    expect(notice.nodesFound).toBe(812);
    expect(notice.edgesShown).toBe(2000);
    expect(notice.edgesFound).toBe(3104);
    // The numbers have to be IN the sentence — a banner that says "truncated"
    // without saying by how much tells a person nothing they can act on.
    expect(notice.text).toContain('500 of 812 assets');
    expect(notice.text).toContain('2000 of 3104 relationships');
  });
});

describe('the impact overlay', () => {
  function impact(over: Partial<Impact> = {}): Impact {
    return {
      root_asset_id: ROOT,
      direction: 'downstream',
      depth: 5,
      types: ['runs_on', 'depends_on'],
      nodes: [
        { asset_id: HOST, depth: 1 },
        { asset_id: DB, depth: 3 },
      ],
      counts_by_depth: [{ depth: 1, count: 1 }, { depth: 3, count: 1 }],
      total: 2,
      truncated: false,
      node_cap: 500,
      ...over,
    };
  }

  it('indexes the closure by asset, keeping the SHORTEST hop count', () => {
    const o = buildImpactOverlay(impact({
      nodes: [{ asset_id: HOST, depth: 3 }, { asset_id: HOST, depth: 1 }],
    }))!;
    expect(o.depthById[HOST]).toBe(1);
  });

  it('tints by depth: nearer is stronger, and the furthest hop is still visible', () => {
    const o = buildImpactOverlay(impact())!;
    const near = impactTint(o, HOST, ROOT);
    const far = impactTint(o, DB, ROOT);
    expect(near.inImpact).toBe(true);
    expect(near.depth).toBe(1);
    expect(near.strength).toBe(1);
    expect(far.inImpact).toBe(true);
    expect(far.depth).toBe(3);
    expect(far.strength).toBeLessThan(near.strength);
    // Floored, so the last hop reads as "in the blast radius" rather than as a
    // bystander that happens to be faint.
    expect(far.strength).toBeGreaterThanOrEqual(0.3);
  });

  it('dims — does not hide — an asset outside the closure', () => {
    // "Nothing else is affected" is only readable if the something-else is
    // still on screen.
    const o = buildImpactOverlay(impact())!;
    const outside = impactTint(o, 'somebody-else', ROOT);
    expect(outside.inImpact).toBe(false);
    expect(outside.depth).toBeNull();
    expect(outside.opacity).toBe(IMPACT_DIMMED_OPACITY);
    expect(outside.opacity).toBeGreaterThan(0);
  });

  it('always keeps the focus asset lit', () => {
    // The impact closure excludes its own root, so without this the asset being
    // asked about is the one node that dims.
    const o = buildImpactOverlay(impact())!;
    const root = impactTint(o, ROOT, ROOT);
    expect(root.inImpact).toBe(true);
    expect(root.depth).toBe(0);
    expect(root.opacity).toBe(1);
  });

  it('leaves everything lit when the overlay is off', () => {
    const off = impactTint(null, 'anything', ROOT);
    expect(off.opacity).toBe(1);
    expect(off.inImpact).toBe(true);
  });

  it('does not divide by zero on a single-hop closure', () => {
    const o = buildImpactOverlay(impact({ nodes: [{ asset_id: HOST, depth: 1 }], total: 1 }))!;
    expect(o.maxDepth).toBe(1);
    expect(impactTint(o, HOST, ROOT).strength).toBe(1);
  });

  it('says "at least" when the closure was capped', () => {
    // The same honesty `impactHeadline` keeps: a floored total is a number
    // somebody plans a maintenance window around.
    const capped = buildImpactOverlay(impact({ truncated: true, total: 500 }));
    expect(impactOverlayHeadline(capped)).toBe('At least 500 assets depend on this');
    const exact = buildImpactOverlay(impact());
    expect(impactOverlayHeadline(exact)).toBe('2 assets depend on this');
    const upstream = buildImpactOverlay(impact({ direction: 'upstream', total: 1 }));
    expect(impactOverlayHeadline(upstream)).toBe('1 asset this depends on');
  });

  it('says nothing-recorded rather than nothing-affected on an empty closure', () => {
    const none = buildImpactOverlay(impact({ nodes: [], total: 0, counts_by_depth: [] }));
    expect(impactOverlayHeadline(none)).toBe('Nothing recorded depends on this');
    const noneUp = buildImpactOverlay(impact({ direction: 'upstream', nodes: [], total: 0 }));
    expect(impactOverlayHeadline(noneUp)).toBe('Nothing recorded that this depends on');
  });
});

describe('canvasState', () => {
  const drawn = buildMapGraph(neighbourhood());
  const lone = buildMapGraph(neighbourhood({ nodes: [{ asset_id: ROOT, depth: 0, is_root: true }], edges: [] }));

  it('names each of the four, one at a time', () => {
    expect(canvasState({ isLoading: true, isError: false }, drawn)).toBe('loading');
    expect(canvasState({ isLoading: false, isError: true }, drawn)).toBe('error');
    expect(canvasState({ isLoading: false, isError: false }, lone)).toBe('empty');
    expect(canvasState({ isLoading: false, isError: false }, drawn)).toBe('graph');
  });

  it('a FAILED read is an error, even though the old payload is still in hand', () => {
    // react-query holds the last successful data through a failure, so a graph
    // is sitting there the whole time the request is failing. Reading it would
    // put "No relationships yet" — or worse, a drawn graph of the PREVIOUS
    // asset — under a request that never arrived.
    expect(drawn.nodes.length).toBeGreaterThan(1);   // there IS a graph in hand
    expect(canvasState({ isLoading: false, isError: true }, drawn)).toBe('error');
    expect(canvasState({ isLoading: false, isError: true }, drawn)).not.toBe('graph');
    expect(canvasState({ isLoading: false, isError: true }, drawn)).not.toBe('empty');
  });

  it('a failed read with NOTHING in hand is still an error, not an empty map', () => {
    // The first-load failure. This is the one that would say "nothing has been
    // observed about what this asset is attached to" about an asset the server
    // refused to answer for.
    const nothing = buildMapGraph(undefined);
    expect(canvasState({ isLoading: false, isError: true }, nothing)).toBe('error');
    expect(canvasState({ isLoading: false, isError: false }, nothing)).toBe('empty');
  });

  it('an asset with only itself IS empty — the commonest neighbourhood there is', () => {
    expect(canvasState({ isLoading: false, isError: false }, lone)).toBe('empty');
    expect(lone.nodes).toHaveLength(1);
  });
});

describe('keyboard selection', () => {
  // React Flow makes every node a tab stop and turns Enter / Space / Escape on
  // one into a `select` change. With `nodes` passed controlled and no
  // `onNodesChange`, that change was dropped — so the node panel, which is the
  // only route to "Open asset" and "Focus here", could be opened with a mouse
  // and by nothing else.
  it('takes the node a batch selected', () => {
    expect(selectionAfterNodeChanges([{ type: 'select', id: HOST, selected: true }])).toBe(HOST);
  });

  it('prefers the selection over the deselections that come with it', () => {
    // React Flow emits "deselect the old one" and "select the new one" in one
    // batch, and the order follows the node lookup rather than the click. Both
    // orders have to land on the new node, or every other selection would
    // clear the panel instead of moving it.
    const forwards = selectionAfterNodeChanges([
      { type: 'select', id: ROOT, selected: false },
      { type: 'select', id: HOST, selected: true },
    ]);
    const backwards = selectionAfterNodeChanges([
      { type: 'select', id: HOST, selected: true },
      { type: 'select', id: ROOT, selected: false },
    ]);
    expect(forwards).toBe(HOST);
    expect(backwards).toBe(HOST);
  });

  it('clears on a batch that only deselects — Escape, or a click on the pane', () => {
    expect(selectionAfterNodeChanges([{ type: 'select', id: HOST, selected: false }])).toBeNull();
  });

  it('says NOTHING about a batch with no selection in it', () => {
    // Position and dimension changes arrive through the same callback on every
    // measure and every viewport change. Reading them as "nothing is selected"
    // would close the panel under the user while they were reading it.
    expect(selectionAfterNodeChanges([
      { type: 'dimensions', id: HOST },
      { type: 'position', id: ROOT },
    ])).toBeUndefined();
    expect(selectionAfterNodeChanges([])).toBeUndefined();
  });
});

describe('nodeAriaLabel', () => {
  const graph = buildMapGraph(neighbourhood());
  const find = (id: string) => graph.nodes.find((n) => n.id === id)!;

  it('says the three things the colours say, because none of them are read aloud', () => {
    const label = nodeAriaLabel(find(HOST), null);
    expect(label).toContain('host-01');
    expect(label).toContain('Server');        // the fill and the icon
    expect(label).toContain('Monitored');     // the ring
  });

  it('calls the focus asset the focus, and gives everything else its distance', () => {
    expect(nodeAriaLabel(find(ROOT), 0)).toContain('the focus of this map');
    expect(nodeAriaLabel(find(HOST), 1)).toContain('1 hop from the focus');
    expect(nodeAriaLabel(find(DB), 3)).toContain('3 hops from the focus');
    // No overlay on: no distance claimed.
    expect(nodeAriaLabel(find(HOST), null)).not.toContain('hop');
  });

  it('falls back to the class GROUP when the class key is unknown to this build', () => {
    // The same rule the visible label keeps — an unrecognised subclass reads as
    // "Other", not as a blank.
    const unknown = { ...find(HOST), classLabel: '', group: 'other' as const };
    expect(nodeAriaLabel(unknown, null)).toContain('Other');
  });
});

describe('legendFor', () => {
  it('describes the picture, not the taxonomy', () => {
    // A legend listing all seven groups when the graph holds three is a legend
    // nobody reads.
    const legend = legendFor(buildMapGraph(neighbourhood()));
    expect(legend.map((l) => l.group)).toEqual(['cloud_resource', 'application', 'hardware'].sort(
      (a, b) => CLASS_GROUP_KEYS.indexOf(a as never) - CLASS_GROUP_KEYS.indexOf(b as never),
    ));
    expect(legend.every((l) => l.count === 1)).toBe(true);
  });
});
