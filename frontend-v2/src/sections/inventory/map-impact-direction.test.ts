// The impact overlay draws the answer the SERVER gave, per-type direction and
// all (ADR-0003 D5, as amended.
//
// The amendment exists because D5's original rule — one uniform "walk the
// impact-bearing types in reverse" — is wrong for the two types that point the
// other way. `contains` is container → contained and `manages` is manager →
// managed, so a uniform reverse walk inverts them, and the demonstration table
// in the ADR is blunt about what that cost:
//
//     asked about                      "what breaks if this dies" returned
//     wlc-controller (manages an AP)   (nothing)
//     ap-01                            wlc-controller
//
// Backwards, for exactly the class of asset the ops persona asks about.
//
// The traversal is the server's and stays the server's — the fix lives in
// `shared/relationships` and is asserted there against a real Postgres. What
// this file pins is the CLIENT half: that the overlay reproduces the answer it
// was given rather than re-deriving one, because re-deriving it from the
// neighbourhood edges already on screen is the obvious-looking optimisation
// that would reintroduce the uniform reverse on this side of the wire — and it
// would look right, because on most of the vocabulary a uniform reverse IS
// right.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Impact, Neighbourhood, Relationship, RelationshipType } from './relationships';
import { buildImpactOverlay, buildMapGraph, impactTint, impactOverlayHeadline } from './map-model';

const WLC = 'aaaaaaaa-0000-0000-0000-000000000001'; // a wireless controller
const AP1 = 'aaaaaaaa-0000-0000-0000-000000000002'; // an access point it manages
const AP2 = 'aaaaaaaa-0000-0000-0000-000000000003'; // and another
const SW1 = 'aaaaaaaa-0000-0000-0000-000000000004'; // a switch it merely talks to

function edge(id: string, from: string, to: string, type: RelationshipType): Relationship {
  return {
    id,
    tenant_id: 'tenant',
    from_asset_id: from,
    to_asset_id: to,
    type,
    source_kind: 'measured',
    confidence: 0.95,
    status: 'active',
    first_seen_at: '2026-01-01T00:00:00Z',
    last_seen_at: '2026-09-01T00:00:00Z',
    observation_count: 12,
  };
}

/**
 * The neighbourhood as the ADR's demonstration table describes it: the
 * controller MANAGES its access points (so the edges point away from it), and
 * a switch merely CONNECTS TO it.
 */
const NEIGHBOURHOOD: Neighbourhood = {
  root_asset_id: WLC,
  depth: 2,
  include_pending: false,
  nodes: [
    { asset_id: WLC, display_name: 'wlc-controller', class_key: 'network_device', asset_status: 'monitoring', depth: 0, is_root: true },
    { asset_id: AP1, display_name: 'ap-01', class_key: 'network_device', asset_status: 'monitoring', depth: 1 },
    { asset_id: AP2, display_name: 'ap-02', class_key: 'network_device', asset_status: 'monitoring', depth: 1 },
    { asset_id: SW1, display_name: 'sw-01', class_key: 'network_device', asset_status: 'monitoring', depth: 1 },
  ],
  edges: [
    edge('e-m1', WLC, AP1, 'manages'),
    edge('e-m2', WLC, AP2, 'manages'),
    edge('e-c1', SW1, WLC, 'connects_to'),
  ],
  truncated: false,
  total_nodes: 4,
  total_edges: 3,
  node_cap: 500,
  edge_cap: 2000,
};

/** What the AMENDED server answers for "what breaks if the controller dies":
 *  `manages` is walked FORWARD downstream, so the access points. */
const DOWNSTREAM_FROM_CONTROLLER: Impact = {
  root_asset_id: WLC,
  direction: 'downstream',
  depth: 6,
  types: [
    'runs_on', 'hosted_on', 'virtualized_by', 'depends_on', 'member_of',
    'sends_data_to', 'contains', 'manages', 'impacts',
  ],
  nodes: [
    { asset_id: AP1, depth: 1 },
    { asset_id: AP2, depth: 1 },
  ],
  counts_by_depth: [{ depth: 1, count: 2 }],
  total: 2,
  truncated: false,
  node_cap: 500,
};

/** The exact mirror, from one of the access points. */
const UPSTREAM_FROM_AP: Impact = {
  ...DOWNSTREAM_FROM_CONTROLLER,
  root_asset_id: AP1,
  direction: 'upstream',
  nodes: [{ asset_id: WLC, depth: 1 }],
  counts_by_depth: [{ depth: 1, count: 1 }],
  total: 1,
};

/**
 * The regression, implemented: the closure a UNIFORM-REVERSE walk over the
 * impact-bearing types produces from the same edges. This is not a strawman —
 * it is what D5 said before the amendment, and what the shipped CTE did.
 */
function uniformReverseClosure(nbh: Neighbourhood, root: string): Set<string> {
  const impactBearing = (t: RelationshipType) => t !== 'connects_to';
  const found = new Set<string>();
  const queue = [root];
  while (queue.length) {
    const at = queue.shift()!;
    for (const e of nbh.edges) {
      if (!impactBearing(e.type) || e.to_asset_id !== at || found.has(e.from_asset_id)) continue;
      found.add(e.from_asset_id);
      queue.push(e.from_asset_id);
    }
  }
  return found;
}

describe('the impact overlay follows the per-type direction (ADR-0003 D5 amendment)', () => {
  const graph = buildMapGraph(NEIGHBOURHOOD);
  const overlay = buildImpactOverlay(DOWNSTREAM_FROM_CONTROLLER)!;

  it('lights the access points a controller MANAGES when asked what it takes down', () => {
    // The headline question, and the one a uniform reverse answered with
    // silence. `manages` points controller → AP, so the things at risk are at
    // the FAR end of the edge, not the near one.
    expect(impactTint(overlay, AP1, WLC).inImpact).toBe(true);
    expect(impactTint(overlay, AP2, WLC).inImpact).toBe(true);
    expect(impactTint(overlay, AP1, WLC).depth).toBe(1);
    expect(impactOverlayHeadline(overlay)).toBe('2 assets depend on this');
  });

  it('disagrees with a uniform-reverse walk over the very same edges', () => {
    // The tripwire. Re-deriving the closure on this side from the edges already
    // on screen is the obvious optimisation — one fewer request, the data is
    // right there — and on six of the nine types it would agree, which is what
    // makes it dangerous. Here it returns the EMPTY SET where the truth is two
    // access points, which is the ADR's first table row exactly.
    const naive = uniformReverseClosure(NEIGHBOURHOOD, WLC);
    expect([...naive]).toEqual([]);
    expect(Object.keys(overlay.depthById).sort()).toEqual([AP1, AP2].sort());
    // Stated as a disagreement rather than as two separate facts, so this fails
    // if the overlay is ever fed a uniformly-reversed closure.
    for (const id of Object.keys(overlay.depthById)) expect(naive.has(id)).toBe(false);
  });

  it('does not light a `connects_to` neighbour — an observed flow is not a dependency', () => {
    const sw = impactTint(overlay, SW1, WLC);
    expect(sw.inImpact).toBe(false);
    // Dimmed, not hidden: it is still on the map, still readable as unaffected.
    expect(sw.opacity).toBeGreaterThan(0);
    expect(sw.opacity).toBeLessThan(1);
    // ...and the server said so, by echoing the vocabulary it walked.
    expect(DOWNSTREAM_FROM_CONTROLLER.types).not.toContain('connects_to');
  });

  it('echoes NINE impact-bearing types, not the eight D5 originally listed', () => {
    // `impacts` is walked since the amendment (as a terminal hop). Anything
    // quoting eight is stale.
    expect(DOWNSTREAM_FROM_CONTROLLER.types).toHaveLength(9);
    expect(DOWNSTREAM_FROM_CONTROLLER.types).toContain('impacts');
    expect(DOWNSTREAM_FROM_CONTROLLER.types).toContain('manages');
    expect(DOWNSTREAM_FROM_CONTROLLER.types).toContain('contains');
  });

  it('mirrors: upstream from an access point reaches the controller', () => {
    const up = buildImpactOverlay(UPSTREAM_FROM_AP)!;
    expect(impactTint(up, WLC, AP1).inImpact).toBe(true);
    expect(up.direction).toBe('upstream');
    expect(impactOverlayHeadline(up)).toBe('1 asset this depends on');
  });

  it('keeps the focus lit and every node it was given, in both directions', () => {
    // The closure excludes its own root, so the asset being asked about is the
    // one node that would otherwise dim.
    expect(impactTint(overlay, WLC, WLC).opacity).toBe(1);
    // Every node on the map is accounted for — lit or dimmed, none dropped.
    expect(graph.nodes).toHaveLength(4);
    for (const n of graph.nodes) expect(impactTint(overlay, n.id, WLC).opacity).toBeGreaterThan(0);
  });
});

// ------------------------------------------------------------- the wiring --

// The overlay above is fed by `/impact`. Pinning the model without pinning what
// reaches the request would leave the direction toggle free to stop arriving —
// the shape of bug CLAUDE.md calls out ("test the WIRING, not just the
// helper"). No DOM harness exists here, so this is structural.
const lensSrc = readFileSync(fileURLToPath(new URL('./map-lens.tsx', import.meta.url)), 'utf8');
const queriesSrc = readFileSync(fileURLToPath(new URL('./relationship-queries.ts', import.meta.url)), 'utf8');

describe('the direction the user picked reaches the request', () => {
  it('the map passes its own direction state to useAssetImpact', () => {
    expect(lensSrc).toMatch(/useAssetImpact\(assetId, impactDirection, impactOn\)/);
  });

  it('...and the hook forwards it as the `direction` query param, and keys on it', () => {
    expect(queriesSrc).toMatch(/queryKey: \['asset-impact', id, direction\]/);
    expect(queriesSrc).toMatch(/query: \{ direction \}/);
  });

  it('the overlay reads the direction the SERVER echoed, not the local toggle', () => {
    // If the two ever disagree — a request in flight, a failed refetch — the
    // headline must describe the answer on screen rather than the button.
    expect(buildImpactOverlay(UPSTREAM_FROM_AP)!.direction).toBe(UPSTREAM_FROM_AP.direction);
  });
});
