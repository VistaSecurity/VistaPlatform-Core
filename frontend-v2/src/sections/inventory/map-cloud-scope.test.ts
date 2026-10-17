// Cloud region as a map grouping node ( slice D, amended by
// asset-inventory ADR-0009 D1).
//
// The account used to be a second synthetic box here. It is now a real
// `cloud_account` asset, and every cloud resource reaches it by a STORED
// `hosted_on` edge, so the map draws it like any other asset and this file
// only groups by REGION — a place, not a thing anybody owns, with no asset row
// behind it. That is exactly what makes it easy to get wrong. Everything below
// is one of three failure shapes:
//
//   1. a box that should not exist — a fabricated region for an asset that
//      records none, or one account's box holding another account's resources;
//   2. a box that swallows something — scaffolding counted as an asset in the
//      truncation banner or the legend, or a scope node reached by code that
//      assumes every node has an asset id;
//   3. a box that stops being emitted at all, which is the regression this
//      whole slice would silently become.
import { describe, expect, it } from 'vitest';
import type { Neighbourhood, Relationship } from './relationships';
import {
  assetNodeCount, buildMapGraph, canvasState, capGraph,
  cloudRegionNodeId, cloudRegionSubLabel, isAssetNode, legendFor, nodeAriaLabel,
  truncationNotice, withCloudScopeRoots, type MapGraph, type MapNode,
} from './map-model';
import { toCytoscape, toGraphML } from './map-export';

const ACCOUNT = '123456789012';
const OTHER_ACCOUNT = '210987654321';
const REGION = 'us-east-1';

const LB = 'aaaaaaaa-0000-4000-8000-000000000001';
const KEYS = 'aaaaaaaa-0000-4000-8000-000000000002';
const INSTANCE = 'aaaaaaaa-0000-4000-8000-000000000003';
const BUCKET = 'aaaaaaaa-0000-4000-8000-000000000004';
const CDN = 'aaaaaaaa-0000-4000-8000-000000000005';
const PRINTER = 'aaaaaaaa-0000-4000-8000-000000000006';
const ACCOUNT_ASSET = 'aaaaaaaa-0000-4000-8000-000000000007';

function edge(over: Partial<Relationship> & Pick<Relationship, 'id' | 'from_asset_id' | 'to_asset_id'>): Relationship {
  return {
    tenant_id: 'tenant',
    type: 'contains',
    source_kind: 'measured',
    confidence: 1,
    status: 'active',
    first_seen_at: '2026-09-01T00:00:00Z',
    last_seen_at: '2026-09-21T00:00:00Z',
    observation_count: 2,
    ...over,
  };
}

/** A cloud estate in the classes that exist after cloud subnets became IPAM
 * prefixes and VPCs container prefixes (asset-inventory ADR-0009,
 *  amendment): a load balancer that contains a key store that contains an
 *  instance (generic containment chain — the map is class-agnostic about it),
 *  plus a bucket and a CDN distribution with no containment at all. DCIM row
 *  1.6 will add prefix grouping to the map; until then there are no VPC/subnet
 *  asset nodes. */
// (VPC -> subnet -> instance nesting was retired with the classes; see ADR-0009 amendment and DCIM row 1.6.)
function awsNeighbourhood(over: Partial<Neighbourhood> = {}): Neighbourhood {
  return {
    root_asset_id: LB,
    depth: 3,
    include_pending: false,
    nodes: [
      { asset_id: LB, display_name: 'lb-front', class_key: 'cloud_load_balancer', asset_status: 'monitoring', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
      { asset_id: KEYS, display_name: 'key-vault', class_key: 'key_store', asset_status: 'monitoring', depth: 1, cloud_account: ACCOUNT, cloud_region: REGION },
      { asset_id: INSTANCE, display_name: 'web-01', class_key: 'compute_instance', asset_status: 'monitoring', depth: 2, cloud_account: ACCOUNT, cloud_region: REGION },
      { asset_id: BUCKET, display_name: 'assets-bucket', class_key: 'object_storage', asset_status: 'monitoring', depth: 3, cloud_account: ACCOUNT, cloud_region: REGION },
      { asset_id: CDN, display_name: 'd123.cloudfront.net', class_key: 'cdn_distribution', asset_status: 'monitoring', depth: 3, cloud_account: ACCOUNT, cloud_region: 'global' },
    ],
    edges: [
      edge({ id: 'e-lb-keys', from_asset_id: LB, to_asset_id: KEYS }),
      edge({ id: 'e-keys-instance', from_asset_id: KEYS, to_asset_id: INSTANCE }),
    ],
    truncated: false,
    total_nodes: 5,
    total_edges: 2,
    node_cap: 500,
    edge_cap: 2000,
    ...over,
  };
}

const rooted = (nbh: Neighbourhood = awsNeighbourhood()): MapGraph => withCloudScopeRoots(buildMapGraph(nbh));

const byId = (g: MapGraph, id: string): MapNode | undefined => g.nodes.find((n) => n.id === id);
const hasEdge = (g: MapGraph, source: string, target: string): boolean =>
  g.edges.some((e) => e.source === source && e.target === target);

// ---------------------------------------------------------------------------

describe('buildMapGraph carries the scoping attributes', () => {
  it('reads cloud_account and cloud_region off the payload', () => {
    const g = buildMapGraph(awsNeighbourhood());
    expect(byId(g, LB)?.cloudAccount).toBe(ACCOUNT);
    expect(byId(g, CDN)?.cloudRegion).toBe('global');
  });

  it('treats a blank or whitespace value as ABSENT, not as a region called ""', () => {
    // The server omits the field when the fact is missing, but a proxy, a
    // fixture or a future serialiser can still hand over "". Absent and empty
    // have to end up in the same place, because only one box may be drawn for
    // either and it is no box at all.
    const g = buildMapGraph(awsNeighbourhood({
      nodes: [{ asset_id: BUCKET, display_name: 'b', class_key: 'object_storage', depth: 0, is_root: true, cloud_account: '   ', cloud_region: '' }],
      edges: [],
    }));
    expect(byId(g, BUCKET)?.cloudAccount).toBeUndefined();
    expect(byId(g, BUCKET)?.cloudRegion).toBeUndefined();
  });

  it('marks every payload node as an asset, with its asset id', () => {
    const g = buildMapGraph(awsNeighbourhood());
    for (const n of g.nodes) {
      expect(n.kind).toBe('asset');
      expect(n.assetId).toBe(n.id);
      expect(isAssetNode(n)).toBe(true);
    }
  });
});

describe('withCloudScopeRoots', () => {
  it('groups by region: region → load balancer → key store → instance, and synthesises NO account box', () => {
    const g = rooted();
    const regionId = cloudRegionNodeId(ACCOUNT, REGION);

    expect(byId(g, regionId)?.kind).toBe('cloud_region');
    expect(hasEdge(g, regionId, LB)).toBe(true);
    // The account is an asset now (ADR-0009 D1); nothing fabricates a box for it.
    expect(g.nodes.some((n) => n.id.startsWith('scope:cloud_account'))).toBe(false);
    // The stored half of the chain is untouched.
    expect(hasEdge(g, LB, KEYS)).toBe(true);
    expect(hasEdge(g, KEYS, INSTANCE)).toBe(true);
  });

  it('hangs a bucket and a CDN distribution off their region rather than leaving them isolated', () => {
    const g = rooted();
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), BUCKET)).toBe(true);
    // `global` is the distribution's real answer, not a stand-in for unknown,
    // so it gets its own box under the same account.
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, 'global'), CDN)).toBe(true);
  });

  it('draws the account as the stored hosted_on edges say, and never puts it in a region', () => {
    // The account asset arrives in the payload with its own stored edges; the
    // region grouping leaves those alone and does not box the account itself.
    const g = rooted(awsNeighbourhood({
      root_asset_id: ACCOUNT_ASSET,
      nodes: [
        { asset_id: ACCOUNT_ASSET, display_name: 'AWS account ' + ACCOUNT, class_key: 'cloud_account', asset_status: 'monitoring', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
        { asset_id: BUCKET, display_name: 'assets-bucket', class_key: 'object_storage', asset_status: 'monitoring', depth: 1, cloud_account: ACCOUNT, cloud_region: REGION },
      ],
      edges: [edge({ id: 'e-bucket-account', from_asset_id: BUCKET, to_asset_id: ACCOUNT_ASSET, type: 'hosted_on' })],
    }));
    expect(hasEdge(g, BUCKET, ACCOUNT_ASSET)).toBe(true);
    expect(g.edges.find((e) => e.id === 'e-bucket-account')?.synthetic).toBe(false);
    // hosted_on is not containment: the bucket is still grouped by its region.
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), BUCKET)).toBe(true);
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), ACCOUNT_ASSET)).toBe(false);
  });

  it('does NOT also hang a contained asset off its region', () => {
    // The key store is inside the LB and the instance inside the key store.
    // Adding a region → key store edge would draw the same containment twice and flatten
    // the hierarchy into a bush.
    const g = rooted();
    const regionId = cloudRegionNodeId(ACCOUNT, REGION);
    expect(hasEdge(g, regionId, KEYS)).toBe(false);
    expect(hasEdge(g, regionId, INSTANCE)).toBe(false);
  });

  it('DOES attach an asset whose container fell outside the depth window', () => {
    // On this map the key store really is a root: its LB is not drawn. Leaving it
    // unattached would reproduce the bug this slice exists to fix, one level
    // down.
    const g = rooted(awsNeighbourhood({
      root_asset_id: KEYS,
      nodes: [
        { asset_id: KEYS, display_name: 'key-vault', class_key: 'key_store', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
        { asset_id: INSTANCE, display_name: 'web-01', class_key: 'compute_instance', depth: 1, cloud_account: ACCOUNT, cloud_region: REGION },
      ],
      edges: [edge({ id: 'e-keys-instance', from_asset_id: KEYS, to_asset_id: INSTANCE })],
    }));
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), KEYS)).toBe(true);
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), INSTANCE)).toBe(false);
  });

  it('never invents a region for an asset that records none', () => {
    const g = rooted(awsNeighbourhood({
      root_asset_id: PRINTER,
      nodes: [{ asset_id: PRINTER, display_name: 'printer-01', class_key: 'printer', depth: 0, is_root: true }],
      edges: [],
      total_nodes: 1,
      total_edges: 0,
    }));
    // Unchanged: still one node, still no edges, and no box labelled "—" or
    // "unknown" that a reader would take for a place.
    expect(g.nodes).toHaveLength(1);
    expect(g.edges).toHaveLength(0);
    expect(g.nodes.every(isAssetNode)).toBe(true);
  });

  it('keeps a region-less cloud asset ON the map, unboxed', () => {
    // The other polarity of the rule above: absent must not mean deleted
    // either. An asset that knows its account and not its region stays where
    // it is — attached to its account, if at all, by its stored hosted_on edge.
    const g = rooted(awsNeighbourhood({
      root_asset_id: BUCKET,
      nodes: [{ asset_id: BUCKET, display_name: 'assets-bucket', class_key: 'object_storage', depth: 0, is_root: true, cloud_account: ACCOUNT }],
      edges: [],
    }));
    expect(byId(g, BUCKET)).toBeDefined();
    expect(g.nodes).toHaveLength(1);
    expect(g.nodes.filter((n) => n.kind === 'cloud_region')).toHaveLength(0);
  });

  it('gives an account-less asset its own region box, labelled as such', () => {
    const g = rooted(awsNeighbourhood({
      nodes: [
        { asset_id: LB, display_name: 'lb-front', class_key: 'cloud_load_balancer', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
        { asset_id: BUCKET, display_name: 'orphan-bucket', class_key: 'object_storage', depth: 1, cloud_region: REGION },
      ],
      edges: [],
    }));
    const orphanRegion = cloudRegionNodeId('', REGION);
    expect(byId(g, orphanRegion)?.classLabel).toBe('Account not recorded');
    expect(hasEdge(g, orphanRegion, BUCKET)).toBe(true);
    // And it is NOT quietly folded into the neighbouring account's box, which
    // would state an ownership nothing recorded.
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), BUCKET)).toBe(false);
  });

  it('keeps two accounts sharing a region name apart', () => {
    const g = rooted(awsNeighbourhood({
      nodes: [
        { asset_id: LB, display_name: 'lb-a', class_key: 'cloud_load_balancer', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
        { asset_id: BUCKET, display_name: 'bucket-b', class_key: 'object_storage', depth: 1, cloud_account: OTHER_ACCOUNT, cloud_region: REGION },
      ],
      edges: [],
    }));
    expect(g.nodes.filter((n) => n.kind === 'cloud_region')).toHaveLength(2);
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), BUCKET)).toBe(false);
    expect(hasEdge(g, cloudRegionNodeId(OTHER_ACCOUNT, REGION), BUCKET)).toBe(true);
  });

  it('emits one box per scope however many assets sit in it', () => {
    const g = rooted();
    // us-east-1 and global.
    expect(g.nodes.filter((n) => n.kind === 'cloud_region')).toHaveLength(2);
  });

  it('is idempotent — re-rooting an already-rooted graph adds nothing', () => {
    const once = rooted();
    const twice = withCloudScopeRoots(once);
    expect(twice.nodes).toHaveLength(once.nodes.length);
    expect(twice.edges).toHaveLength(once.edges.length);
  });

  it('gives a scope node NO asset id', () => {
    // Everything that opens, focuses or exports a node reads `assetId`. A
    // synthetic uuid here would put a row that does not exist behind "Open
    // asset" and hand the export a join key onto nothing.
    for (const n of rooted().nodes.filter((node) => !isAssetNode(node))) {
      expect(n.assetId).toBeUndefined();
      expect(n.riskScore).toBeUndefined();
      expect(n.status).toBe('');
      expect(n.isRoot).toBe(false);
    }
  });

  it('places a scope box at the shallowest depth of what it groups', () => {
    const g = rooted();
    expect(byId(g, cloudRegionNodeId(ACCOUNT, REGION))?.depth).toBe(0);
    expect(byId(g, cloudRegionNodeId(ACCOUNT, 'global'))?.depth).toBe(3);
  });

  it('marks its edges synthetic and leaves the stored ones alone', () => {
    const g = rooted();
    const derived = g.edges.filter((e) => e.synthetic);
    const stored = g.edges.filter((e) => !e.synthetic);
    expect(derived.length).toBeGreaterThan(0);
    expect(stored.map((e) => e.id).sort()).toEqual(['e-keys-instance', 'e-lb-keys']);
    for (const e of derived) {
      // No observation history, because nothing observed it.
      expect(e.observationCount).toBe(0);
      expect(e.sourceKind).toBe('inferred');
      expect(e.status).toBe('active');
      expect(e.pending).toBe(false);
    }
  });

  it('labels the region sub-line with the account, or says nobody recorded one', () => {
    expect(cloudRegionSubLabel(ACCOUNT)).toBe(`Account ${ACCOUNT}`);
    expect(cloudRegionSubLabel('')).toBe('Account not recorded');
  });
});

describe('a scope node is not an asset, wherever the graph is counted', () => {
  it('assetNodeCount ignores the boxes', () => {
    const g = rooted();
    expect(g.nodes.length).toBe(7); // 5 assets + 2 regions
    expect(assetNodeCount(g)).toBe(5);
  });

  it('the truncation banner quotes assets, not boxes', () => {
    const g = rooted(awsNeighbourhood({ truncated: true, total_nodes: 40, total_edges: 60 }));
    const notice = truncationNotice(awsNeighbourhood({ truncated: true, total_nodes: 40, total_edges: 60 }), {
      nodes: assetNodeCount(g),
      edges: g.edges.reduce((n, e) => (e.synthetic ? n : n + 1), 0),
    });
    expect(notice?.text).toContain('Showing 5 of 40 assets');
    expect(notice?.text).toContain('2 of 60 relationships');
  });

  it('the legend lists the scope kinds separately from the class groups', () => {
    const entries = legendFor(rooted());
    const cloud = entries.find((e) => e.group === 'cloud_resource');
    // Five cloud resources, and the two boxes are NOT among them.
    expect(cloud?.count).toBe(5);
    expect(entries.find((e) => e.group === 'cloud_region')?.count).toBe(2);
    // Scaffolding is listed after the inventory.
    expect(entries.map((e) => e.group).slice(-1)).toEqual(['cloud_region']);
  });

  it('a lone cloud asset is still "no relationships yet"', () => {
    // The scope boxes are not relationships. Letting them decide would swap the
    // empty state — which says so and offers "Declare one" — for a graph of
    // three boxes that answers a different question.
    const g = rooted(awsNeighbourhood({
      root_asset_id: BUCKET,
      nodes: [{ asset_id: BUCKET, display_name: 'assets-bucket', class_key: 'object_storage', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION }],
      edges: [],
    }));
    expect(g.nodes).toHaveLength(2);
    expect(canvasState({ isLoading: false, isError: false }, g)).toBe('empty');
  });

  it('a cloud asset with a real relationship is still a graph', () => {
    // The other polarity: the check above must not swallow a genuine edge.
    expect(canvasState({ isLoading: false, isError: false }, rooted())).toBe('graph');
  });

  it('announces a scope box as scaffolding, never as an archived asset', () => {
    // `statusRing('')` is `muted`, whose help text reads "Archived, denied, or
    // otherwise not in service" — true of no region that has ever existed, and
    // in the one channel with no picture to contradict it.
    const region = byId(rooted(), cloudRegionNodeId(ACCOUNT, REGION))!;
    const label = nodeAriaLabel(region, null);
    expect(label).toContain('Cloud region');
    expect(label).toContain(REGION);
    expect(label).not.toContain('Archived');
  });
});

describe('ordering: cap the assets, THEN root them', () => {
  it('scope boxes cannot push an asset out of a capped graph', () => {
    const nbh = awsNeighbourhood({ node_cap: 5, edge_cap: 2000, truncated: true, total_nodes: 9 });
    const capped = capGraph(buildMapGraph(nbh), nbh.node_cap, nbh.edge_cap);
    const g = withCloudScopeRoots(capped);
    expect(assetNodeCount(g)).toBe(5);
    expect(g.nodes.length).toBeGreaterThan(5);
  });
});

describe('the exports describe the scope boxes honestly', () => {
  it('GraphML marks the node kind and writes no asset id for a box', () => {
    const xml = toGraphML(rooted());
    const regionId = cloudRegionNodeId(ACCOUNT, REGION);
    const start = xml.indexOf(`<node id="${regionId}">`);
    expect(start).toBeGreaterThan(-1);
    const block = xml.slice(start, xml.indexOf('</node>', start));
    expect(block).toContain('<data key="n_kind">cloud_region</data>');
    expect(block).not.toContain('n_asset_id');
  });

  it('Cytoscape marks a derived edge synthetic and a stored one not', () => {
    const els = toCytoscape(rooted());
    const stored = els.elements.edges.find((e) => e.data.id === 'e-lb-keys');
    const derived = els.elements.edges.find((e) => String(e.data.source).startsWith('scope:'));
    expect(stored?.data.synthetic).toBe('false');
    expect(derived?.data.synthetic).toBe('true');
  });

  it('every GraphML data key it writes is declared', () => {
    // The new keys are the easy ones to forget, and an undeclared key makes yEd
    // import the graph with no attributes at all rather than erroring.
    const xml = toGraphML(rooted());
    const declared = new Set([...xml.matchAll(/<key id="([^"]+)"/g)].map((m) => m[1]));
    const used = new Set([...xml.matchAll(/<data key="([^"]+)"/g)].map((m) => m[1]));
    expect(used.has('n_kind')).toBe(true);
    for (const key of used) expect(declared, `<data key="${key}"> is not declared`).toContain(key);
  });
});
