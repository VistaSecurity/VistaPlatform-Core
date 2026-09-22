// Cloud account and region as map grouping nodes ( slice D).
//
// The thing this closes: an AWS discovery produced a correct containment
// hierarchy — VPC contains subnet contains instance — and nothing above it, so
// the two VPCs floated unrooted and the buckets and the CDN distribution, which
// live outside a VPC entirely, had no edges at all. A user could ask "what is
// in this VPC" and could not ask "what is in this account".
//
// Account and region are SCOPING ATTRIBUTES, not asset classes (owner decision
// D6). They carry no crypto posture, so there is no asset row behind them —
// which is exactly what makes them easy to get wrong here. Everything below is
// one of three failure shapes:
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
  assetNodeCount, buildMapGraph, canvasState, capGraph, cloudAccountNodeId,
  cloudRegionNodeId, cloudRegionSubLabel, isAssetNode, legendFor, nodeAriaLabel,
  truncationNotice, withCloudScopeRoots, type MapGraph, type MapNode,
} from './map-model';
import { toCytoscape, toGraphML } from './map-export';

const ACCOUNT = '123456789012';
const OTHER_ACCOUNT = '210987654321';
const REGION = 'us-east-1';

const VPC = 'aaaaaaaa-0000-4000-8000-000000000001';
const SUBNET = 'aaaaaaaa-0000-4000-8000-000000000002';
const INSTANCE = 'aaaaaaaa-0000-4000-8000-000000000003';
const BUCKET = 'aaaaaaaa-0000-4000-8000-000000000004';
const CDN = 'aaaaaaaa-0000-4000-8000-000000000005';
const PRINTER = 'aaaaaaaa-0000-4000-8000-000000000006';

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

/** The shape the demo host's first AWS discovery actually produced: a VPC that
 *  contains a subnet that contains an instance, plus a bucket and a CDN
 *  distribution with no containment at all. */
function awsNeighbourhood(over: Partial<Neighbourhood> = {}): Neighbourhood {
  return {
    root_asset_id: VPC,
    depth: 3,
    include_pending: false,
    nodes: [
      { asset_id: VPC, display_name: 'vpc-prod', class_key: 'virtual_network', asset_status: 'monitoring', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
      { asset_id: SUBNET, display_name: 'subnet-a', class_key: 'subnet', asset_status: 'monitoring', depth: 1, cloud_account: ACCOUNT, cloud_region: REGION },
      { asset_id: INSTANCE, display_name: 'web-01', class_key: 'compute_instance', asset_status: 'monitoring', depth: 2, cloud_account: ACCOUNT, cloud_region: REGION },
      { asset_id: BUCKET, display_name: 'assets-bucket', class_key: 'object_storage', asset_status: 'monitoring', depth: 3, cloud_account: ACCOUNT, cloud_region: REGION },
      { asset_id: CDN, display_name: 'd123.cloudfront.net', class_key: 'cdn_distribution', asset_status: 'monitoring', depth: 3, cloud_account: ACCOUNT, cloud_region: 'global' },
    ],
    edges: [
      edge({ id: 'e-vpc-subnet', from_asset_id: VPC, to_asset_id: SUBNET }),
      edge({ id: 'e-subnet-instance', from_asset_id: SUBNET, to_asset_id: INSTANCE }),
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
    expect(byId(g, VPC)?.cloudAccount).toBe(ACCOUNT);
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
  it('roots the hierarchy: account → region → VPC → subnet → instance', () => {
    const g = rooted();
    const accountId = cloudAccountNodeId(ACCOUNT);
    const regionId = cloudRegionNodeId(ACCOUNT, REGION);

    expect(byId(g, accountId)?.kind).toBe('cloud_account');
    expect(byId(g, regionId)?.kind).toBe('cloud_region');
    expect(hasEdge(g, accountId, regionId)).toBe(true);
    expect(hasEdge(g, regionId, VPC)).toBe(true);
    // The stored half of the chain is untouched.
    expect(hasEdge(g, VPC, SUBNET)).toBe(true);
    expect(hasEdge(g, SUBNET, INSTANCE)).toBe(true);
  });

  it('hangs a bucket and a CDN distribution off their region rather than leaving them isolated', () => {
    const g = rooted();
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), BUCKET)).toBe(true);
    // `global` is the distribution's real answer, not a stand-in for unknown,
    // so it gets its own box under the same account.
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, 'global'), CDN)).toBe(true);
    expect(hasEdge(g, cloudAccountNodeId(ACCOUNT), cloudRegionNodeId(ACCOUNT, 'global'))).toBe(true);
  });

  it('does NOT also hang a contained asset off its region', () => {
    // The subnet is inside the VPC and the instance inside the subnet. Adding a
    // region → subnet edge would draw the same containment twice and flatten
    // the hierarchy into a bush.
    const g = rooted();
    const regionId = cloudRegionNodeId(ACCOUNT, REGION);
    expect(hasEdge(g, regionId, SUBNET)).toBe(false);
    expect(hasEdge(g, regionId, INSTANCE)).toBe(false);
  });

  it('DOES attach an asset whose container fell outside the depth window', () => {
    // On this map the subnet really is a root: its VPC is not drawn. Leaving it
    // unattached would reproduce the bug this slice exists to fix, one level
    // down.
    const g = rooted(awsNeighbourhood({
      root_asset_id: SUBNET,
      nodes: [
        { asset_id: SUBNET, display_name: 'subnet-a', class_key: 'subnet', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
        { asset_id: INSTANCE, display_name: 'web-01', class_key: 'compute_instance', depth: 1, cloud_account: ACCOUNT, cloud_region: REGION },
      ],
      edges: [edge({ id: 'e-subnet-instance', from_asset_id: SUBNET, to_asset_id: INSTANCE })],
    }));
    expect(hasEdge(g, cloudRegionNodeId(ACCOUNT, REGION), SUBNET)).toBe(true);
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

  it('keeps a region-less cloud asset ON the map, attached to its account', () => {
    // The other polarity of the rule above: absent must not mean deleted
    // either. An asset that knows its account and not its region hangs off the
    // account directly.
    const g = rooted(awsNeighbourhood({
      root_asset_id: BUCKET,
      nodes: [{ asset_id: BUCKET, display_name: 'assets-bucket', class_key: 'object_storage', depth: 0, is_root: true, cloud_account: ACCOUNT }],
      edges: [],
    }));
    expect(byId(g, BUCKET)).toBeDefined();
    expect(hasEdge(g, cloudAccountNodeId(ACCOUNT), BUCKET)).toBe(true);
    expect(g.nodes.filter((n) => n.kind === 'cloud_region')).toHaveLength(0);
  });

  it('gives an account-less asset its own region box, labelled as such', () => {
    const g = rooted(awsNeighbourhood({
      nodes: [
        { asset_id: VPC, display_name: 'vpc-prod', class_key: 'virtual_network', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
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
    expect(hasEdge(g, cloudAccountNodeId(ACCOUNT), orphanRegion)).toBe(false);
  });

  it('keeps two accounts sharing a region name apart', () => {
    const g = rooted(awsNeighbourhood({
      nodes: [
        { asset_id: VPC, display_name: 'vpc-a', class_key: 'virtual_network', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
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
    expect(g.nodes.filter((n) => n.kind === 'cloud_account')).toHaveLength(1);
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
    expect(byId(g, cloudAccountNodeId(ACCOUNT))?.depth).toBe(0);
    expect(byId(g, cloudRegionNodeId(ACCOUNT, 'global'))?.depth).toBe(3);
  });

  it('marks its edges synthetic and leaves the stored ones alone', () => {
    const g = rooted();
    const derived = g.edges.filter((e) => e.synthetic);
    const stored = g.edges.filter((e) => !e.synthetic);
    expect(derived.length).toBeGreaterThan(0);
    expect(stored.map((e) => e.id).sort()).toEqual(['e-subnet-instance', 'e-vpc-subnet']);
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
    expect(g.nodes.length).toBe(8); // 5 assets + 1 account + 2 regions
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
    // Five cloud resources, and the three boxes are NOT among them.
    expect(cloud?.count).toBe(5);
    expect(entries.find((e) => e.group === 'cloud_account')?.count).toBe(1);
    expect(entries.find((e) => e.group === 'cloud_region')?.count).toBe(2);
    // Scaffolding is listed after the inventory.
    expect(entries.map((e) => e.group).slice(-2)).toEqual(['cloud_account', 'cloud_region']);
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
    expect(g.nodes).toHaveLength(3);
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
    const stored = els.elements.edges.find((e) => e.data.id === 'e-vpc-subnet');
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
