// The topology view's model (ADR-0006 D4 second half, workstream 3.8).
//
// The drill-through query is the load-bearing thing here: the tree is an INDEX
// into the asset list, and a link that opens a different set from the count it
// was clicked on looks perfectly fine until somebody counts the rows. Every
// assertion below is about that, or about a state the view must not flatten.
import { describe, expect, it } from 'vitest';
import { parse } from '@vistasecurity/primitives/query';
import {
  DEFAULT_MAP_VIEW, MAP_VIEWS, UNSEGMENTED_QUERY, classDrillThroughQuery, edgeSummary,
  readMapView, segmentDrillThroughQuery, segmentKey, topologyAssetsHref,
  topologyEdgeHeadline, topologyTruncationNotice, treeAssetTotal,
  type TopologyEdge, type TopologyPayload,
} from './topology-model';

const SEG = '2f1b9e7c-0000-4000-8000-000000000001';

describe('the view switch', () => {
  it('defaults to the neighbourhood, which is what ?lens=map has always meant', () => {
    // The other polarity of the feature: adding a second view must not change
    // where an existing bookmark lands.
    expect(readMapView(null)).toBe('neighbourhood');
    expect(DEFAULT_MAP_VIEW).toBe('neighbourhood');
  });

  it('reads the topology out of the URL, so the view is a link', () => {
    expect(readMapView('topology')).toBe('topology');
  });

  it('falls back rather than rendering nothing for a typo', () => {
    expect(readMapView('topolgy')).toBe('neighbourhood');
    expect(readMapView('')).toBe('neighbourhood');
  });

  it('offers exactly the two views ADR-0006 D4 names', () => {
    expect([...MAP_VIEWS]).toEqual(['neighbourhood', 'topology']);
  });
});

describe('the drill-through query', () => {
  it('scopes a class node to its segment AND its class', () => {
    const q = classDrillThroughQuery({ segment_id: SEG }, { class_key: 'server' });
    expect(q).toBe(`segment_id:${SEG} and class=server`);
  });

  it('matches the class EXACTLY, because that is what the node counted', () => {
    // `:` and `=` are different operators on a class (QUERY_LANGUAGE §5.3): `:`
    // matches the whole subtree by materialised path, `=` matches the class
    // itself. The topology groups by `class_key`, and plenty of classes are not
    // leaves — the classification rules assign `network_device` to anything
    // they cannot narrow, while switches and routers sit beneath it. Under the
    // subtree form a chip reading 4,167 opened a list of 12,500.
    const q = classDrillThroughQuery({ segment_id: SEG }, { class_key: 'network_device' });
    expect(q).toContain('class=network_device');
    expect(q).not.toContain('class:network_device');
  });

  it('spells the unsegmented bucket as an ABSENCE, not as a null value', () => {
    // The language has no null literal, deliberately (QUERY_LANGUAGE §1):
    // absence is `exists(field)` / `not exists(field)`, which keeps SQL's
    // `= NULL` trap off the surface. `segment_id:null` would parse as the
    // bareword "null" and match nothing.
    expect(UNSEGMENTED_QUERY).toBe('not exists(segment_id)');
    expect(classDrillThroughQuery({ segment_id: null }, { class_key: 'server' }))
      .toBe('not exists(segment_id) and class=server');
    expect(segmentDrillThroughQuery({ segment_id: null })).toBe('not exists(segment_id)');
  });

  it('produces queries the real parser accepts', () => {
    // The one check that matters and that a string comparison cannot make: the
    // link is only useful if the query language can read it. Driving the REAL
    // parser rather than asserting on the text is the difference between
    // pinning a format and pinning a behaviour.
    for (const q of [
      classDrillThroughQuery({ segment_id: SEG }, { class_key: 'server' }),
      classDrillThroughQuery({ segment_id: null }, { class_key: 'managed_database' }),
      segmentDrillThroughQuery({ segment_id: SEG }),
      segmentDrillThroughQuery({ segment_id: null }),
    ]) {
      const res = parse(q);
      expect(res.ok, `${q} did not parse: ${JSON.stringify(res.ok ? null : res.errors)}`).toBe(true);
    }
  });

  it('quotes with the query language rule, not JSON', () => {
    // A tenant subclass key is free text. The two quoting rules agree on
    // backslash and double quote and disagree on everything else, so using the
    // wrong one produces a query the validator rejects.
    const q = classDrillThroughQuery({ segment_id: null }, { class_key: 'my class' });
    expect(q).toContain('class="my class"');
    expect(parse(q).ok).toBe(true);
  });

  it('lands on the asset list, encoded once', () => {
    const href = topologyAssetsHref(classDrillThroughQuery({ segment_id: SEG }, { class_key: 'server' }));
    expect(href.startsWith('/inventory?lens=assets&query=')).toBe(true);
    const decoded = decodeURIComponent(new URL(href, 'https://x').searchParams.get('query')!);
    expect(decoded).toBe(`segment_id:${SEG} and class=server`);
  });
});

describe('the expansion key', () => {
  it('keys on the segment ID, so a segment NAMED "Unsegmented" is its own row', () => {
    // Nothing stops a tenant naming a segment "Unsegmented": the column is free
    // text. Keying on the name would make expanding one expand the other.
    const real = segmentKey('DC-East', { segment_id: SEG });
    const bucket = segmentKey('DC-East', { segment_id: null });
    expect(real).not.toBe(bucket);
  });

  it('separates by SITE, so the same segment under two sites expands independently', () => {
    expect(segmentKey('DC-East', { segment_id: null }))
      .not.toBe(segmentKey('DC-West', { segment_id: null }));
  });
});

describe('truncation', () => {
  const base: TopologyPayload = {
    sites: [{ site: 'DC-East', asset_count: 3, segments: [
      { segment_id: SEG, segment_name: 'Core', asset_count: 3, classes: [
        { class_key: 'server', class_path: 'hardware.computer.server', asset_count: 3 },
      ] },
    ] }],
    edges: [],
    total_assets: 3, unassigned_assets: 0,
    total_nodes: 1, total_edges: 0, truncated: false, node_cap: 2000, edge_cap: 500,
  };

  it('says nothing when nothing was cut', () => {
    expect(topologyTruncationNotice(base)).toBeNull();
    expect(topologyTruncationNotice(undefined)).toBeNull();
  });

  it('says what was cut, with the real totals', () => {
    // A capped answer that looked complete is the failure the caps are written
    // against: a diagram that looks whole and is not is worse than no diagram.
    const notice = topologyTruncationNotice({ ...base, truncated: true, total_nodes: 4_012, total_edges: 900 });
    expect(notice).toContain('1 of 4,012 groups');
    expect(notice).toContain('0 of 900 connection summaries');
  });
});

describe('the cross-segment-link headline', () => {
  // The headline read `edges.length` — how many links were DRAWN — and printed
  // it as the estate's total. The two are the same number only until an estate
  // is big enough to truncate, at which point a tenant with 900 cross-segment
  // links saw "200" in 24-point type. The number a headline states is the one a
  // reader believes, so it has to be the one the server counted.
  const edge = (i: number): TopologyEdge => ({
    from_segment_id: `a-${i}`, from_segment_name: `A${i}`,
    to_segment_id: `b-${i}`, to_segment_name: `B${i}`,
    count: 1, by_type: { connects_to: 1 },
  });

  const t = (over: Partial<TopologyPayload>): TopologyPayload => ({
    sites: [], edges: [], total_assets: 0, unassigned_assets: 0,
    total_nodes: 0, total_edges: 0, truncated: false, node_cap: 2000, edge_cap: 500,
    ...over,
  });

  it('reads total_edges, not the number drawn', () => {
    const h = topologyEdgeHeadline(t({ edges: [edge(1), edge(2)], total_edges: 900, truncated: true }));
    expect(h.count).toBe(900);
    expect(h.partial).toBe(true);
  });

  it('is not partial when everything was drawn, even on a truncated topology', () => {
    // `truncated` can be set because the NODE cap bit while every edge fitted.
    // Qualifying the edge headline then would tell the reader the number is a
    // floor when it is exact — the same dishonesty pointed the other way.
    const h = topologyEdgeHeadline(t({ edges: [edge(1), edge(2)], total_edges: 2, truncated: true }));
    expect(h.count).toBe(2);
    expect(h.partial).toBe(false);
  });

  it('singularises on exactly one', () => {
    expect(topologyEdgeHeadline(t({ edges: [edge(1)], total_edges: 1 })).label).toBe('cross-segment link');
    expect(topologyEdgeHeadline(t({ total_edges: 0 })).label).toBe('cross-segment links');
    expect(topologyEdgeHeadline(t({ edges: [edge(1), edge(2)], total_edges: 2 })).label).toBe('cross-segment links');
  });

  it('answers zero rather than throwing with no payload', () => {
    expect(topologyEdgeHeadline(undefined)).toEqual({
      count: 0, label: 'cross-segment links', partial: false,
    });
  });
});

describe('the tree total', () => {
  it('sums the sites, so it can be compared with the independent count', () => {
    // The server counts total_assets separately from the grouping. Summing the
    // tree here makes the disagreement visible instead of letting the view draw
    // a tidy picture of a subset.
    expect(treeAssetTotal({
      sites: [
        { site: 'A', asset_count: 4, segments: [] },
        { site: 'B', asset_count: 6, segments: [] },
      ],
      edges: [], total_assets: 10, unassigned_assets: 0,
      total_nodes: 0, total_edges: 0, truncated: false, node_cap: 1, edge_cap: 1,
    })).toBe(10);
  });

  it('is 0 for no data, not NaN', () => {
    expect(treeAssetTotal(undefined)).toBe(0);
  });
});

describe('the edge summary', () => {
  it('names each relationship type rather than one blended number', () => {
    // `connects_to` (observed traffic) and `depends_on` (a declared dependency)
    // are different claims. A single "9 connections" would hide which.
    expect(edgeSummary({
      from_segment_name: 'Core', to_segment_name: 'DMZ', count: 9,
      by_type: { connects_to: 7, depends_on: 2 },
    })).toBe('7 connections · 2 dependencies');
  });

  it('singularises', () => {
    expect(edgeSummary({
      from_segment_name: 'Core', to_segment_name: 'DMZ', count: 1,
      by_type: { depends_on: 1 },
    })).toBe('1 dependency');
  });

  it('reads stably rather than in map-iteration order', () => {
    const a = edgeSummary({ from_segment_name: 'a', to_segment_name: 'b', count: 3, by_type: { depends_on: 1, connects_to: 2 } });
    const b = edgeSummary({ from_segment_name: 'a', to_segment_name: 'b', count: 3, by_type: { connects_to: 2, depends_on: 1 } });
    expect(a).toBe(b);
  });

  it('falls back to the total for a type it has no word for', () => {
    // A relationship type added to the registry after this build must not
    // render as "undefined".
    expect(edgeSummary({
      from_segment_name: 'a', to_segment_name: 'b', count: 2, by_type: { member_of: 2 },
    })).toBe('2 member ofs');
  });
});
