// GraphML and Cytoscape-JSON serialisers (workstream 2.9).
//
// Golden fixtures, because the failure mode of an exporter is not an exception
// — it is a file that downloads fine and then will not open, or opens with the
// attributes missing. Neither shows up anywhere in the app.
//
// The escaping cases are not decoration: display names come from discovery and
// from spreadsheet imports, so `O'Brien's laptop` and `<probe> & "test"` are
// both things a real inventory contains, and either one unescaped produces a
// GraphML file that yEd rejects with a parse error the user cannot act on.
import { describe, expect, it } from 'vitest';
import {
  closesOnKey, closesOnOutsidePointer,
  mapExportFilename, toCytoscape, toCytoscapeJSON, toGraphML, xmlEscape,
} from './map-export';
import type { MapEdge, MapGraph, MapNode } from './map-model';

const node = (over: Partial<MapNode> & Pick<MapNode, 'id'>): MapNode => ({
  kind: 'asset',
  assetId: over.id,
  label: over.id,
  classKey: 'server',
  classLabel: 'Server',
  group: 'hardware',
  status: 'monitoring',
  depth: 1,
  isRoot: false,
  ...over,
});

const edge = (over: Partial<MapEdge> & Pick<MapEdge, 'id' | 'source' | 'target'>): MapEdge => ({
  type: 'runs_on',
  label: 'runs on',
  status: 'active',
  pending: false,
  sourceKind: 'measured',
  confidence: 0.9,
  firstSeenAt: '2026-01-01T00:00:00Z',
  lastSeenAt: '2026-09-01T00:00:00Z',
  observationCount: 4,
  synthetic: false,
  ...over,
});

const GRAPH: MapGraph = {
  rootId: 'root-1',
  nodes: [
    node({ id: 'root-1', label: 'app-01', classKey: 'web_application', classLabel: 'Web application', group: 'application', depth: 0, isRoot: true, riskScore: 72 }),
    node({ id: 'host-1', label: 'host-01' }),
  ],
  edges: [edge({ id: 'edge-1', source: 'root-1', target: 'host-1' })],
};

describe('xmlEscape', () => {
  it('escapes all five, the apostrophe included', () => {
    // An apostrophe inside a single-quoted attribute is the one people forget,
    // and `O'Brien's laptop` is an ordinary hostname.
    expect(xmlEscape(`<probe> & "quoted" 'apostrophe'`))
      .toBe('&lt;probe&gt; &amp; &quot;quoted&quot; &apos;apostrophe&apos;');
  });

  it('escapes the ampersand FIRST, so an escape is not re-escaped', () => {
    // `&` → `&amp;` then `<` → `&lt;` is correct; the other order turns
    // `&lt;` into `&amp;lt;`.
    expect(xmlEscape('a<b')).toBe('a&lt;b');
    expect(xmlEscape('&amp;')).toBe('&amp;amp;');
  });

  it('renders absent values as empty rather than "undefined"', () => {
    expect(xmlEscape(undefined)).toBe('');
    expect(xmlEscape(null)).toBe('');
    // ...but a real 0 is a value, not an absence.
    expect(xmlEscape(0)).toBe('0');
  });
});

describe('toGraphML', () => {
  it('matches the golden document', () => {
    expect(toGraphML(GRAPH)).toBe(
`<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
  <key id="n_label" for="node" attr.name="label" attr.type="string"/>
  <key id="n_kind" for="node" attr.name="node_kind" attr.type="string"/>
  <key id="n_asset_id" for="node" attr.name="asset_id" attr.type="string"/>
  <key id="n_class_key" for="node" attr.name="class_key" attr.type="string"/>
  <key id="n_class_group" for="node" attr.name="class_group" attr.type="string"/>
  <key id="n_status" for="node" attr.name="asset_status" attr.type="string"/>
  <key id="n_depth" for="node" attr.name="depth" attr.type="int"/>
  <key id="n_is_root" for="node" attr.name="is_root" attr.type="string"/>
  <key id="n_risk" for="node" attr.name="risk_score" attr.type="double"/>
  <key id="e_label" for="edge" attr.name="label" attr.type="string"/>
  <key id="e_type" for="edge" attr.name="type" attr.type="string"/>
  <key id="e_status" for="edge" attr.name="status" attr.type="string"/>
  <key id="e_source_kind" for="edge" attr.name="source_kind" attr.type="string"/>
  <key id="e_synthetic" for="edge" attr.name="synthetic" attr.type="string"/>
  <key id="e_confidence" for="edge" attr.name="confidence" attr.type="double"/>
  <key id="e_first_seen" for="edge" attr.name="first_seen_at" attr.type="string"/>
  <key id="e_last_seen" for="edge" attr.name="last_seen_at" attr.type="string"/>
  <key id="e_observations" for="edge" attr.name="observation_count" attr.type="int"/>
  <graph id="neighbourhood" edgedefault="directed">
    <node id="root-1">
      <data key="n_label">app-01</data>
      <data key="n_kind">asset</data>
      <data key="n_asset_id">root-1</data>
      <data key="n_class_key">web_application</data>
      <data key="n_class_group">application</data>
      <data key="n_status">monitoring</data>
      <data key="n_depth">0</data>
      <data key="n_is_root">true</data>
      <data key="n_risk">72</data>
    </node>
    <node id="host-1">
      <data key="n_label">host-01</data>
      <data key="n_kind">asset</data>
      <data key="n_asset_id">host-1</data>
      <data key="n_class_key">server</data>
      <data key="n_class_group">hardware</data>
      <data key="n_status">monitoring</data>
      <data key="n_depth">1</data>
      <data key="n_is_root">false</data>
    </node>
    <edge id="edge-1" source="root-1" target="host-1">
      <data key="e_label">runs on</data>
      <data key="e_type">runs_on</data>
      <data key="e_status">active</data>
      <data key="e_source_kind">measured</data>
      <data key="e_synthetic">false</data>
      <data key="e_confidence">0.9</data>
      <data key="e_first_seen">2026-01-01T00:00:00Z</data>
      <data key="e_last_seen">2026-09-01T00:00:00Z</data>
      <data key="e_observations">4</data>
    </edge>
  </graph>
</graphml>
`,
    );
  });

  it('declares every key it uses — an undeclared key imports as no attributes', () => {
    const xml = toGraphML(GRAPH);
    const declared = new Set([...xml.matchAll(/<key id="([^"]+)"/g)].map((m) => m[1]));
    const used = new Set([...xml.matchAll(/<data key="([^"]+)"/g)].map((m) => m[1]));
    expect(used.size).toBeGreaterThan(0);
    for (const key of used) expect(declared, `<data key="${key}"> is not declared`).toContain(key);
  });

  it('escapes labels and ids in both text and attribute position', () => {
    const nasty = toGraphML({
      rootId: `a<&"'`,
      nodes: [node({ id: `a<&"'`, label: `O'Brien's <laptop> & "spare"`, isRoot: true })],
      edges: [],
    });
    expect(nasty).toContain(`<node id="a&lt;&amp;&quot;&apos;">`);
    expect(nasty).toContain('<data key="n_label">O&apos;Brien&apos;s &lt;laptop&gt; &amp; &quot;spare&quot;</data>');
    // Nothing raw survived.
    expect(nasty).not.toMatch(/<laptop>/);
  });

  it('is directed — a relationship that lost its direction lost its meaning', () => {
    // `runs_on` reversed is a different and wrong statement about the estate.
    expect(toGraphML(GRAPH)).toContain('edgedefault="directed"');
  });

  it('omits an absent optional rather than writing an empty element', () => {
    // The second node has no risk score; a `<data key="n_risk"></data>` would
    // import as the number zero, which here would read as "not risky" when the
    // truth is "not assessed".
    const xml = toGraphML(GRAPH);
    const hostBlock = xml.slice(xml.indexOf('<node id="host-1">'), xml.indexOf('</node>', xml.indexOf('<node id="host-1">')));
    expect(hostBlock).not.toContain('n_risk');
  });

  it('produces a well-formed document for an empty graph', () => {
    const xml = toGraphML({ rootId: '', nodes: [], edges: [] });
    expect(xml).toContain('<graph id="neighbourhood" edgedefault="directed">');
    expect(xml).toContain('</graph>');
    expect(xml.trimEnd().endsWith('</graphml>')).toBe(true);
  });
});

describe('toCytoscape', () => {
  it('matches the golden object', () => {
    expect(toCytoscape(GRAPH)).toEqual({
      elements: {
        nodes: [
          {
            data: {
              id: 'root-1', label: 'app-01', node_kind: 'asset', asset_id: 'root-1',
              class_key: 'web_application',
              class_group: 'application', asset_status: 'monitoring', depth: 0,
              is_root: 'true', risk_score: 72,
            },
          },
          {
            data: {
              id: 'host-1', label: 'host-01', node_kind: 'asset', asset_id: 'host-1',
              class_key: 'server',
              class_group: 'hardware', asset_status: 'monitoring', depth: 1,
              is_root: 'false',
            },
          },
        ],
        edges: [
          {
            data: {
              id: 'edge-1', source: 'root-1', target: 'host-1', label: 'runs on',
              type: 'runs_on', status: 'active', source_kind: 'measured',
              synthetic: 'false', confidence: 0.9, first_seen_at: '2026-01-01T00:00:00Z',
              last_seen_at: '2026-09-01T00:00:00Z', observation_count: 4,
            },
          },
        ],
      },
    });
  });

  it('needs no escaping — JSON.stringify owns that', () => {
    const json = toCytoscapeJSON({
      rootId: 'r',
      nodes: [node({ id: 'r', label: `O'Brien's <laptop> & "spare"`, isRoot: true })],
      edges: [],
    });
    // It round-trips to the original string, which is the whole point.
    const parsed = JSON.parse(json) as ReturnType<typeof toCytoscape>;
    expect(parsed.elements.nodes[0].data.label).toBe(`O'Brien's <laptop> & "spare"`);
  });

  it('describes the SAME graph as the GraphML — same nodes, same edges', () => {
    // Two exporters that disagree is the bug this pins: a customer comparing a
    // Visio import against a Cytoscape one must not find different estates.
    const cy = toCytoscape(GRAPH);
    const xml = toGraphML(GRAPH);
    for (const n of cy.elements.nodes) expect(xml).toContain(`<node id="${n.data.id as string}">`);
    for (const e of cy.elements.edges) expect(xml).toContain(`<edge id="${e.data.id as string}"`);
    expect(cy.elements.nodes).toHaveLength(GRAPH.nodes.length);
    expect(cy.elements.edges).toHaveLength(GRAPH.edges.length);
  });

  it('is valid JSON with an empty graph', () => {
    expect(JSON.parse(toCytoscapeJSON({ rootId: '', nodes: [], edges: [] })))
      .toEqual({ elements: { nodes: [], edges: [] } });
  });
});

describe('mapExportFilename', () => {
  it('slugifies the focus asset and stamps the date', () => {
    expect(mapExportFilename('app-01.prod.example.com', 'graphml'))
      .toMatch(/^vista-map-app-01-prod-example-com-\d{4}-\d{2}-\d{2}\.graphml$/);
    expect(mapExportFilename('DB Cluster #2', 'json'))
      .toMatch(/^vista-map-db-cluster-2-\d{4}-\d{2}-\d{2}\.json$/);
  });

  it('never produces a name that is just the stamp', () => {
    // A label made entirely of punctuation slugs to '' and would give
    // `vista-map--.graphml`.
    expect(mapExportFilename('!!!', 'graphml')).toMatch(/^vista-map-asset-\d{4}-\d{2}-\d{2}\.graphml$/);
    expect(mapExportFilename('', 'graphml')).toMatch(/^vista-map-asset-/);
  });

  it('bounds the length, so a long display name cannot make an unusable filename', () => {
    const name = mapExportFilename('x'.repeat(300), 'json');
    expect(name.length).toBeLessThan(90);
  });
});


// --- the menu's dismissal rules --------------------------------------------
//
// The export menu closed on `mouseleave` and nothing else. A keyboard user
// could open it and had no way to close it; a pointer user who clicked the
// canvas left it hanging over the part of the map they had just clicked; and on
// a touch device, where there is no mouseleave at all, it never closed.
//
// Both polarities matter. A dismissal that fires on EVERYTHING is as broken as
// one that fires on nothing — it would close the menu on the very click that
// chose an item, before the item's own handler ran.

describe('closesOnKey', () => {
  it('dismisses on Escape, under either spelling', () => {
    // `Esc` is what older browsers and most synthetic events send. Handling
    // only `Escape` is a dismissal that half works, which nobody notices until
    // a keyboard user reports it.
    expect(closesOnKey('Escape')).toBe(true);
    expect(closesOnKey('Esc')).toBe(true);
  });

  it('ignores every other key', () => {
    for (const k of ['Enter', 'Tab', ' ', 'ArrowDown', 'e', 'Shift']) {
      expect(closesOnKey(k)).toBe(false);
    }
  });
});

describe('closesOnOutsidePointer', () => {
  /** A stand-in for a DOM node, so the rule is testable with no document. */
  const holding = (...members: unknown[]) => ({ contains: (n: unknown) => members.includes(n) });

  const menuItem = Symbol('menu item');
  const button = Symbol('the Export button');
  const canvas = Symbol('the graph canvas');

  it('dismisses on a click anywhere else', () => {
    expect(closesOnOutsidePointer(canvas, holding(menuItem), holding(button))).toBe(true);
  });

  it('does NOT dismiss on a click inside the menu', () => {
    // Otherwise choosing an export closes the menu on mousedown and the item's
    // own click handler never runs — the menu would look like it did nothing.
    expect(closesOnOutsidePointer(menuItem, holding(menuItem), holding(button))).toBe(false);
  });

  it('does NOT dismiss on a click on the button that opened it', () => {
    // The button already toggles. Treating it as outside would close here and
    // reopen there, so the button would appear not to work.
    expect(closesOnOutsidePointer(button, holding(menuItem), holding(button))).toBe(false);
  });

  it('is inert when nothing is mounted', () => {
    // A closed menu must not answer "dismiss" to every click on the page.
    expect(closesOnOutsidePointer(canvas, null, null)).toBe(false);
  });

  it('still protects the button when the menu ref has not attached yet', () => {
    expect(closesOnOutsidePointer(button, null, holding(button))).toBe(false);
    expect(closesOnOutsidePointer(canvas, null, holding(button))).toBe(true);
  });
});
