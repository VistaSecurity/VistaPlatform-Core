// GraphML and Cytoscape-JSON export of the map (ADR-0006 D4, workstream 2.9).
//
// Client-side, from the graph already on screen — the same page-local export
// pattern as the Inventory lens's CSV, and the same caveat applies twice over:
//
//   THESE ARE CONVENIENCE, NOT EVIDENCE.
//
// A file written from loaded data carries no provenance, no content hash and no
// statement of what predicate selected it, and it is a PREFIX of the real
// neighbourhood whenever the graph was truncated. For audit-grade output with
// a hash and a scope, the answer is a CBOM artifact, and `docsv4/core/features/
// map.md` says so where a user will read it. What these files are good for is
// the thing customers actually ask for: taking a picture of a neighbourhood
// into Visio, yEd, Gephi or Cytoscape.
//
// Pure functions, so the serialisers are pinned against golden fixtures rather
// than eyeballed in a downloaded file.
import type { MapEdge, MapGraph, MapNode } from './map-model';

/** Escape for XML TEXT and ATTRIBUTE content.
 *
 *  All five, including the apostrophe: display names come from discovery and
 *  from a spreadsheet import, so `O'Brien's laptop` and `<probe>` are both
 *  things a real inventory contains, and either one unescaped produces a file
 *  the importing tool rejects with a parse error the user cannot act on. */
export function xmlEscape(value: string | number | boolean | null | undefined): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** The node attributes both formats carry, in one place so the two exports
 *  cannot describe different graphs. */
function nodeFields(n: MapNode, rootId: string): Record<string, string | number> {
  return {
    label: n.label,
    // `node_kind` is what tells the importing tool which boxes are assets. A
    // grouping node carries NO `asset_id` — there is no asset — and a file that
    // said otherwise would let a downstream tool join a region onto an
    // inventory row that does not exist.
    node_kind: n.kind,
    ...(n.assetId === undefined ? {} : { asset_id: n.assetId }),
    class_key: n.classKey,
    class_group: n.group,
    asset_status: n.status,
    depth: n.depth,
    is_root: n.id === rootId ? 'true' : 'false',
    ...(n.riskScore === undefined ? {} : { risk_score: n.riskScore }),
  };
}

function edgeFields(e: MapEdge): Record<string, string | number> {
  return {
    label: e.label,
    type: e.type,
    status: e.status,
    source_kind: e.sourceKind,
    // Derived rather than stored. Exported explicitly so a graph opened in yEd
    // six months from now still distinguishes a relationship a collector
    // observed from a line this client drew out of an asset's recorded region.
    synthetic: e.synthetic ? 'true' : 'false',
    confidence: e.confidence,
    first_seen_at: e.firstSeenAt,
    last_seen_at: e.lastSeenAt,
    observation_count: e.observationCount,
  };
}

// GraphML requires every data key to be DECLARED before use, with its type.
// Declaring them once here (rather than per node) is what makes the file open
// in yEd and Gephi instead of importing as a graph with no attributes.
const NODE_KEYS: { id: string; name: string; type: 'string' | 'int' | 'double' }[] = [
  { id: 'n_label', name: 'label', type: 'string' },
  { id: 'n_kind', name: 'node_kind', type: 'string' },
  { id: 'n_asset_id', name: 'asset_id', type: 'string' },
  { id: 'n_class_key', name: 'class_key', type: 'string' },
  { id: 'n_class_group', name: 'class_group', type: 'string' },
  { id: 'n_status', name: 'asset_status', type: 'string' },
  { id: 'n_depth', name: 'depth', type: 'int' },
  { id: 'n_is_root', name: 'is_root', type: 'string' },
  { id: 'n_risk', name: 'risk_score', type: 'double' },
];

const EDGE_KEYS: { id: string; name: string; type: 'string' | 'int' | 'double' }[] = [
  { id: 'e_label', name: 'label', type: 'string' },
  { id: 'e_type', name: 'type', type: 'string' },
  { id: 'e_status', name: 'status', type: 'string' },
  { id: 'e_source_kind', name: 'source_kind', type: 'string' },
  { id: 'e_synthetic', name: 'synthetic', type: 'string' },
  { id: 'e_confidence', name: 'confidence', type: 'double' },
  { id: 'e_first_seen', name: 'first_seen_at', type: 'string' },
  { id: 'e_last_seen', name: 'last_seen_at', type: 'string' },
  { id: 'e_observations', name: 'observation_count', type: 'int' },
];

/**
 * GraphML 1.0 — the interchange format Visio, yEd and Gephi read.
 *
 * `edgedefault="directed"` because every relationship in ADR-0003 is stored in
 * a canonical direction and an undirected export would lose which end runs on
 * which.
 */
export function toGraphML(graph: MapGraph): string {
  const lines: string[] = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"'
      + ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
      + ' xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns'
      + ' http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
  ];
  for (const k of NODE_KEYS) {
    lines.push(`  <key id="${k.id}" for="node" attr.name="${k.name}" attr.type="${k.type}"/>`);
  }
  for (const k of EDGE_KEYS) {
    lines.push(`  <key id="${k.id}" for="edge" attr.name="${k.name}" attr.type="${k.type}"/>`);
  }
  lines.push('  <graph id="neighbourhood" edgedefault="directed">');

  for (const n of graph.nodes) {
    const fields = nodeFields(n, graph.rootId);
    lines.push(`    <node id="${xmlEscape(n.id)}">`);
    for (const k of NODE_KEYS) {
      const v = fields[k.name];
      if (v === undefined || v === '') continue;
      lines.push(`      <data key="${k.id}">${xmlEscape(v)}</data>`);
    }
    lines.push('    </node>');
  }

  for (const e of graph.edges) {
    const fields = edgeFields(e);
    lines.push(
      `    <edge id="${xmlEscape(e.id)}" source="${xmlEscape(e.source)}" target="${xmlEscape(e.target)}">`,
    );
    for (const k of EDGE_KEYS) {
      const v = fields[k.name];
      if (v === undefined || v === '') continue;
      lines.push(`      <data key="${k.id}">${xmlEscape(v)}</data>`);
    }
    lines.push('    </edge>');
  }

  lines.push('  </graph>', '</graphml>', '');
  return lines.join('\n');
}

export interface CytoscapeElements {
  elements: {
    nodes: { data: Record<string, unknown> }[];
    edges: { data: Record<string, unknown> }[];
  };
}

/**
 * Cytoscape.js JSON — `{ elements: { nodes, edges } }`, each element a `data`
 * bag keyed by `id` (and `source`/`target` on edges). That is the shape
 * `cy.add()` takes directly, so the file is loadable without a transform step.
 */
export function toCytoscape(graph: MapGraph): CytoscapeElements {
  return {
    elements: {
      nodes: graph.nodes.map((n) => ({ data: { id: n.id, ...nodeFields(n, graph.rootId) } })),
      edges: graph.edges.map((e) => ({
        data: { id: e.id, source: e.source, target: e.target, ...edgeFields(e) },
      })),
    },
  };
}

export const toCytoscapeJSON = (graph: MapGraph): string => JSON.stringify(toCytoscape(graph), null, 2);

/** A filename stamped with the date, matching the CSV exports' convention. */
export function mapExportFilename(rootLabel: string, ext: 'graphml' | 'json'): string {
  const stamp = new Date().toISOString().slice(0, 10);
  const slug = rootLabel
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'asset';
  return `vista-map-${slug}-${stamp}.${ext}`;
}

/**
 * Hand the browser a file.
 *
 * The same object-URL dance as `downloadCsv` on the Inventory page, kept
 * separate rather than shared because that one owns CSV escaping and this one
 * has nothing to escape by the time it is called.
 */
export function downloadText(filename: string, mime: string, text: string): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// --- the export menu's dismissal rules -------------------------------------
//
// The menu closed on `mouseleave` and on nothing else. Three consequences, and
// none of them is cosmetic:
//
//   - a keyboard user could open it and had no way to close it — Escape did
//     nothing, and tabbing past it left it hanging open over the graph;
//   - a pointer user who opened it and then clicked the canvas left it open,
//     covering the part of the map they had just clicked;
//   - on a touch device there is no `mouseleave` at all, so it never closed.
//
// The rules are pure functions rather than inline conditions in the component
// so both polarities can be pinned: a dismissal that fires on EVERYTHING is as
// broken as one that fires on nothing (it would close the menu on the click
// that chose an item, before the handler ran).

/** Whether this key dismisses an open menu. */
export function closesOnKey(key: string): boolean {
  // `Esc` as well as `Escape`: the older spelling is what some browsers and
  // most synthetic events still send, and a dismissal that only half works is
  // the kind nobody notices until a keyboard user reports it.
  return key === 'Escape' || key === 'Esc';
}

/** The minimum of a DOM node this module needs — so the rule below is testable
 *  without a document. */
export interface Containing {
  contains(node: unknown): boolean;
}

/**
 * Whether a pointer event outside the menu should dismiss it.
 *
 * The BUTTON counts as inside. It has its own toggle handler, and treating a
 * click on it as "outside" would close the menu here and reopen it there (or,
 * depending on event order, close and immediately reopen) — the button would
 * appear not to work.
 *
 * A null container is "the menu is not mounted", which is not a dismissal:
 * returning true there would fire a state update on every click of a page whose
 * menu is already closed.
 */
export function closesOnOutsidePointer(
  target: unknown,
  menu: Containing | null,
  button: Containing | null,
): boolean {
  if (!menu && !button) return false;
  if (menu?.contains(target)) return false;
  if (button?.contains(target)) return false;
  return true;
}
