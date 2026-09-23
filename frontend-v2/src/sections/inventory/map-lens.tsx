// The asset map (ADR-0006 D4, workstream 2.9).
//
// The renderer, and the ONLY module in the app that imports `@xyflow/react` or
// dagre. Both entry points below are reached through `React.lazy`, so the graph
// library and the layout engine ship as their own chunk and a user who never
// opens the map never downloads them.
//
// Everything with a decision in it lives next door and is unit-tested:
// `map-model.ts` (which edges are drawn, how a node is coloured, what the
// truncation banner says, how the impact overlay tints), `map-layout.ts` (dagre)
// and `map-export.ts` (GraphML / Cytoscape). What is left here is the wiring:
// state, URL, and the React Flow props.
//
// 2.8 left `useAssetNeighbourhood` as the seam, and this mounts onto it exactly
// — same hook, same cache key, no second endpoint.
import { memo, useCallback, useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import {
  Background, BackgroundVariant, BaseEdge, Controls, EdgeLabelRenderer, Handle,
  MarkerType, MiniMap, Panel,
  Position, ReactFlow, ReactFlowProvider, useUpdateNodeInternals,
  type Edge, type EdgeProps, type Node, type NodeChange, type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Icon } from '../../components/ui';
import { useAssetImpact, useAssetNeighbourhood } from './relationship-queries';
import { SOURCE_KIND_HELP, SOURCE_KIND_LABEL, TYPE_HELP } from './relationships';
import {
  CLASS_GROUP_STYLES, IMPACT_DIMMED_OPACITY, STATUS_RING_COLOR, STATUS_RING_HELP,
  assetNodeCount, buildImpactOverlay, buildMapGraph, canvasState, capGraph, classGroupOf,
  impactOverlayHeadline, impactTint, isAssetNode, legendFor, nodeAriaLabel,
  selectionAfterNodeChanges, statusRing, truncationNotice, withCloudScopeRoots,
  type MapEdge, type MapGraph, type MapNode,
} from './map-model';
import {
  DIRECTION_LABEL, HANDLE_SIDES, NODE_HEIGHT, NODE_WIDTH, flipDirection, layoutGraph,
  offsetEdgePath, parallelEdgeOffsets,
  type HandleSide, type LayoutDirection,
} from './map-layout';
import { closesOnKey, closesOnOutsidePointer, downloadText, mapExportFilename, toCytoscapeJSON, toGraphML } from './map-export';
import { QueryEditor } from './query-editor';
import { useAssetsQuery, AssetQueryError } from './asset-queries';
import { assetIdentity, classLabel } from './asset-shape';

const MIN_DEPTH = 1;
const MAX_DEPTH = 3;

export const clampDepth = (n: number): number => Math.min(MAX_DEPTH, Math.max(MIN_DEPTH, Math.round(n) || MIN_DEPTH));

/** Hold a value still for `ms` after it stops changing.
 *
 *  Used on the depth control. Dragging 1 → 3 otherwise fires a fetch and a
 *  layout at every step, and the intermediate graphs are work nobody asked
 *  for. The LAYOUT itself is a `useMemo`, not an effect, so it never re-runs on
 *  a hover or a selection — only when the graph or the direction changes. */
function useDebounced<T>(value: T, ms: number): T {
  const [held, setHeld] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setHeld(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return held;
}

// --------------------------------------------------------------- the node --

type AssetNodeData = {
  node: MapNode;
  focused: boolean;
  selected: boolean;
  dimmed: boolean;
  tintStrength: number;
  impactDepth: number | null;
  /** Which sides edges attach to — follows the layout axis (`HANDLE_SIDES`). */
  handles: { source: HandleSide; target: HandleSide };
};

/** The dagre-side side names, in xyflow's enum. The mapping lives here because
 *  `map-layout.ts` must not import the graph library. */
const HANDLE_POSITION: Readonly<Record<HandleSide, Position>> = {
  top: Position.Top,
  right: Position.Right,
  bottom: Position.Bottom,
  left: Position.Left,
};

/**
 * One asset box.
 *
 * `memo`'d: React Flow re-renders every node on a viewport change, and the
 * comparison here is cheap while the render is not.
 */
const AssetNode = memo(function AssetNode({ data }: NodeProps<Node<AssetNodeData>>) {
  const { node, focused, selected, dimmed, tintStrength, impactDepth, handles } = data;
  const style = CLASS_GROUP_STYLES[node.group];
  const isAsset = isAssetNode(node);
  const ring = statusRing(node.status);
  const tinted = impactDepth !== null && tintStrength > 0;
  // A scope box has no lifecycle, so it gets no status ring and no status line
  // in its tooltip. `statusRing('')` is `muted`, whose help text reads
  // "Archived, denied, or otherwise not in service" — true of no region ever.
  const ringColor = isAsset ? STATUS_RING_COLOR[ring] : 'transparent';
  const boxTitle = isAsset
    ? `${node.label}${node.classLabel ? ` · ${node.classLabel}` : ''}\n${STATUS_RING_HELP[ring]}`
    : `${style.label} ${node.label}\n${node.classLabel}\nGroups the assets below it. Not an asset itself.`;

  return (
    <div
      data-testid="map-node"
      data-group={node.group}
      data-status-ring={ring}
      title={boxTitle}
      style={{
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        opacity: dimmed ? IMPACT_DIMMED_OPACITY : 1,
        display: 'flex',
        alignItems: 'center',
        gap: 9,
        padding: '0 11px',
        borderRadius: 11,
        boxSizing: 'border-box',
        background: tinted
          ? `color-mix(in srgb, ${style.color} ${Math.round(tintStrength * 26)}%, var(--app-panel2))`
          : 'var(--app-panel2)',
        // Class is the fill/left bar, status is the ring. Two channels, because
        // a pending server has to still read as a server.
        // Dashed for a scope box: it is a frame the client drew, not a thing
        // the inventory holds, and one glance should say so.
        border: `${focused ? 2 : 1}px ${isAsset ? 'solid' : 'dashed'} ${focused ? style.color : 'var(--app-border2)'}`,
        outline: selected ? '2px solid var(--accent)' : 'none',
        outlineOffset: 2,
        boxShadow: focused ? `0 0 0 4px color-mix(in srgb, ${style.color} 18%, transparent)` : 'none',
        transition: 'opacity .15s ease',
      }}
    >
      <Handle type="target" position={HANDLE_POSITION[handles.target]} style={{ opacity: 0, pointerEvents: 'none' }} />
      <div
        aria-hidden
        style={{
          width: 26, height: 26, borderRadius: 8, flexShrink: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `color-mix(in srgb, ${style.color} 16%, transparent)`,
          // The status ring: a coloured circle around the class icon.
          boxShadow: `0 0 0 2px ${ringColor}`,
        }}
      >
        <Icon name={style.icon} size={14} style={{ color: style.color }} />
      </div>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontSize: 12, fontWeight: 650, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {node.label}
        </div>
        <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {node.classLabel || style.label}
          {impactDepth !== null && impactDepth > 0 ? ` · ${impactDepth} hop${impactDepth === 1 ? '' : 's'}` : ''}
        </div>
      </div>
      {focused && (
        <span
          title="The asset this neighbourhood is drawn around"
          style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: .4, textTransform: 'uppercase', color: style.color, flexShrink: 0 }}
        >
          Focus
        </span>
      )}
      <Handle type="source" position={HANDLE_POSITION[handles.source]} style={{ opacity: 0, pointerEvents: 'none' }} />
    </div>
  );
});

const NODE_TYPES = { asset: AssetNode };

/**
 * An edge that can be displaced sideways, so two relationships between the same
 * pair of assets are two visible, separately hoverable lines.
 *
 * xyflow's built-in edges all draw one canonical path between two handles, so
 * an application that both `runs_on` and `connects_to` its host was drawn as a
 * single line: the second edge hidden underneath, its label overprinted, and no
 * way to hover it for its provenance and confidence. The geometry is
 * `offsetEdgePath`, which is pure and unit-tested; this component is the
 * xyflow-shaped wrapper around it.
 *
 * `interactionWidth` is what makes the line HIT-TESTABLE — a 1.4px stroke is
 * almost impossible to hover with a mouse, and two of them 30px apart are worse
 * than one. `BaseEdge` draws a transparent fat path underneath for the purpose.
 */
const OffsetEdge = memo(function OffsetEdge({
  id, sourceX, sourceY, targetX, targetY, label, style, markerEnd, data,
}: EdgeProps) {
  const offset = typeof data?.offset === 'number' ? data.offset : 0;
  const { path, labelX, labelY } = offsetEdgePath(sourceX, sourceY, targetX, targetY, offset);
  return (
    <>
      <BaseEdge id={id} path={path} style={style} markerEnd={markerEnd} interactionWidth={20} />
      {label && (
        <EdgeLabelRenderer>
          <div
            // `pointer-events: none` so the label never steals the hover from
            // the line it names — the tooltip is bound to the EDGE, and a label
            // that swallowed the pointer would make the second edge's detail
            // unreachable again by a different route.
            style={{
              position: 'absolute', pointerEvents: 'none',
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              fontSize: 10, color: 'var(--app-t3)', background: 'var(--app-bg)',
              padding: '2px 4px', borderRadius: 4,
              opacity: typeof style?.opacity === 'number' ? style.opacity : 1,
            }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});

const EDGE_TYPES = { offset: OffsetEdge };

// --------------------------------------------------------- virtual list ----

/**
 * A fixed-row-height windowed list.
 *
 * The picker can hold a full page of results and the side panel a node's whole
 * edge list, and both sit inside a panel that is already competing with a
 * canvas for frame budget. Rendering only the visible slice keeps a scroll
 * cheap without adding a dependency for it.
 */
function VirtualList<T>({ items, rowHeight, height, render, empty }: {
  items: T[];
  rowHeight: number;
  height: number;
  render: (item: T, index: number) => ReactNode;
  empty?: ReactNode;
}) {
  const [scrollTop, setScrollTop] = useState(0);
  const overscan = 4;
  const total = items.length;
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const visible = Math.ceil(height / rowHeight) + overscan * 2;
  const slice = items.slice(first, first + visible);

  if (total === 0 && empty) return <>{empty}</>;

  return (
    <div
      data-testid="virtual-list"
      onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
      style={{ height, overflowY: 'auto', position: 'relative' }}
    >
      <div style={{ height: total * rowHeight, position: 'relative' }}>
        <div style={{ position: 'absolute', top: first * rowHeight, left: 0, right: 0 }}>
          {slice.map((item, i) => (
            <div key={first + i} style={{ height: rowHeight }}>{render(item, first + i)}</div>
          ))}
        </div>
      </div>
    </div>
  );
}

// -------------------------------------------------------------- controls --

function Toggle({ on, onClick, icon, label, title }: {
  on: boolean; onClick: () => void; icon: string; label: string; title: string;
}) {
  return (
    <button
      className={'ui-btn sm' + (on ? ' accent' : '')}
      onClick={onClick}
      title={title}
      aria-pressed={on}
      style={{ fontSize: 12 }}
    >
      <Icon name={icon} size={12} />{label}
    </button>
  );
}

function ExportMenu({ graph, rootLabel, disabled }: { graph: MapGraph; rootLabel: string; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);

  // Closing it. It used to close on `mouseleave` alone, which is no dismissal
  // at all for a keyboard user (Escape did nothing, tab left it hanging open
  // over the graph) and none on a touch device, where there is no mouseleave.
  //
  // Focus goes back to the BUTTON on an Escape, because that is where it came
  // from — an Escape that closes the menu and drops focus onto the document
  // body makes the next Tab restart from the top of the page.
  const close = useCallback((restoreFocus: boolean) => {
    setOpen(false);
    if (restoreFocus) buttonRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (closesOnKey(e.key)) {
        e.stopPropagation();
        close(true);
      }
    };
    // `mousedown`, not `click`: a click on a menu ITEM would otherwise race the
    // item's own handler, and closing first can unmount the button before its
    // onClick runs. mousedown outside is unambiguous.
    const onPointer = (e: MouseEvent) => {
      if (closesOnOutsidePointer(e.target, menuRef.current, buttonRef.current)) close(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onPointer);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onPointer);
    };
  }, [open, close]);

  return (
    <div style={{ position: 'relative' }}>
      <button
        ref={buttonRef}
        className="ui-btn sm"
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open && !disabled}
        onClick={() => setOpen((v) => !v)}
        title="Export the graph on screen — convenience, not audit evidence"
        style={{ fontSize: 12, opacity: disabled ? 0.5 : 1 }}
      >
        <Icon name="download" size={12} />Export
      </button>
      {open && !disabled && (
        <div
          ref={menuRef}
          role="menu"
          data-testid="map-export-menu"
          style={{
            position: 'absolute', top: 'calc(100% + 5px)', right: 0, zIndex: 20, minWidth: 236,
            padding: 6, borderRadius: 11, border: '1px solid var(--app-border2)',
            background: 'var(--app-panel)', boxShadow: 'var(--app-shadow)',
          }}
        >
          <button
            className="ui-btn sm ghost"
            style={{ width: '100%', justifyContent: 'flex-start', fontSize: 12 }}
            onClick={() => {
              downloadText(mapExportFilename(rootLabel, 'graphml'), 'application/xml', toGraphML(graph));
              close(true);
            }}
          >
            GraphML <span style={{ color: 'var(--app-t3)' }}>· Visio, yEd, Gephi</span>
          </button>
          <button
            className="ui-btn sm ghost"
            style={{ width: '100%', justifyContent: 'flex-start', fontSize: 12 }}
            onClick={() => {
              downloadText(mapExportFilename(rootLabel, 'json'), 'application/json', toCytoscapeJSON(graph));
              close(true);
            }}
          >
            Cytoscape JSON <span style={{ color: 'var(--app-t3)' }}>· Cytoscape.js</span>
          </button>
          <div style={{ fontSize: 10.5, color: 'var(--app-t3)', lineHeight: 1.5, padding: '6px 8px 3px' }}>
            A picture of what is on screen, with no provenance or content hash — and a
            prefix of the real neighbourhood when the graph is truncated. For evidence,
            generate a CBOM artifact.
          </div>
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------- the picker --

/** The height of an element, tracked as it resizes — so the picker's windowed
 *  list can fill whatever the sidebar leaves it rather than a fixed guess. */
function useElementHeight<T extends HTMLElement>(): [(el: T | null) => void, number] {
  const [height, setHeight] = useState(0);
  const observer = useRef<ResizeObserver | null>(null);
  const ref = useCallback((el: T | null) => {
    observer.current?.disconnect();
    observer.current = null;
    if (!el) return;
    setHeight(el.clientHeight);
    if (typeof ResizeObserver === 'undefined') return;
    observer.current = new ResizeObserver(([entry]) => setHeight(entry.contentRect.height));
    observer.current.observe(el);
  }, []);
  return [ref, height];
}

/** Find the asset to centre the map on — the map lens's left-hand sidebar.
 *
 *  The same query language and the same editor as the Inventory list, because
 *  "which asset" is the question the list already answers and a second search
 *  box with its own syntax would be a second thing to learn. The query itself
 *  lives with the lens, which needs the first result to auto-focus the map. */
function AssetPicker({ query, onQueryChange, q, selectedId, onPick }: {
  query: string;
  onQueryChange: (query: string) => void;
  q: ReturnType<typeof useAssetsQuery>;
  selectedId: string;
  onPick: (id: string) => void;
}) {
  const rows = q.data?.assets ?? [];
  const [listRef, listHeight] = useElementHeight<HTMLDivElement>();

  return (
    <aside
      data-testid="map-picker"
      style={{
        width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 10, minHeight: 0,
        padding: '4px 12px 12px', borderRight: '1px solid var(--app-border)',
      }}
    >
      {/* A row of its own: the editor's root is `flex: 1` for the toolbars it
          normally sits in, which in this column would split the sidebar's
          height with the list. */}
      <div style={{ display: 'flex', flex: 'none' }}>
        <QueryEditor value={query} onChange={onQueryChange} placeholder="e.g. class:server" />
      </div>

      {q.isError && (
        <div data-testid="map-picker-error" style={{ fontSize: 12, color: 'var(--danger-text)' }}>
          {q.error instanceof AssetQueryError || q.error instanceof Error
            ? q.error.message
            : 'The search failed.'}
        </div>
      )}

      {!q.isError && (
        <div ref={listRef} style={{ flex: 1, minHeight: 0 }}>
        <VirtualList
          items={rows}
          rowHeight={46}
          height={listHeight}
          empty={
            <div data-testid="map-picker-empty" style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '18px 2px' }}>
              {q.isLoading ? 'Searching…' : 'No assets match that query.'}
            </div>
          }
          render={(a) => (
            <button
              onClick={() => onPick(a.id)}
              className={'ui-btn ghost' + (a.id === selectedId ? ' accent' : '')}
              aria-current={a.id === selectedId ? 'true' : undefined}
              style={{
                width: '100%', height: 42, justifyContent: 'flex-start', gap: 10,
                textAlign: 'left', fontSize: 12.5,
              }}
            >
              <Icon name={CLASS_GROUP_STYLES[classGroupOf(a.class_key)].icon} size={14} style={{ color: 'var(--app-t3)', flexShrink: 0 }} />
              <span style={{ minWidth: 0, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {assetIdentity(a).primary}
              </span>
              <span style={{ fontSize: 11, color: 'var(--app-t3)', flexShrink: 0 }}>{classLabel(a.class_key) || '—'}</span>
            </button>
          )}
        />
        </div>
      )}
    </aside>
  );
}

// ---------------------------------------------------------- side panel ----

function NodePanel({ node, edges, onClose, onFocus, fullScreen }: {
  node: MapNode;
  edges: MapEdge[];
  onClose: () => void;
  onFocus: (id: string) => void;
  fullScreen: boolean;
}) {
  const style = CLASS_GROUP_STYLES[node.group];
  const isAsset = isAssetNode(node);
  const ring = statusRing(node.status);
  const attached = edges.filter((e) => e.source === node.id || e.target === node.id);

  return (
    <aside
      data-testid="map-node-panel"
      style={{
        width: 292, flexShrink: 0, display: 'flex', flexDirection: 'column',
        borderLeft: '1px solid var(--app-border)', background: 'var(--app-panel)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 9, padding: '13px 14px 10px' }}>
        <div
          style={{
            width: 28, height: 28, borderRadius: 8, flexShrink: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: `color-mix(in srgb, ${style.color} 16%, transparent)`,
            boxShadow: `0 0 0 2px ${isAsset ? STATUS_RING_COLOR[ring] : 'transparent'}`,
          }}
        >
          <Icon name={style.icon} size={15} style={{ color: style.color }} />
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)', wordBreak: 'break-word' }}>{node.label}</div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
            {isAsset
              ? `${node.classLabel || style.label} · ${node.status || 'status unknown'}`
              : `${style.label} · ${node.classLabel}`}
          </div>
        </div>
        <button className="ui-btn sm ghost" onClick={onClose} title="Close"><Icon name="x" size={12} /></button>
      </div>

      {!isAsset && (
        // No actions, and a line saying why. A region is a scoping attribute
        // ( D6), not an asset: there is no page to open and no
        // neighbourhood to redraw around it. Saying so beats two greyed-out
        // buttons that look like a permissions problem.
        <div data-testid="map-scope-panel-note" style={{ fontSize: 11.5, color: 'var(--app-t3)', padding: '0 14px 11px', lineHeight: 1.55 }}>
          A {style.label.toLowerCase()} is recorded on each asset, not inventoried on its own — there is
          no asset page for it. It is drawn here so its resources have somewhere to sit.
        </div>
      )}

      {isAsset && (
      <div style={{ display: 'flex', gap: 6, padding: '0 14px 11px', flexWrap: 'wrap' }}>
        <Link
          to={`/inventory/assets/${node.assetId ?? node.id}`}
          className="ui-btn sm"
          style={{ textDecoration: 'none', fontSize: 12 }}
          // The full-screen map has no rail to come back to, so the asset page
          // opens in a new tab rather than replacing the map the user built.
          target={fullScreen ? '_blank' : undefined}
          rel={fullScreen ? 'noreferrer' : undefined}
        >
          <Icon name="external-link" size={12} />Open asset
        </Link>
        {!node.isRoot && (
          <button className="ui-btn sm" onClick={() => onFocus(node.assetId ?? node.id)} title="Redraw the neighbourhood around this asset" style={{ fontSize: 12 }}>
            <Icon name="crosshair" size={12} />Focus here
          </button>
        )}
      </div>
      )}

      {node.riskScore !== undefined && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', padding: '0 14px 10px' }}>
          Risk score <span className="mono" style={{ color: 'var(--app-t1)' }}>{node.riskScore}</span>
          {node.riskScore === 0 && ' — not assessed rather than safe'}
        </div>
      )}

      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: .4, textTransform: 'uppercase', color: 'var(--app-t3)', padding: '2px 14px 7px' }}>
        {attached.length} relationship{attached.length === 1 ? '' : 's'} on the map
      </div>
      <div style={{ padding: '0 8px 12px', flex: 1, minHeight: 0 }}>
        <VirtualList
          items={attached}
          rowHeight={40}
          height={Math.min(360, Math.max(44, attached.length * 40))}
          empty={
            <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '10px 6px' }}>
              Nothing on this map connects to it at the current depth.
            </div>
          }
          render={(e) => (
            <div style={{ padding: '4px 6px', display: 'flex', alignItems: 'center', gap: 7 }}>
              <span
                title={TYPE_HELP[e.type]}
                className="mono"
                style={{ fontSize: 11, color: 'var(--app-t2)', whiteSpace: 'nowrap' }}
              >
                {e.source === node.id ? '→' : '←'} {e.label}
              </span>
              <div style={{ flex: 1 }} />
              {e.pending && (
                <span style={{ fontSize: 10, color: 'var(--warn)', border: '1px solid color-mix(in srgb, var(--warn) 40%, transparent)', borderRadius: 40, padding: '0 6px' }}>
                  pending
                </span>
              )}
              <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }} title={SOURCE_KIND_HELP[e.sourceKind]}>
                {SOURCE_KIND_LABEL[e.sourceKind]}
              </span>
            </div>
          )}
        />
      </div>
    </aside>
  );
}

// ------------------------------------------------------- the map itself ---

export interface AssetMapViewProps {
  assetId: string;
  depth: number;
  includePending: boolean;
  onDepthChange: (d: number) => void;
  onIncludePendingChange: (v: boolean) => void;
  onFocus: (id: string) => void;
  /** Full screen: no app rail, an Exit button instead of a "Full screen" one. */
  fullScreen: boolean;
  onToggleFullScreen: () => void;
}

function AssetMapViewInner(props: AssetMapViewProps) {
  const { assetId, depth, includePending, fullScreen } = props;
  const [direction, setDirection] = useState<LayoutDirection>('LR');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [impactOn, setImpactOn] = useState(false);
  const [impactDirection, setImpactDirection] = useState<'downstream' | 'upstream'>('downstream');
  const [hoverEdge, setHoverEdge] = useState<{ edge: MapEdge; x: number; y: number } | null>(null);

  const heldDepth = useDebounced(depth, 220);
  const nbh = useAssetNeighbourhood(assetId, { depth: heldDepth, includePending });
  const impact = useAssetImpact(assetId, impactDirection, impactOn);

  // The model. Capped again on this side: the server caps at 500/2000 and says
  // so, and the browser should not be the thing that discovers a server that
  // stopped.
  const graph = useMemo(() => {
    const built = buildMapGraph(nbh.data);
    if (!nbh.data) return built;
    // Capped FIRST, then rooted. The caps are about assets and the totals the
    // truncation banner quotes come from the server, which has never heard of a
    // grouping node — synthesising the account and region boxes before the cap
    // would let scaffolding push real assets out of the graph.
    return withCloudScopeRoots(capGraph(built, nbh.data.node_cap, nbh.data.edge_cap));
  }, [nbh.data]);

  // The expensive step, memoised on exactly what changes it. Hovering an edge,
  // selecting a node and toggling the impact overlay all leave this untouched,
  // so none of them re-lay-out the graph.
  const layout = useMemo(() => layoutGraph(graph, direction), [graph, direction]);

  const overlay = useMemo(
    () => (impactOn ? buildImpactOverlay(impact.data) : null),
    [impactOn, impact.data],
  );

  const handles = HANDLE_SIDES[direction];

  const rfNodes = useMemo<Node<AssetNodeData>[]>(() => graph.nodes.map((n) => {
    const tint = impactTint(overlay, n.id, graph.rootId);
    return {
      id: n.id,
      type: 'asset',
      position: layout.positions[n.id] ?? { x: 0, y: 0 },
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
      draggable: false,
      // The class, the ring and the tint are all colour; none of them reach a
      // screen reader on their own, and the default announcement is "node".
      ariaLabel: nodeAriaLabel(n, isAssetNode(n) ? tint.depth : null),
      // `button` rather than the default `group`: Enter and Space activate it.
      // A grouping node has no panel to open, so it announces as an image
      // rather than promising an action that does nothing.
      ariaRole: isAssetNode(n) ? 'button' : 'img',
      data: {
        node: n,
        focused: n.isRoot,
        selected: n.id === selectedId,
        // A grouping node is never dimmed by the impact overlay. It is not an
        // asset, so it cannot be in or out of a blast radius, and dimming it as
        // "not affected" would answer a question nobody asked about a region.
        dimmed: !!overlay && isAssetNode(n) && !tint.inImpact,
        tintStrength: isAssetNode(n) ? tint.strength : 0,
        impactDepth: isAssetNode(n) ? tint.depth : null,
        handles,
      },
    };
  }), [graph, layout, overlay, selectedId, handles]);

  // Handle POSITIONS are measured once, when a node mounts — changing one
  // without saying so leaves xyflow drawing to where the handle used to be, so
  // flipping LR/TB would move the boxes and leave the arrows behind.
  const updateNodeInternals = useUpdateNodeInternals();
  useEffect(() => {
    if (graph.nodes.length) updateNodeInternals(graph.nodes.map((n) => n.id));
  }, [direction, graph.nodes, updateNodeInternals]);

  const rfEdges = useMemo<Edge[]>(() => {
    // Parallel edges are spread apart before anything is drawn, so two
    // relationships between the same pair of assets are two lines rather than
    // one line with a hidden twin. Computed over the WHOLE edge list, because
    // an offset only means anything relative to the other edges of its pair.
    const offsets = parallelEdgeOffsets(graph.edges);
    return graph.edges.map((e) => {
    const dimmed = !!overlay
      && !impactTint(overlay, e.source, graph.rootId).inImpact
      && !impactTint(overlay, e.target, graph.rootId).inImpact;
    return {
      id: e.id,
      type: 'offset',
      data: { offset: offsets[e.id] ?? 0 },
      source: e.source,
      target: e.target,
      label: e.label,
      // Pending is DASHED — proposed, not agreed. Rejected never reaches here:
      // `buildMapGraph` drops it.
      animated: false,
      style: {
        stroke: e.pending ? 'var(--warn)' : 'var(--app-border2)',
        strokeWidth: 1.4,
        strokeDasharray: e.pending ? '5 4' : undefined,
        opacity: dimmed ? IMPACT_DIMMED_OPACITY : 1,
      },
      // No `labelStyle` / `labelBgStyle` / `labelBgPadding` here: those are
      // read by xyflow's BUILT-IN edges, and this is `type: 'offset'`.
      // `OffsetEdge` renders the label itself (it has to — the midpoint of a
      // displaced curve is not the midpoint of the straight line), so it owns
      // the label's styling. Leaving them would be four lines that look like
      // they set the label's appearance and do not.
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: e.pending ? 'var(--warn)' : 'var(--app-border2)' },
    };
    });
  }, [graph, overlay]);

  const edgeById = useMemo(() => new Map(graph.edges.map((e) => [e.id, e])), [graph.edges]);
  const selectedNode = useMemo(() => graph.nodes.find((n) => n.id === selectedId) ?? null, [graph.nodes, selectedId]);
  const legend = useMemo(() => legendFor(graph), [graph]);
  // Assets and STORED edges only: the banner's "of N" comes from the server's
  // own totals, so counting the derived scope boxes and their lines here would
  // have a complete graph claim to be showing more than exists.
  const shownCounts = useMemo(() => ({
    nodes: assetNodeCount(graph),
    edges: graph.edges.reduce((n, e) => (e.synthetic ? n : n + 1), 0),
  }), [graph]);
  const truncation = useMemo(
    () => truncationNotice(nbh.data, shownCounts),
    [nbh.data, shownCounts],
  );

  // Read off the graph rather than fetched separately: the neighbourhood
  // ALWAYS contains its own root node, so a second `useAsset` call would be a
  // request per map view whose only job is a label we already have.
  const rootLabel = graph.nodes.find((n) => n.isRoot)?.label ?? 'asset';

  // A focus change clears the selection: the side panel would otherwise
  // describe a node from the previous neighbourhood, which may not be in this
  // one at all.
  //
  // Adjusted DURING RENDER rather than in an effect — React's own
  // recommendation for resetting state when a prop changes, and the same shape
  // the query editor uses to follow the URL. An effect would paint the stale
  // panel for a frame first, which here means a panel describing an asset that
  // is no longer on screen.
  const [lastAssetId, setLastAssetId] = useState(assetId);
  if (assetId !== lastAssetId) {
    setLastAssetId(assetId);
    setSelectedId(null);
  }

  const onEdgeEnter = useCallback((ev: ReactMouseEvent, edge: Edge) => {
    const model = edgeById.get(edge.id);
    if (model) setHoverEdge({ edge: model, x: ev.clientX, y: ev.clientY });
  }, [edgeById]);

  // The KEYBOARD path into the side panel. React Flow already makes each node a
  // tab stop and handles Enter / Space / Escape on it, but it reports the
  // result as a change — and a controlled `nodes` prop with no handler here
  // meant the change was discarded and pressing Enter did nothing. Position and
  // dimension changes are ignored on purpose: the layout owns those.
  const onNodesChange = useCallback((changes: NodeChange<Node<AssetNodeData>>[]) => {
    const next = selectionAfterNodeChanges(changes);
    if (next !== undefined) setSelectedId(next);
  }, []);

  // Exactly one of loading / error / empty / graph. Everything that describes
  // "the graph on screen" reads THIS and not `nbh.data`, which react-query goes
  // on holding through a failure.
  const state = canvasState(nbh, graph);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      {/* ------------------------------------------------------ toolbar -- */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: fullScreen ? '12px 18px' : '14px 26px 10px', flexWrap: 'wrap', borderBottom: fullScreen ? '1px solid var(--app-border)' : 'none' }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15.5, color: 'var(--app-t1)', display: 'flex', alignItems: 'center', gap: 9 }}>
          <Icon name="waypoints" size={17} style={{ color: 'var(--accent)' }} />
          Map
          <span style={{ fontWeight: 500, fontSize: 13, color: 'var(--app-t3)' }}>· {rootLabel}</span>
        </h2>

        <div style={{ flex: 1 }} />

        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--app-t3)' }}>
          Depth
          <input
            type="range" min={MIN_DEPTH} max={MAX_DEPTH} step={1} value={depth}
            onChange={(e) => props.onDepthChange(clampDepth(Number(e.target.value)))}
            title={`Hops from the focus asset (${MIN_DEPTH}–${MAX_DEPTH})`}
            style={{ width: 74 }}
          />
          <span className="mono" style={{ color: 'var(--app-t1)', width: 10 }}>{depth}</span>
        </label>

        <Toggle
          on={includePending} icon="inbox" label="Pending"
          title="Include relationships nobody has confirmed yet. They draw dashed."
          onClick={() => props.onIncludePendingChange(!includePending)}
        />
        <Toggle
          on={impactOn} icon="zap" label="Show impact of focus"
          title="Highlight what depends on the focus asset (or what it depends on). Everything else dims."
          onClick={() => setImpactOn((v) => !v)}
        />
        {impactOn && (
          <button
            className="ui-btn sm ghost" style={{ fontSize: 12 }}
            onClick={() => setImpactDirection((d) => (d === 'downstream' ? 'upstream' : 'downstream'))}
            title="Swap between what depends on this and what this depends on"
          >
            <Icon name="arrow-left-right" size={12} />
            {impactDirection === 'downstream' ? 'Downstream' : 'Upstream'}
          </button>
        )}
        <button
          className="ui-btn sm" style={{ fontSize: 12 }}
          onClick={() => setDirection(flipDirection)}
          title={`Layout: ${DIRECTION_LABEL[direction]}`}
        >
          <Icon name="route" size={12} />{direction}
        </button>
        {/* Offered only when a graph is actually drawn. Under an error card the
            model still holds the LAST good neighbourhood, and a file written
            from it — named after that asset — could not be told apart later
            from one exported deliberately. */}
        <ExportMenu graph={graph} rootLabel={rootLabel} disabled={state !== 'graph'} />
        <button className="ui-btn sm" onClick={props.onToggleFullScreen} style={{ fontSize: 12 }} title={fullScreen ? 'Back to the Inventory map lens' : 'Open the map full screen'}>
          <Icon name={fullScreen ? 'minimize' : 'maximize'} size={12} />{fullScreen ? 'Exit' : 'Full screen'}
        </button>
      </div>

      {impactOn && impact.data && (
        <div data-testid="map-impact-headline" style={{ margin: fullScreen ? '10px 18px 0' : '0 26px 10px', fontSize: 12.5, color: 'var(--app-t1)' }}>
          <Icon name="zap" size={12} style={{ color: 'var(--accent)', verticalAlign: -1 }} />{' '}
          {impactOverlayHeadline(overlay)}
          <span style={{ color: 'var(--app-t3)' }}> — everything else is dimmed, not hidden.</span>
        </div>
      )}
      {impactOn && impact.isError && (
        <div data-testid="map-impact-error" style={{ margin: fullScreen ? '10px 18px 0' : '0 26px 10px', fontSize: 12.5, color: 'var(--danger-text)' }}>
          Couldn&rsquo;t work out the blast radius — nothing is highlighted, which is not an answer of &ldquo;nothing is affected&rdquo;.
        </div>
      )}

      {state === 'graph' && truncation && (
        <div
          data-testid="map-truncated"
          style={{
            display: 'flex', alignItems: 'center', gap: 9,
            margin: fullScreen ? '10px 18px 0' : '0 26px 10px', padding: '8px 13px', borderRadius: 11,
            border: '1px solid color-mix(in srgb, var(--warn) 35%, transparent)',
            background: 'color-mix(in srgb, var(--warn) 8%, transparent)',
          }}
        >
          <Icon name="alert-triangle" size={14} style={{ color: 'var(--warn)', flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{truncation.text}</span>
        </div>
      )}

      {/* ------------------------------------------------------- canvas -- */}
      <div style={{ display: 'flex', flex: 1, minHeight: 0, margin: fullScreen ? 0 : '0 26px 18px', borderRadius: fullScreen ? 0 : 14, border: fullScreen ? 'none' : '1px solid var(--app-border)', overflow: 'hidden', background: 'var(--app-bg2)' }}>
        <div style={{ flex: 1, minWidth: 0, position: 'relative' }}>
          {state === 'loading' && (
            <Centered testId="map-loading" icon="loader" title="Drawing the neighbourhood…" message="Fetching what this asset is attached to." />
          )}

          {state === 'error' && (
            <Centered
              testId="map-error" icon="alert-triangle" tone="var(--danger-text)"
              title="Couldn't load the neighbourhood"
              message={`${nbh.error instanceof Error ? nbh.error.message : 'The request failed.'} This asset may still have relationships; none are shown.`}
              action={{ label: 'Retry', onClick: () => { void nbh.refetch(); } }}
            />
          )}

          {(state === 'graph' || state === 'empty') && (
            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              onNodesChange={onNodesChange}
              nodeTypes={NODE_TYPES}
              edgeTypes={EDGE_TYPES}
              fitView
              // A lone focus node would otherwise be zoomed to maxZoom and fill
              // the canvas; cap the initial fit at actual size.
              fitViewOptions={{ maxZoom: 1 }}
              // The layout owns positions; dragging a node would desync it from
              // the exports and from what a second viewer sees.
              nodesDraggable={false}
              nodesConnectable={false}
              edgesFocusable
              minZoom={0.15}
              maxZoom={2}
              proOptions={{ hideAttribution: false }}
              onNodeClick={(_, n) => setSelectedId(n.id)}
              onPaneClick={() => { setSelectedId(null); setHoverEdge(null); }}
              onEdgeMouseEnter={onEdgeEnter}
              onEdgeMouseLeave={() => setHoverEdge(null)}
            >
              <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--app-border)" />
              <Controls showInteractive={false} />
              <MiniMap
                pannable zoomable
                nodeColor={(n) => CLASS_GROUP_STYLES[(n.data as AssetNodeData).node.group].color}
                style={{ background: 'var(--app-panel2)' }}
              />
              <Panel position="top-left">
                <div
                  data-testid="map-legend"
                  style={{
                    display: 'flex', gap: 10, flexWrap: 'wrap', maxWidth: 420,
                    padding: '6px 10px', borderRadius: 10,
                    border: '1px solid var(--app-border2)', background: 'var(--app-panel)',
                  }}
                >
                  {legend.map(({ group, style, count }) => (
                    <span key={group} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--app-t2)' }}>
                      <span style={{ width: 9, height: 9, borderRadius: 3, background: style.color }} />
                      {style.label}
                      <span className="mono" style={{ color: 'var(--app-t3)' }}>{count}</span>
                    </span>
                  ))}
                </div>
              </Panel>
              {state === 'empty' && (
                // Drawn OVER the canvas rather than instead of it: the focus asset
                // is still on the map, so the user can see there is a map here
                // and that this asset simply has nothing attached yet.
                <Panel position="bottom-center">
                  <div
                    data-testid="map-empty"
                    style={{
                      maxWidth: 460, padding: '11px 14px', borderRadius: 11, textAlign: 'center',
                      border: '1px solid var(--app-border2)', background: 'var(--app-panel)',
                      display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'center',
                    }}
                  >
                    <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>No relationships yet</div>
                    <div style={{ fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.55 }}>
                      Nothing has been observed or declared about what this asset is attached to.
                      Most of an inventory is a leaf, so this is a normal answer — but impact
                      analysis has nothing to go on here.
                    </div>
                    <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', justifyContent: 'center' }}>
                      <Link to="/discovery/sensors" className="ui-btn sm" style={{ textDecoration: 'none', fontSize: 12 }}>
                        <Icon name="radar" size={12} />How relationships are discovered
                      </Link>
                      <Link to={`/inventory/assets/${assetId}/relationships`} className="ui-btn sm ghost" style={{ textDecoration: 'none', fontSize: 12 }}>
                        <Icon name="plus" size={12} />Declare one
                      </Link>
                    </div>
                  </div>
                </Panel>
              )}
            </ReactFlow>
          )}

          {hoverEdge && (
            <div
              data-testid="map-edge-tooltip"
              style={{
                position: 'fixed', left: hoverEdge.x + 14, top: hoverEdge.y + 14, zIndex: 40,
                pointerEvents: 'none', maxWidth: 290, padding: '8px 11px', borderRadius: 10,
                border: '1px solid var(--app-border2)', background: 'var(--app-panel)',
                boxShadow: 'var(--app-shadow)',
              }}
            >
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--app-t1)' }}>{hoverEdge.edge.label}</div>
              <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 2, lineHeight: 1.5 }}>
                {hoverEdge.edge.synthetic ? (
                  // No provenance block: there is no stored relationship here,
                  // so a confidence and an observation count would be numbers
                  // about nothing.
                  <>Drawn from the asset&rsquo;s recorded cloud account and region. Not a stored relationship — nothing observed it.</>
                ) : (
                  <>
                    {SOURCE_KIND_LABEL[hoverEdge.edge.sourceKind]} — {SOURCE_KIND_HELP[hoverEdge.edge.sourceKind]}
                    <br />
                    Confidence <span className="mono">{hoverEdge.edge.confidence.toFixed(2)}</span>
                    {' · '}seen <span className="mono">{hoverEdge.edge.observationCount}×</span>
                    <br />
                    First {shortDate(hoverEdge.edge.firstSeenAt)} · last {shortDate(hoverEdge.edge.lastSeenAt)}
                  </>
                )}
                {hoverEdge.edge.pending && (
                  <>
                    <br />
                    <span style={{ color: 'var(--warn)' }}>Pending — proposed, not confirmed, and not counted in impact.</span>
                  </>
                )}
              </div>
            </div>
          )}
        </div>

        {selectedNode && (
          <NodePanel
            node={selectedNode}
            edges={graph.edges}
            onClose={() => setSelectedId(null)}
            onFocus={props.onFocus}
            fullScreen={fullScreen}
          />
        )}
      </div>
    </div>
  );
}

function shortDate(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toISOString().slice(0, 10);
}

function Centered({ testId, icon, tone, title, message, action }: {
  testId: string; icon: string; tone?: string; title: string; message: string;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div
      data-testid={testId}
      style={{
        position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center', gap: 9, padding: '30px 26px', textAlign: 'center',
      }}
    >
      <Icon name={icon} size={26} style={{ color: tone ?? 'var(--app-t3)' }} />
      <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>{title}</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 480, lineHeight: 1.6 }}>{message}</div>
      {action && <button className="ui-btn sm" onClick={action.onClick}>{action.label}</button>}
    </div>
  );
}

/** React Flow needs its provider above anything that uses its store. */
export function AssetMapView(props: AssetMapViewProps) {
  return (
    <ReactFlowProvider>
      <AssetMapViewInner {...props} />
    </ReactFlowProvider>
  );
}

// ----------------------------------------------------------- entry points --

/**
 * The Inventory map lens (`/inventory?lens=map`).
 *
 * Focus, depth and the pending toggle live in the URL, like the rest of this
 * page's state, so a map is a link somebody can paste into a ticket.
 */
export function AssetMapLens() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const focus = params.get('focus') ?? '';
  const depth = clampDepth(Number(params.get('depth') ?? 2));
  const includePending = params.get('pending') === '1';
  const [query, setQuery] = useState('');
  const q = useAssetsQuery(query, 1, true);
  const firstId = q.data?.assets?.[0]?.id;

  const setParam = useCallback((key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value === null || value === '') next.delete(key); else next.set(key, value);
    setParams(next, { replace: true });
  }, [params, setParams]);

  // Start on the first asset in the list, so the lens opens on a map rather
  // than on a list with an empty space beside it. Only when nothing is focused:
  // a focus from the URL (a pasted link) or a click always wins.
  useEffect(() => {
    if (!focus && firstId) setParam('focus', firstId);
  }, [focus, firstId, setParam]);

  return (
    <div data-testid="map-lens" style={{ display: 'flex', flex: 1, minHeight: 0, height: '100%' }}>
      <AssetPicker
        query={query}
        onQueryChange={setQuery}
        q={q}
        selectedId={focus}
        onPick={(id) => setParam('focus', id)}
      />
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
        {focus ? (
          <AssetMapView
            assetId={focus}
            depth={depth}
            includePending={includePending}
            onDepthChange={(d) => setParam('depth', String(d))}
            onIncludePendingChange={(v) => setParam('pending', v ? '1' : null)}
            onFocus={(id) => setParam('focus', id)}
            fullScreen={false}
            onToggleFullScreen={() => {
              void navigate(`/inventory/map/${focus}?depth=${depth}${includePending ? '&pending=1' : ''}`);
            }}
          />
        ) : (
          <div style={{ flex: 1, position: 'relative', margin: '0 26px 18px', borderRadius: 14, border: '1px solid var(--app-border)', background: 'var(--app-bg2)' }}>
            {q.isLoading ? (
              <Centered testId="map-loading" icon="loader" title="Loading assets…" message="The map opens on the first asset in the list." />
            ) : (
              <Centered
                testId="map-no-assets" icon="waypoints" title="Nothing to map yet"
                message={query
                  ? 'No assets match that query. Change or clear it to pick an asset to map.'
                  : 'The map draws what an asset is attached to. Once assets are in the inventory, the first one opens here.'}
              />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * The full-screen map (`/inventory/map/:assetId`).
 *
 * Same component, no rail. Exit goes back to the lens carrying the current
 * depth and pending state, so leaving full screen is not a reset.
 */
export function AssetMapFullscreen() {
  const { assetId = '' } = useParams<{ assetId: string }>();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const depth = clampDepth(Number(params.get('depth') ?? 2));
  const includePending = params.get('pending') === '1';

  const setParam = useCallback((key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value === null || value === '') next.delete(key); else next.set(key, value);
    setParams(next, { replace: true });
  }, [params, setParams]);

  const exitTo = `/inventory?lens=map&focus=${encodeURIComponent(assetId)}&depth=${depth}${includePending ? '&pending=1' : ''}`;

  return (
    <div style={{ position: 'fixed', inset: 0, display: 'flex', flexDirection: 'column', background: 'var(--app-bg)', zIndex: 5 }}>
      <AssetMapView
        assetId={assetId}
        depth={depth}
        includePending={includePending}
        onDepthChange={(d) => setParam('depth', String(d))}
        onIncludePendingChange={(v) => setParam('pending', v ? '1' : null)}
        onFocus={(id) => { void navigate(`/inventory/map/${id}?depth=${depth}${includePending ? '&pending=1' : ''}`, { replace: true }); }}
        fullScreen
        onToggleFullScreen={() => { void navigate(exitTo); }}
      />
    </div>
  );
}

export default AssetMapLens;
