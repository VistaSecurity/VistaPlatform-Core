// @vitest-environment jsdom
//
// Physical cabling on the map (DCIM BUILD_PLAN row 3.6), driven through the
// REAL neighbourhood and topology views.
//
// React Flow draws no edges in jsdom (it waits for measured handles), so its
// canvas is replaced by a stand-in that renders each edge it is HANDED as a
// button carrying the edge's style and calling the view's own `onEdgeClick`.
// Everything up to that prop — which edges the view builds, their styles, the
// layer toggle, the click handling, the menu and the trace — is the real code.
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Neighbourhood } from './relationships';
import type { TopologyPayload } from './topology-model';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
vi.stubGlobal('ResizeObserver', class { observe(): void {} unobserve(): void {} disconnect(): void {} });

const state = vi.hoisted(() => ({
  nbh: null as Neighbourhood | null,
  nbhLoading: false,
  nbhError: false,
  topology: null as TopologyPayload | null,
  get: vi.fn(),
}));

vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: state.get, POST: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

vi.mock('./relationship-queries', () => ({
  useAssetNeighbourhood: () => ({
    data: state.nbhLoading || state.nbhError ? undefined : state.nbh ?? undefined,
    isLoading: state.nbhLoading, isError: state.nbhError,
    error: state.nbhError ? new Error('boom') : null, refetch: () => {},
  }),
  useAssetImpact: () => ({ data: undefined, isLoading: false, isError: false, error: null }),
  useAssetTopology: () => ({ data: state.topology ?? undefined, isLoading: false, isError: false, error: null }),
}));

vi.mock('@xyflow/react', async (importOriginal) => {
  const real = await importOriginal<typeof import('@xyflow/react')>();
  const React = await import('react');
  type E = { id: string; style?: { stroke?: string; strokeWidth?: number; strokeDasharray?: string }; label?: string };
  return {
    ...real,
    ReactFlowProvider: ({ children }: { children: React.ReactNode }) => React.createElement(React.Fragment, null, children),
    useUpdateNodeInternals: () => () => {},
    Background: () => null,
    Controls: () => null,
    MiniMap: () => null,
    Panel: ({ children }: { children: React.ReactNode }) => React.createElement('div', null, children),
    ReactFlow: ({ nodes, edges, onEdgeClick, onNodeClick, children }: {
      nodes: { id: string }[]; edges: E[]; children?: React.ReactNode;
      onEdgeClick?: (ev: unknown, e: E) => void; onNodeClick?: (ev: unknown, n: { id: string }) => void;
    }) =>
      React.createElement('div', { 'data-testid': 'rf-canvas' },
        nodes.map((n) => React.createElement('button', {
          key: n.id, type: 'button', 'data-testid': 'rf-node', 'data-id': n.id, onClick: (ev: unknown) => onNodeClick?.(ev, n),
        })),
        edges.map((e) => React.createElement('button', {
          key: e.id, type: 'button', 'data-testid': 'rf-edge', 'data-id': e.id,
          'data-stroke': e.style?.stroke ?? '', 'data-width': String(e.style?.strokeWidth ?? ''), 'data-dash': e.style?.strokeDasharray ?? '',
          onClick: (ev: { clientX: number; clientY: number }) => onEdgeClick?.(ev, e),
        }, e.label ?? '')),
        children),
  };
});

import { mountUi, patchPanelPath, unmount, byTest, tick, type Mounted } from './cabling/cabling-test-kit';
import { CABLE_EDGE_COLOR } from './map-cabling-model';

const SW = 'aaaaaaaa-0000-4000-8000-000000000001';
const SRV = 'aaaaaaaa-0000-4000-8000-000000000002';
const SRV2 = 'aaaaaaaa-0000-4000-8000-000000000003';
const GI1 = 'bbbbbbbb-0000-4000-8000-000000000001';
const ETH0 = 'bbbbbbbb-0000-4000-8000-000000000002';

function edge(id: string, to: string, over: Record<string, unknown> = {}) {
  return {
    id, tenant_id: 't', from_asset_id: SW, to_asset_id: to, type: 'connects_to' as const, source_kind: 'measured' as const,
    confidence: 1, status: 'active' as const, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-09-01T00:00:00Z', observation_count: 3, ...over,
  };
}

function neighbourhood(cables: 'both' | 'none'): Neighbourhood {
  return {
    root_asset_id: SW, depth: 1, include_pending: false,
    nodes: [
      { asset_id: SW, display_name: 'sw-1', class_key: 'switch', asset_status: 'monitoring', risk_assessed: false, depth: 0, is_root: true },
      { asset_id: SRV, display_name: 'srv-9', class_key: 'server', asset_status: 'monitoring', risk_assessed: false, depth: 1, is_root: false },
      { asset_id: SRV2, display_name: 'srv-10', class_key: 'server', asset_status: 'monitoring', risk_assessed: false, depth: 1, is_root: false },
    ],
    edges: [
      edge('e-named', SRV, { from_interface_id: GI1, from_interface_name: 'Gi1/0/1', to_interface_id: ETH0, to_interface_name: 'eth0' }),
      edge('e-bare', SRV2),
    ],
    cable_paths: cables === 'none' ? [] : [
      { id: GI1, from_asset_id: SW, to_asset_id: SRV, from_interface_id: GI1, from_interface_name: 'Gi1/0/1', to_interface_id: ETH0, to_interface_name: 'eth0',
        cable_id: 'cable-1', cable_label: 'P-1', status: 'active', operational_status: 'connected', cable_count: 2, patch_panel_count: 1, circuit_count: 0 },
      { id: 'gi2', from_asset_id: SW, to_asset_id: SRV2, from_interface_id: 'gi2', from_interface_name: 'Gi1/0/2', to_interface_id: 'eth1', to_interface_name: 'eth1',
        cable_id: 'cable-2', cable_label: '', status: 'pending', operational_status: 'connected', cable_count: 1, patch_panel_count: 0, circuit_count: 0 },
    ],
    total_cable_paths: cables === 'none' ? 0 : 2,
    truncated: false, total_nodes: 3, total_edges: 2, node_cap: 500, edge_cap: 2000,
  };
}

let m: Mounted | null = null;
beforeEach(() => {
  state.nbh = neighbourhood('both');
  state.nbhLoading = false;
  state.nbhError = false;
  state.get.mockReset();
  state.get.mockImplementation((path: string) => Promise.resolve(path === '/dcim/interfaces/{id}/trace'
    ? { data: { data: { object: patchPanelPath().origin, paths: [patchPanelPath()] } } }
    : { data: { data: [] } }));
});
afterEach(() => { unmount(m); m = null; });

async function mountMap() {
  const { AssetMapView } = await import('./map-lens');
  m = await mountUi(
    <AssetMapView assetId={SW} depth={1} includePending={false} onDepthChange={() => {}} onIncludePendingChange={() => {}}
      onFocus={() => {}} fullScreen={false} onToggleFullScreen={() => {}} />,
    ['dcim.read'],
  );
  await tick(20);
}

const edgeEl = (id: string) => document.body.querySelector<HTMLButtonElement>(`[data-testid="rf-edge"][data-id="${id}"]`);
const toggle = () => byTest('map-cabling-toggle')[0] as HTMLButtonElement;
const click = (el: HTMLElement) => act(async () => { el.click(); });

describe('the neighbourhood view', () => {
  it('draws each cable run as a thick line in the cable colour, dashed while proposed, with the legend', async () => {
    await mountMap();
    expect(toggle().getAttribute('aria-pressed')).toBe('true');
    const run = edgeEl(`cable:${GI1}`)!;
    expect(run).not.toBeNull();
    expect(run.dataset.stroke).toBe(CABLE_EDGE_COLOR);
    expect(Number(run.dataset.width)).toBeGreaterThan(2);
    expect(run.dataset.dash).toBe('');
    expect(edgeEl('cable:gi2')!.dataset.dash).not.toBe('');
    // A relationship keeps its own style: thin and not the cable colour.
    expect(edgeEl('e-named')!.dataset.stroke).not.toBe(CABLE_EDGE_COLOR);
    const legend = byTest('map-cabling-legend')[0];
    expect(legend?.textContent).toContain('Cable');
    expect(legend?.textContent).toContain('Proposed cable');
  });

  it('the Physical cabling toggle hides and restores the layer', async () => {
    await mountMap();
    await click(toggle());
    expect(toggle().getAttribute('aria-pressed')).toBe('false');
    expect(edgeEl(`cable:${GI1}`)).toBeNull();
    expect(edgeEl('e-named')).not.toBeNull();
    expect(byTest('map-cabling-legend')).toHaveLength(0);
    await click(toggle());
    expect(edgeEl(`cable:${GI1}`)).not.toBeNull();
  });

  it('with no cable runs the layer is off and the toggle disabled, saying why', async () => {
    state.nbh = neighbourhood('none');
    await mountMap();
    expect(toggle().disabled).toBe(true);
    expect(toggle().getAttribute('aria-pressed')).toBe('false');
    expect(toggle().title).toContain('No cables run between');
    expect(document.body.querySelectorAll('[data-testid="rf-edge"][data-id^="cable:"]')).toHaveLength(0);
  });

  it('while loading and on error the toggle is disabled', async () => {
    state.nbhLoading = true;
    await mountMap();
    expect(byTest('map-loading')).toHaveLength(1);
    expect(toggle().disabled).toBe(true);
    unmount(m); m = null;
    state.nbhLoading = false;
    state.nbhError = true;
    await mountMap();
    expect(byTest('map-error')).toHaveLength(1);
    expect(toggle().disabled).toBe(true);
  });

  it('a relationship with a known interface offers "Show physical path", which opens the trace', async () => {
    await mountMap();
    await click(edgeEl('e-named')!);
    const item = byTest('map-show-physical-path')[0] as HTMLButtonElement;
    expect(item).toBeDefined();
    expect(item.disabled).toBe(false);
    expect(item.textContent).toContain('Gi1/0/1');
    await click(item);
    await tick(20);
    expect(byTest('map-edge-menu')).toHaveLength(0);
    expect(byTest('map-trace')).toHaveLength(1);
    expect(state.get.mock.calls.some(([p, o]) => p === '/dcim/interfaces/{id}/trace' && (o as { params: { path: { id: string } } }).params.path.id === GI1)).toBe(true);
    expect(byTest('trace-diagram')).toHaveLength(1);
  });

  it('a relationship with no interface has the action disabled, with the reason', async () => {
    await mountMap();
    await click(edgeEl('e-bare')!);
    const item = byTest('map-show-physical-path')[0] as HTMLButtonElement;
    expect(item.disabled).toBe(true);
    expect(byTest('map-physical-path-reason')[0]?.textContent).toContain('No interface is known');
    await click(item);
    expect(byTest('map-trace')).toHaveLength(0);
  });

  it('clicking a cable opens its trace with a link to the cable', async () => {
    await mountMap();
    await click(edgeEl(`cable:${GI1}`)!);
    await tick(20);
    expect(byTest('map-edge-menu')).toHaveLength(0);
    expect(byTest('map-trace')).toHaveLength(1);
    expect(byTest('map-trace-open-cable')[0]?.getAttribute('href')).toBe('/inventory/cables/cable-1');
  });

  it('the side panel offers the same action per relationship (the keyboard route)', async () => {
    await mountMap();
    await click(document.body.querySelector<HTMLElement>(`[data-testid="rf-node"][data-id="${SW}"]`)!);
    const buttons = byTest('map-panel-physical-path') as HTMLButtonElement[];
    expect(buttons).toHaveLength(2);
    expect(buttons.filter((b) => b.disabled)).toHaveLength(1);
    await click(buttons.find((b) => !b.disabled)!);
    await tick(20);
    expect(byTest('map-trace')).toHaveLength(1);
  });
});

describe('the topology view', () => {
  function topology(cables: TopologyPayload['cable_paths']): TopologyPayload {
    return {
      sites: [{ site: 'DC-1', asset_count: 3, prefixes: [{ prefix_id: 'p1', prefix_name: '10.0.0.0/24', asset_count: 3, classes: [{ class_key: 'server', class_path: 'hardware.computer.server', asset_count: 3 }] }] }],
      clouds: [], edges: [], total_assets: 3, unassigned_assets: 0, total_nodes: 1, total_edges: 0,
      truncated: false, node_cap: 2000, edge_cap: 500,
      cable_paths: cables, total_cable_paths: cables?.length ?? 0,
    };
  }
  async function mountTopology() {
    const { TopologyView } = await import('./topology-view');
    m = await mountUi(<TopologyView />, ['dcim.read']);
    await tick(10);
  }
  const ttoggle = () => byTest('topology-cabling-toggle')[0] as HTMLButtonElement;

  it('lists cable runs between prefixes in the cable style, and the toggle hides them', async () => {
    state.topology = topology([
      { from_prefix_id: 'p1', from_prefix_name: '10.0.0.0/24', to_prefix_id: null, to_prefix_name: 'No prefix', count: 3, pending_count: 1 },
      { from_prefix_id: 'p1', from_prefix_name: '10.0.0.0/24', to_prefix_id: 'p2', to_prefix_name: '10.0.1.0/24', count: 1, pending_count: 1 },
    ]);
    await mountTopology();
    expect(ttoggle().getAttribute('aria-pressed')).toBe('true');
    const rows = byTest('topology-cable-path');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('3 (1 proposed)');
    expect(rows[0].style.borderLeft).toContain('solid');
    expect(rows[1].dataset.proposed).toBe('true');
    expect(rows[1].style.borderLeft).toContain('dashed');
    await click(ttoggle());
    expect(byTest('topology-cable-path')).toHaveLength(0);
  });

  it('with no cable runs the toggle is disabled', async () => {
    state.topology = topology([]);
    await mountTopology();
    expect(ttoggle().disabled).toBe(true);
    expect(byTest('topology-cable-paths')).toHaveLength(0);
  });
});
