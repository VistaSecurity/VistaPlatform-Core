// @vitest-environment jsdom
//
// Selecting a node must cost O(changed), not O(nodes).
//
// `rfNodes` used to put `selected` inside every node's `data`, so one click
// built a new data object for all of the (up to 500) nodes and re-rendered every
// memoised AssetNode. The fix hands xyflow its own `selected` flag on just the
// previous and the new node. This drives the real renderer and counts AssetNode
// renders through the one thing each render creates exactly once per box: its
// target Handle.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import type { Neighbourhood } from './relationships';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

class StubResizeObserver {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal('ResizeObserver', StubResizeObserver);
vi.stubGlobal('DOMMatrixReadOnly', class { m22 = 1; constructor(_?: string) {} });

const renders = vi.hoisted(() => ({ assetNode: 0 }));

vi.mock('@xyflow/react', async (importOriginal) => {
  const real = await importOriginal<typeof import('@xyflow/react')>();
  const React = await import('react');
  return {
    ...real,
    // One target Handle per AssetNode render. Its style prop is a fresh object
    // each time, so it re-runs exactly when the node component does.
    Handle: (props: React.ComponentProps<typeof real.Handle>) => {
      if (props.type === 'target') renders.assetNode += 1;
      return React.createElement(real.Handle, props);
    },
  };
});

const COUNT = 60;
// previous + new node, allowing xyflow's own select-change round trip to render
// each of them twice. The point is a constant that does not grow with COUNT.
const MAX_RENDERS = 4;
const id = (i: number): string => `aaaaaaaa-0000-4000-8000-${String(i).padStart(12, '0')}`;

const NEIGHBOURHOOD: Neighbourhood = {
  root_asset_id: id(0),
  depth: 2,
  include_pending: false,
  nodes: Array.from({ length: COUNT }, (_, i) => ({
    asset_id: id(i), display_name: `host-${i}`, class_key: 'server', asset_status: 'monitoring', depth: i === 0 ? 0 : 1, is_root: i === 0,
  })),
  edges: Array.from({ length: COUNT - 1 }, (_, i) => ({
    id: `e${i}`, tenant_id: 't', from_asset_id: id(0), to_asset_id: id(i + 1), type: 'runs_on', source_kind: 'measured',
    confidence: 0.9, status: 'active', first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-09-01T00:00:00Z', observation_count: 1,
  })),
  truncated: false,
  total_nodes: COUNT,
  total_edges: COUNT - 1,
  node_cap: 500,
  edge_cap: 2000,
};

vi.mock('./relationship-queries', () => ({
  useAssetNeighbourhood: () => ({ data: NEIGHBOURHOOD, isLoading: false, isError: false, error: null, refetch: () => {} }),
  useAssetImpact: () => ({ data: undefined, isLoading: false, isError: false, error: null }),
}));
vi.mock('./asset-queries', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useAssetsQuery: () => ({ data: { assets: [] }, isLoading: false, isError: false, error: null }),
}));

let host: HTMLDivElement;
let root: Root;

beforeAll(async () => {
  await import('./map-lens');
}, 60_000);
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

const nodeEl = (i: number): HTMLElement => host.querySelector(`.react-flow__node[data-id="${id(i)}"]`) as HTMLElement;

it('re-renders only the previously and newly selected node when the selection moves', async () => {
  const { AssetMapView } = await import('./map-lens');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AssetMapView assetId={id(0)} depth={2} includePending={false} onDepthChange={() => {}}
            onIncludePendingChange={() => {}} onFocus={() => {}} fullScreen={false} onToggleFullScreen={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  expect(host.querySelectorAll('[data-testid="map-node"]')).toHaveLength(COUNT);

  const click = async (i: number) => {
    await act(async () => { nodeEl(i).click(); });
  };

  let before = renders.assetNode;
  await click(5);
  // The click really selected it (the side panel opens) — otherwise "0 renders"
  // would pass vacuously.
  expect(host.querySelector('[data-testid="map-node-panel"]')).not.toBeNull();
  expect(renders.assetNode - before).toBeLessThanOrEqual(MAX_RENDERS);

  before = renders.assetNode;
  await click(9);
  const moved = renders.assetNode - before;
  expect(moved).toBeGreaterThanOrEqual(1);
  expect(moved).toBeLessThanOrEqual(MAX_RENDERS);
});
