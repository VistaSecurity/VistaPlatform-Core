// @vitest-environment jsdom
//
// The WIRING for the map's cloud scope boxes ( slice D).
//
// `map-cloud-scope.test.ts` pins what `withCloudScopeRoots` decides. That is
// the easy half, and on its own it is the trap CLAUDE.md names twice: a helper
// with perfect tests and no call site. Delete the `withCloudScopeRoots(...)`
// call in `map-lens.tsx` and every one of those 27 assertions stays green while
// the map goes back to drawing two unrooted VPCs.
//
// So this drives the REAL renderer through the REAL hook and looks for the
// boxes on the canvas: an account box, a region box, both labelled with what
// they are, and a legend that lists them as scaffolding rather than folding
// them into the cloud-resource count.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Neighbourhood } from './relationships';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// React Flow measures. jsdom does not, and a missing ResizeObserver throws
// during mount rather than degrading.
class StubResizeObserver {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal('ResizeObserver', StubResizeObserver);
vi.stubGlobal('DOMMatrixReadOnly', class { m22 = 1; constructor(_?: string) {} });

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';
const VPC = 'aaaaaaaa-0000-4000-8000-000000000001';
const BUCKET = 'aaaaaaaa-0000-4000-8000-000000000004';

const NEIGHBOURHOOD: Neighbourhood = {
  root_asset_id: VPC,
  depth: 2,
  include_pending: false,
  nodes: [
    { asset_id: VPC, display_name: 'vpc-prod', class_key: 'virtual_network', asset_status: 'monitoring', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
    { asset_id: BUCKET, display_name: 'assets-bucket', class_key: 'object_storage', asset_status: 'monitoring', depth: 1, cloud_account: ACCOUNT, cloud_region: REGION },
  ],
  // No stored relationship at all: the bucket is exactly the "isolated node"
  // this slice exists to place.
  edges: [],
  truncated: false,
  total_nodes: 2,
  total_edges: 0,
  node_cap: 500,
  edge_cap: 2000,
};

vi.mock('./relationship-queries', () => ({
  useAssetNeighbourhood: () => ({ data: NEIGHBOURHOOD, isLoading: false, isError: false, error: null, refetch: () => {} }),
  useAssetImpact: () => ({ data: undefined, isLoading: false, isError: false, error: null }),
}));

// The picker runs its own asset query; it is not what this test is about.
vi.mock('./asset-queries', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useAssetsQuery: () => ({ data: { assets: [] }, isLoading: false, isError: false, error: null }),
}));

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

async function render(): Promise<void> {
  const { AssetMapView } = await import('./map-lens');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AssetMapView
            assetId={VPC}
            depth={2}
            includePending={false}
            onDepthChange={() => {}}
            onIncludePendingChange={() => {}}
            onFocus={() => {}}
            fullScreen={false}
            onToggleFullScreen={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
}

const groups = (): string[] =>
  [...host.querySelectorAll('[data-testid="map-node"]')].map((el) => el.getAttribute('data-group') ?? '');

it('draws the account and region boxes the model synthesised', async () => {
  await render();
  const drawn = groups();
  expect(drawn).toContain('cloud_account');
  expect(drawn).toContain('cloud_region');
  // And the assets are still there — the boxes are additional, not a
  // replacement.
  expect(drawn.filter((g) => g === 'cloud_resource')).toHaveLength(2);
});

it('labels the boxes with the account and the region, not with a uuid', async () => {
  // React Flow draws its EDGES only once it has measured the nodes, which jsdom
  // never does — so this asserts the boxes reached the canvas with the content
  // that makes them useful, and the edge set itself is pinned on the model in
  // map-cloud-scope.test.ts.
  await render();
  const boxes = [...host.querySelectorAll('[data-testid="map-node"]')]
    .filter((el) => (el.getAttribute('data-group') ?? '').startsWith('cloud_') && el.getAttribute('data-group') !== 'cloud_resource')
    .map((el) => el.textContent ?? '');
  expect(boxes.some((t) => t.includes(ACCOUNT))).toBe(true);
  expect(boxes.some((t) => t.includes(REGION))).toBe(true);
  // Two assets plus the two boxes.
  expect(host.querySelectorAll('[data-testid="map-node"]')).toHaveLength(4);
});

it('shows the scope kinds in the legend rather than counting them as assets', async () => {
  await render();
  const legend = host.querySelector('[data-testid="map-legend"]')?.textContent ?? '';
  expect(legend).toContain('Cloud account');
  expect(legend).toContain('Cloud region');
  // Two cloud resources, not five: the boxes must not inflate the class count.
  expect(legend).toMatch(/Cloud resource\s*2/);
});
