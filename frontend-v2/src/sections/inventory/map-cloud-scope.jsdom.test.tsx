// @vitest-environment jsdom
//
// The WIRING for the map's cloud region boxes ( slice D, amended by
// asset-inventory ADR-0009 D1: the account is a real asset with stored
// `hosted_on` edges, so no account box is synthesised).
//
// `map-cloud-scope.test.ts` pins what `withCloudScopeRoots` decides. That is
// the easy half, and on its own it is the trap CLAUDE.md names twice: a helper
// with perfect tests and no call site. Delete the `withCloudScopeRoots(...)`
// call in `map-lens.tsx` and every one of those 27 assertions stays green while
// the map goes back to drawing two unrooted load balancers.
//
// So this drives the REAL renderer through the REAL hook and looks for the
// box on the canvas: a region box labelled with what it is, the account drawn
// as the asset it is, and a legend that lists the region as scaffolding rather
// than folding it into the cloud-resource count.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
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
const LB = 'aaaaaaaa-0000-4000-8000-000000000001';
const BUCKET = 'aaaaaaaa-0000-4000-8000-000000000004';
const ACCOUNT_ASSET = 'aaaaaaaa-0000-4000-8000-000000000007';

const NEIGHBOURHOOD: Neighbourhood = {
  root_asset_id: LB,
  depth: 2,
  include_pending: false,
  nodes: [
    { asset_id: LB, display_name: 'lb-front', class_key: 'cloud_load_balancer', asset_status: 'monitoring', depth: 0, is_root: true, cloud_account: ACCOUNT, cloud_region: REGION },
    { asset_id: BUCKET, display_name: 'assets-bucket', class_key: 'object_storage', asset_status: 'monitoring', depth: 1, cloud_account: ACCOUNT, cloud_region: REGION },
    { asset_id: ACCOUNT_ASSET, display_name: `AWS account ${ACCOUNT}`, class_key: 'cloud_account', asset_status: 'monitoring', depth: 1, cloud_account: ACCOUNT },
  ],
  // The stored hosted_on edges are the account's whole connection to its
  // resources now.
  edges: [
    { id: 'h-lb', tenant_id: 't', from_asset_id: LB, to_asset_id: ACCOUNT_ASSET, type: 'hosted_on', source_kind: 'measured', confidence: 1, status: 'active', first_seen_at: '2026-10-15T00:00:00Z', last_seen_at: '2026-10-15T00:00:00Z', observation_count: 1 },
    { id: 'h-bucket', tenant_id: 't', from_asset_id: BUCKET, to_asset_id: ACCOUNT_ASSET, type: 'hosted_on', source_kind: 'measured', confidence: 1, status: 'active', first_seen_at: '2026-10-15T00:00:00Z', last_seen_at: '2026-10-15T00:00:00Z', observation_count: 1 },
  ],
  truncated: false,
  total_nodes: 3,
  total_edges: 2,
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

// `map-lens` pulls in React Flow, the heaviest module graph this suite loads.
// Import it once up front, under a generous hook timeout, so the first test is
// not billed for the module load: on a loaded CI runner that load alone ran
// past the 5s per-test default while the assertions themselves take milliseconds.
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

async function render(): Promise<void> {
  const { AssetMapView } = await import('./map-lens');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AssetMapView
            assetId={LB}
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

it('draws the region box the model synthesised, and the account as an asset', async () => {
  await render();
  const drawn = groups();
  expect(drawn).toContain('cloud_region');
  // No synthetic account box: the account is the cloud_account ASSET.
  expect(drawn).not.toContain('cloud_account');
  // Load balancer, bucket and the account asset — all cloud resources.
  expect(drawn.filter((g) => g === 'cloud_resource')).toHaveLength(3);
});

it('labels the boxes with the account and the region, not with a uuid', async () => {
  // React Flow draws its EDGES only once it has measured the nodes, which jsdom
  // never does — so this asserts the boxes reached the canvas with the content
  // that makes them useful, and the edge set itself is pinned on the model in
  // map-cloud-scope.test.ts.
  await render();
  const boxes = [...host.querySelectorAll('[data-testid="map-node"]')]
    .filter((el) => el.getAttribute('data-group') === 'cloud_region')
    .map((el) => el.textContent ?? '');
  expect(boxes.some((t) => t.includes(REGION) && t.includes(ACCOUNT))).toBe(true);
  // Three assets plus the one region box.
  expect(host.querySelectorAll('[data-testid="map-node"]')).toHaveLength(4);
});

it('shows the scope kinds in the legend rather than counting them as assets', async () => {
  await render();
  const legend = host.querySelector('[data-testid="map-legend"]')?.textContent ?? '';
  expect(legend).toContain('Cloud region');
  // Three cloud resources (the account is one), not four: the box must not
  // inflate the class count.
  expect(legend).toMatch(/Cloud resource\s*3/);
});
