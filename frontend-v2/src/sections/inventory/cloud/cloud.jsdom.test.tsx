// @vitest-environment jsdom
//
// Inventory → Cloud (asset-inventory ADR-0009 D7; DCIM row 4.6): the Placement
// breadcrumb in all five states, its wiring onto the asset page for a cloud
// resource (and not for anything else), and the Cloud lens's scope, facets and
// Account grouping — over a faked inventory client.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { CloudPlacementSection } from './cloud-placement';
import { CloudLens } from './cloud-lens';
import { AssetPage } from '../asset-page';
import { TopologyView } from '../topology-view';

const ID = '11111111-1111-4111-8111-111111111111';
const ACC = '33333333-3333-4333-8333-333333333333';
const SG = '44444444-4444-4444-8444-444444444444';
const PLACEMENT = {
  asset_id: ID, class_key: 'compute_instance', provider: 'aws', provider_type: 'AWS::EC2::Instance',
  account_id: '123456789012', account_asset_id: ACC, account_name: 'prod', region: 'us-east-1',
  network: { prefix_id: 'p-net', prefix: '10.0.0.0/16' }, prefix: { prefix_id: 'p-sub', prefix: '10.0.1.0/24' },
  security_groups: [{ asset_id: SG, id: 'arn:sg-01', name: 'web' }, { asset_id: null, id: 'sg-02', name: 'db' }],
};

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  mocks.get.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

function answer(routes: Record<string, (init?: unknown) => unknown>) {
  mocks.get.mockImplementation(async (path: string, init?: unknown) => {
    const fn = routes[path];
    return fn ? fn(init) : { data: {} };
  });
}

async function mount(ui: React.ReactNode, path = '/') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], ['assets.read']);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/" element={ui} />
              <Route path="/inventory/assets/:id/:tab?" element={<AssetPage />} />
            </Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
}
const text = () => host.textContent ?? '';
const byTest = (id: string) => host.querySelector(`[data-testid="${id}"]`);

describe('<CloudPlacementSection>', () => {
  it('success: account › region › network prefix › child prefix, the provider type and the groups', async () => {
    answer({ '/infrastructure-assets/{id}/cloud-placement': () => ({ data: { placement: PLACEMENT } }) });
    await mount(<CloudPlacementSection assetId={ID} />);
    await vi.waitFor(() => expect(byTest('placement-breadcrumb')).not.toBeNull());
    const steps = [...host.querySelectorAll('[data-step]')].map((e) => `${e.getAttribute('data-step')}:${e.textContent}`);
    expect(steps).toEqual(['account:prod', 'region:us-east-1', 'network:10.0.0.0/16', 'prefix:10.0.1.0/24']);
    expect(host.querySelector('[data-step="account"]')?.getAttribute('href')).toBe(`/inventory/assets/${ACC}`);
    expect(text()).toContain('AWS::EC2::Instance');
    // The group that is an asset links to it; the one known only from the
    // membership fact is shown, not linked.
    expect(host.querySelector(`[data-testid="placement-groups"] a[href="/inventory/assets/${SG}"]`)?.textContent).toBe('web');
    expect(text()).toContain('db');
  });

  it('default for a resource with no network: the prefix steps are absent, not blank', async () => {
    answer({ '/infrastructure-assets/{id}/cloud-placement': () => ({ data: { placement: { ...PLACEMENT, network: null, prefix: null, security_groups: [] } } }) });
    await mount(<CloudPlacementSection assetId={ID} />);
    await vi.waitFor(() => expect(byTest('placement-breadcrumb')).not.toBeNull());
    expect([...host.querySelectorAll('[data-step]')].map((e) => e.getAttribute('data-step'))).toEqual(['account', 'region']);
    expect(text()).toContain('Member of none that were listed.');
  });

  it('empty: nothing recorded says so', async () => {
    answer({ '/infrastructure-assets/{id}/cloud-placement': () => ({ data: { placement: { ...PLACEMENT, account_id: '', account_asset_id: null, region: '', network: null, prefix: null, security_groups: [] } } }) });
    await mount(<CloudPlacementSection assetId={ID} />);
    await vi.waitFor(() => expect(byTest('placement-empty')).not.toBeNull());
  });

  it('loading', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<CloudPlacementSection assetId={ID} />);
    expect(byTest('placement-loading')).not.toBeNull();
  });

  it('error', async () => {
    answer({ '/infrastructure-assets/{id}/cloud-placement': () => ({ error: { error: 'boom' } }) });
    await mount(<CloudPlacementSection assetId={ID} />);
    await vi.waitFor(() => expect(byTest('placement-error')).not.toBeNull());
  });
});

// MUTATION-VERIFIED: remove the Placement block from asset-page.tsx and the
// first case goes red.
describe('asset page wiring', () => {
  const base = { id: ID, hostname: 'i-01', display_name: 'web-01', asset_status: 'monitoring', risk_score: 0, deleted_at: null };
  it('a cloud resource shows Placement', async () => {
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: { ...base, class_key: 'compute_instance', class_path: 'cloud_resource.compute_instance' } } }),
      '/infrastructure-assets/{id}/cloud-placement': () => ({ data: { placement: PLACEMENT } }),
    });
    await mount(null, `/inventory/assets/${ID}`);
    await vi.waitFor(() => expect(byTest('placement-breadcrumb')).not.toBeNull());
    expect(text()).toContain('Placement');
  });
  it('anything else does not ask for one', async () => {
    answer({ '/infrastructure-assets/{id}': () => ({ data: { asset: { ...base, class_key: 'server', class_path: 'hardware.computer.server' } } }) });
    await mount(null, `/inventory/assets/${ID}`);
    await vi.waitFor(() => expect(text()).toContain('web-01'));
    expect(mocks.get.mock.calls.some(([p]) => p === '/infrastructure-assets/{id}/cloud-placement')).toBe(false);
  });
});

describe('<CloudLens>', () => {
  const asset = (id: string, account: string, region: string) => ({
    id, hostname: id, display_name: id, class_key: 'compute_instance', class_path: 'cloud_resource.compute_instance',
    asset_status: 'monitoring', risk_score: 0, deleted_at: null,
    attributes: { provider: 'aws', account_id: account, region, provider_type: 'AWS::EC2::Instance' }, tags: {},
  });
  const listed = (rows: unknown[]) => ({ data: { assets: rows, pagination: { total: rows.length, page: 1, page_size: 50 } } });

  it('scopes to cloud resources, facets by provider, and groups by account', async () => {
    const queries: string[] = [];
    answer({
      '/infrastructure-assets': (init) => {
        queries.push(((init as { params: { query: { query?: string } } }).params.query.query) ?? '');
        return listed([asset('a1', '111', 'us-east-1'), asset('a2', '222', 'eu-west-1'), asset('a3', '111', 'us-east-1')]);
      },
      '/infrastructure-assets/facets': (init) => {
        const level = (init as { params: { query: { level: string } } }).params.query.level;
        return { data: { level, buckets: level === 'cloud_provider' ? [{ value: 'aws', count: 3 }] : [] } };
      },
    });
    let q = '';
    await mount(<CloudLens query={q} onQueryChange={(v) => { q = v; }} page={1} onPageChange={() => {}} onOpenAsset={() => {}} />);
    await vi.waitFor(() => expect(host.querySelectorAll('[data-testid="cloud-row"]')).toHaveLength(3));
    expect(queries[0]).toBe('class:cloud_resource');

    // A facet click writes its term into the query.
    const aws = [...host.querySelectorAll('[data-testid="cloud-facet-cloud_provider"] button')].find((b) => b.textContent?.includes('aws')) as HTMLButtonElement;
    await act(async () => { aws.click(); });
    expect(q).toBe('provider:aws');

    // Account grouping: two accounts on this page.
    const toggle = byTest('cloud-group-by-account') as HTMLInputElement;
    await act(async () => { toggle.click(); });
    expect(host.querySelectorAll('[data-testid="cloud-account-group"]')).toHaveLength(2);
  });

  it('empty, loading and error', async () => {
    answer({ '/infrastructure-assets': () => listed([]), '/infrastructure-assets/facets': () => ({ data: { buckets: [] } }) });
    await mount(<CloudLens query="" onQueryChange={() => {}} page={1} onPageChange={() => {}} onOpenAsset={() => {}} />);
    await vi.waitFor(() => expect(byTest('cloud-empty')).not.toBeNull());

    act(() => root.unmount());
    root = createRoot(host);
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<CloudLens query="" onQueryChange={() => {}} page={1} onPageChange={() => {}} onOpenAsset={() => {}} />);
    expect(byTest('cloud-loading')).not.toBeNull();

    act(() => root.unmount());
    root = createRoot(host);
    answer({ '/infrastructure-assets': () => ({ error: { error: 'boom' } }), '/infrastructure-assets/facets': () => ({ data: { buckets: [] } }) });
    await mount(<CloudLens query="" onQueryChange={() => {}} page={1} onPageChange={() => {}} onOpenAsset={() => {}} />);
    await vi.waitFor(() => expect(byTest('cloud-error')).not.toBeNull());
  });
});

// ADR-0009 D7: the map's topology view gains the cloud hierarchy — account →
// region → prefix → class — and a region's counts drill into the Cloud lens
// scoped to that account and region.
describe('topology cloud hierarchy', () => {
  it('draws account → region → prefix, scoped drill-throughs', async () => {
    answer({
      '/infrastructure-assets/topology': () => ({ data: { topology: {
        sites: [{ site: 'Unassigned', asset_count: 3, prefixes: [] }], edges: [],
        clouds: [{ provider: 'aws', account_id: '123456789012', account_asset_id: ACC, account_name: 'prod', asset_count: 3,
          regions: [{ region: 'us-east-1', asset_count: 3, prefixes: [{ prefix_id: null, prefix_name: 'No prefix', asset_count: 3,
            classes: [{ class_key: 'object_storage', class_path: 'cloud_resource.object_storage', asset_count: 3 }] }] }] }],
        total_assets: 3, unassigned_assets: 3, total_nodes: 1, total_edges: 0, truncated: false, node_cap: 2000, edge_cap: 500,
      } } }),
    });
    await mount(<TopologyView />);
    await vi.waitFor(() => expect(byTest('topology-cloud-account')).not.toBeNull());
    expect(text()).toContain('prod');
    const region = host.querySelector('[data-testid="topology-cloud-region"] a') as HTMLAnchorElement;
    expect(decodeURIComponent(region.getAttribute('href') ?? '')).toBe('/inventory?lens=cloud&query=class:cloud_resource and account:123456789012 and region:us-east-1');
    // The region's "No prefix" bucket opens that region's prefix-less
    // resources, not every prefix-less asset in the estate.
    const bucket = [...host.querySelectorAll('[data-testid="topology-cloud-region"] [data-testid="topology-prefix"] a')][0];
    expect(decodeURIComponent(bucket.getAttribute('href') ?? '')).toContain('account:123456789012 and region:us-east-1 and not exists(prefix_id)');
  });
});
