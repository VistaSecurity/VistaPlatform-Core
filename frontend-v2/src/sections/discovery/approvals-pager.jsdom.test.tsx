// @vitest-environment jsdom
//
// Discovery → Approvals pages the pending ASSETS server-side and the Command
// Center tile shows the tenant's whole pending count, not the first page's length.
//
// MUTATIONS (recorded in the PR):
//   - send `page: 1` regardless of the pager state: the "Next requests page 2"
//     test fails (and so does the page-2 row assertion);
//   - make the tile read `assets.length` instead of `total`: the tile test fails.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api, devices: api, sensors: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  TENANT_PERMISSIONS: new Proxy({}, { get: () => new Proxy({}, { get: (_t, k) => String(k) }) }),
}));

const { ApprovalsPage } = await import('./approvals-page');
const { usePendingAssets } = await import('./queries');
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ok = (data: unknown) => ({ data, response: { ok: true, status: 200 } });
const asset = (n: number) => ({
  id: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, hostname: `host-${n}`, display_name: `host-${n}`,
  asset_status: 'pending_approval', discovery_method: 'sensor',
});

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset().mockImplementation(async (path: string, o?: { params?: { query?: { page?: number } } }) => {
    switch (path) {
      case '/infrastructure-assets': {
        const page = o?.params?.query?.page ?? 1;
        return ok({ assets: [asset(page * 1000)], pagination: { total: 250, page, page_size: 100 } });
      }
      case '/approvals/merge-proposals': return ok({ merge_proposals: [], total: 0 });
      case '/approvals/relationships': return ok({ relationship_proposals: [], total: 0 });
      case '/approvals/classes': return ok({ class_proposals: [], total: 0 });
      case '/approvals/merge-proposals/auto-accepted': return ok({ merges: [], window_days: 30 });
      default: throw new Error(`unmocked GET ${path}`);
    }
  });
  qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

const settle = async () => { await act(async () => { await new Promise((r) => setTimeout(r, 30)); }); };
const assetPages = () => api.GET.mock.calls
  .filter((c) => c[0] === '/infrastructure-assets')
  .map((c) => (c[1] as { params: { query: { page: number } } }).params.query.page);

it('Next on the Approvals asset pager requests page 2 and shows the range', async () => {
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={qc}><ApprovalsPage /></QueryClientProvider></MemoryRouter>);
  });
  await settle();
  expect(assetPages()).toEqual([1]);
  expect(host.querySelector('[data-testid="asset-page-range"]')!.textContent).toBe('1–1 of 250');
  expect(host.textContent).toContain('Discovered assets (250)');

  await act(async () => { host.querySelector<HTMLButtonElement>('[data-testid="asset-page-next"]')!.click(); });
  await settle();
  expect(assetPages()).toContain(2);
  expect(host.textContent).toContain('host-2000');
  expect(host.querySelector('[data-testid="asset-page-range"]')!.textContent).toBe('101–101 of 250');
});

it('hides the pager when everything fits on one page', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/infrastructure-assets') return ok({ assets: [asset(1)], pagination: { total: 1, page: 1, page_size: 100 } });
    if (path === '/approvals/merge-proposals/auto-accepted') return ok({ merges: [], window_days: 30 });
    return ok({ merge_proposals: [], relationship_proposals: [], class_proposals: [], total: 0 });
  });
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={qc}><ApprovalsPage /></QueryClientProvider></MemoryRouter>);
  });
  await settle();
  expect(host.querySelector('[data-testid="asset-page-next"]')).toBeNull();
});

it('usePendingAssets reports the tenant total, not the page length', async () => {
  let seen: { total: number; n: number } | undefined;
  function Probe() {
    const d = usePendingAssets().data;
    if (d) seen = { total: d.total, n: d.assets.length };
    return null;
  }
  await act(async () => { root.render(<QueryClientProvider client={qc}><Probe /></QueryClientProvider>); });
  await settle();
  expect(seen).toEqual({ total: 250, n: 1 });
});
