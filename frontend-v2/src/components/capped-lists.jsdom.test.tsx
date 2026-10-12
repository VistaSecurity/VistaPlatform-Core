// @vitest-environment jsdom
//
// Capped lists say so: the Command Center "Pending approvals" tile, the asset
// drawer's configurations and the remediation plan's finding picker.
//
// MUTATIONS (recorded in the PR):
//   - tile reads `assets.length` instead of `total`: the tile test fails;
//   - drop <ShownOfNotice> from the asset drawer / plan picker: the matching
//     test fails.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock('../lib/clients', () => ({ clients: { inventory: api, compliance: api, devices: api, sensors: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  TENANT_PERMISSIONS: new Proxy({}, { get: () => new Proxy({}, { get: (_t, k) => String(k) }) }),
  usePermissions: () => ({ can: () => true }),
}));

const { CommandCenterPage } = await import('../sections/discovery/command-center');
const { AssetDrawer } = await import('../sections/inventory/drawers');
const { PlanDetailDrawer } = await import('../sections/remediation/plan-detail');
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset();
  qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

const ok = (data: unknown) => ({ data, response: { ok: true, status: 200 } });
async function render(el: React.ReactNode) {
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={qc}>{el}</QueryClientProvider></MemoryRouter>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 40)); });
}

it('Command Center tile shows the total pending count, not the first page length', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/infrastructure-assets') {
      return ok({ assets: [{ id: 'a1' }], pagination: { total: 4321, page: 1, page_size: 100 } });
    }
    return ok({});
  });
  await render(<CommandCenterPage />);
  expect(host.textContent).toContain('Pending approvals');
  expect(host.textContent).toContain('4321');
});

it('asset drawer notes when configurations are truncated', async () => {
  // Rows need real shape to render, so pad with the minimum; the notice keys
  // off the counts, so 100 stub rows are enough.
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/crypto-configurations') {
      const rows = Array.from({ length: 100 }, (_, i) => ({ id: `c${i}`, asset_id: 'x' }));
      return ok({ crypto_implementations: rows, pagination: { total: 340, page: 1, page_size: 100 } });
    }
    return ok({ asset: { id: 'x' } });
  });
  await render(<AssetDrawer assetId="x" onOpenConfig={() => {}} onClose={() => {}} />);
  const note = host.querySelector('[data-testid="shown-of-notice"]');
  expect(note?.textContent).toBe('Showing 100 of 340 configurations.');
  expect(host.textContent).toContain('Cryptographic configurations (340)');
});

it('plan finding picker notes when the findings list is truncated', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/findings') {
      const rows = Array.from({ length: 200 }, (_, i) => ({ id: `f${i}`, severity: 'high', summary: `s${i}` }));
      return ok({ findings: rows, total: 777 });
    }
    if (path === '/plans/{id}/items') return ok({ items: [] });
    return ok({ plan: { id: 'p1', status: 'draft' } });
  });
  await render(<PlanDetailDrawer plan={{ id: 'p1', title: 'P', status: 'draft' } as never} onClose={() => {}} />);
  expect(host.querySelector('[data-testid="shown-of-notice"]')).toBeNull();
  const add = [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Add finding'))!;
  await act(async () => { add.click(); });
  await act(async () => { await new Promise((r) => setTimeout(r, 40)); });
  expect(host.querySelector('[data-testid="shown-of-notice"]')?.textContent).toContain('Showing 200 of 777 findings');
});
