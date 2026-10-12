// @vitest-environment jsdom
//
// The crypto-risk stream is fetched only where it is rendered, and its pages
// 2..N go out together.
//
// MUTATIONS (recorded in the PR):
//   - drop `enabled` from useCryptoRisks (or pass `true` from the page): the
//     "findings lens" and "disabled hook" tests fail, because /crypto-risks is
//     requested on a lens that never reads it;
//   - fetch pages 2..N sequentially again: the "in flight together" test fails,
//     because page 3 is never requested while page 2 is still pending.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api, compliance: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/auth', () => ({ useAuth: () => ({ user: { id: 'u1' } }) }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  TENANT_PERMISSIONS: new Proxy({}, { get: () => new Proxy({}, { get: (_t, k) => String(k) }) }),
  usePermissions: () => ({ can: () => true }),
}));

import { RISK_PAGE_SIZE, useCryptoRisks } from './queries';
const { FindingsPage } = await import('./findings-page');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset();
  qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

const riskCalls = () => api.GET.mock.calls.filter((c) => c[0] === '/crypto-risks');
const pagesRequested = () =>
  riskCalls().map((c) => (c[1] as { params: { query: { page: number } } }).params.query.page);
const flush = async () => { await act(async () => { await new Promise((r) => setTimeout(r, 20)); }); };

function Probe({ enabled }: { enabled: boolean }) {
  useCryptoRisks(enabled);
  return null;
}
const wrap = (el: React.ReactNode) => <MemoryRouter><QueryClientProvider client={qc}>{el}</QueryClientProvider></MemoryRouter>;

describe('useCryptoRisks', () => {
  it('requests nothing while disabled', async () => {
    api.GET.mockResolvedValue({ data: { risks: [], total: 0, total_pages: 1 } });
    await act(async () => { root.render(wrap(<Probe enabled={false} />)); });
    await flush();
    expect(riskCalls()).toHaveLength(0);
  });

  it('requests pages 2..N together once page 1 has revealed the total', async () => {
    const pending = new Map<number, (v: unknown) => void>();
    api.GET.mockImplementation((_p: string, o: { params: { query: { page: number } } }) => {
      const page = o.params.query.page;
      const body = { data: { risks: [], total: 450, total_pages: 5, page, page_size: RISK_PAGE_SIZE } };
      if (page === 1) return Promise.resolve(body);
      return new Promise((resolve) => { pending.set(page, () => resolve(body)); });
    });
    await act(async () => { root.render(wrap(<Probe enabled />)); });
    await flush();
    // Pages 2..5 are all in flight while none of them has resolved.
    expect(pagesRequested()).toEqual([1, 2, 3, 4, 5]);
    expect([...pending.keys()]).toEqual([2, 3, 4, 5]);
    await act(async () => { pending.forEach((r) => r(undefined)); });
  });
});

describe('FindingsPage lens wiring', () => {
  async function renderAt(lens: string) {
    api.GET.mockImplementation(async (path: string) => {
      if (path === '/crypto-risks') return { data: { risks: [], total: 0, total_pages: 1 } };
      if (path === '/findings') return { data: { findings: [], total: 0, producer_counts: {} } };
      return { data: {} };
    });
    await act(async () => {
      root.render(
        <MemoryRouter initialEntries={[`/findings?lens=${lens}`]}>
          <QueryClientProvider client={qc}><FindingsPage /></QueryClientProvider>
        </MemoryRouter>,
      );
    });
    await flush();
  }

  it('does not fetch crypto risks on a findings-scoped lens', async () => {
    await renderAt('producer');
    expect(riskCalls()).toHaveLength(0);
  });

  it('fetches crypto risks on a crypto lens', async () => {
    await renderAt('severity');
    expect(riskCalls().length).toBeGreaterThan(0);
  });
});
