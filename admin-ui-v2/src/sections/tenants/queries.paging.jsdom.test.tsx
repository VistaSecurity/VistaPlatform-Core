// @vitest-environment jsdom
//
// useTenants / useStaff / useTenantHealthList must walk every page rather than
// stop at the first (admin lists silently truncated at 100/200 rows).
// clients.* is mocked; the real hooks run over a real QueryClient.
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const adminGET = vi.fn();
const healthGET = vi.fn();
vi.mock('../../lib/clients', () => ({ clients: { admin: { GET: (...a: unknown[]) => adminGET(...a) }, tenantHealth: { GET: (...a: unknown[]) => healthGET(...a) } } }));
vi.mock('../../lib/edition', () => ({ usePlatformEdition: () => ({ has: () => true, resolved: true, isMsp: true }) }));

import { useTenants, useTenantsTruncation, useTenantHealthList } from './queries';
import { useStaff } from '../staff/queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function mount<T>(hook: () => T) {
  const out: { current: T | undefined } = { current: undefined };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  function Probe() { out.current = hook(); return null; }
  const root = createRoot(document.createElement('div'));
  act(() => root.render(<QueryClientProvider client={qc}><Probe /></QueryClientProvider>));
  return out;
}
// Poll until the query has settled (the 5000-row walk is dozens of mock calls).
const settle = async (out: { current: unknown }) => {
  for (let i = 0; i < 100; i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
    if ((out.current as { isSuccess?: boolean })?.isSuccess) return;
  }
};
const ids = (n: number, from: number) => Array.from({ length: n }, (_, i) => ({ id: `t${from + i}` }));

beforeEach(() => { adminGET.mockReset(); healthGET.mockReset(); });

describe('list queries page through the server', () => {
  it('useTenants requests page 2 when total exceeds the page size', async () => {
    adminGET.mockImplementation(async (_p: string, o: { params: { query: { page: number } } }) => {
      const page = o.params.query.page;
      return { data: { tenants: page === 1 ? ids(200, 0) : ids(50, 200), pagination: { total: 250 } } };
    });
    const out = mount(() => useTenants());
    await settle(out);
    const pages = adminGET.mock.calls.map((c) => c[1].params.query.page);
    expect(pages).toEqual([1, 2]);
    expect((out.current as { data?: unknown[] }).data).toHaveLength(250);
  });

  it('reports truncation only once the ceiling is hit', async () => {
    adminGET.mockImplementation(async (_p: string, o: { params: { query: { page: number } } }) => ({
      data: { tenants: ids(200, (o.params.query.page - 1) * 200), pagination: { total: 9000 } },
    }));
    const out = mount(() => useTenantsTruncation());
    await settle(out);
    expect((out.current as { data?: { truncated: boolean; total: number; shown: number } }).data).toEqual({ truncated: true, total: 9000, shown: 5000 });
  });

  it('useStaff requests page 2 when total exceeds the page size', async () => {
    adminGET.mockImplementation(async (_p: string, o: { params: { query: { page: number } } }) => ({
      data: { users: o.params.query.page === 1 ? ids(200, 0) : ids(5, 200), pagination: { total: 205 } },
    }));
    const out = mount(() => useStaff());
    await settle(out);
    expect(adminGET.mock.calls.map((c) => c[1].params.query.page)).toEqual([1, 2]);
    expect((out.current as { data?: unknown[] }).data).toHaveLength(205);
  });

  it('tenant health walks offsets until a short page', async () => {
    healthGET.mockImplementation(async (_p: string, o: { params: { query: { offset: number } } }) => ({
      data: { tenants: o.params.query.offset === 0 ? ids(200, 0).map((x) => ({ tenant_id: x.id })) : [{ tenant_id: 'last' }] },
    }));
    const out = mount(() => useTenantHealthList());
    await settle(out);
    expect(healthGET.mock.calls.map((c) => c[1].params.query.offset)).toEqual([0, 200]);
    expect((out.current as { data?: unknown[] }).data).toHaveLength(201);
  });
});
