// @vitest-environment jsdom
//
// Writes that change what the viewer may see or pick must reach the OTHER
// screens' caches.
//
//  - A plan change must refresh the tenant feature map and the viewer's
//    permissions (both cached 5 min by the primitives), or the upgrade card
//    stays up after paying.
//  - Settings -> Scopes and the CBOM scope picker read the same endpoint; they
//    share ONE cache entry, so a rename in Settings reaches the picker.
//
// MUTATIONS (recorded in the PR): drop invalidateEntitlements(qc) from
// useChangePlan -> the first test fails; point the scope modal's invalidation
// back at ['settings','scopes'] -> the last test fails (picker keeps the old name).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { primitivesQueryKeys } from '@vistasecurity/primitives/shared';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { admin: api, auth: api, cbom: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import { useChangePlan } from './billing-modals';
import { ScopeEditModal } from './scope-modals';
import { useScopes } from '../cbom/queries';

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset(); api.POST.mockReset(); api.PUT.mockReset();
  qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 60_000 }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });
const flush = async () => { await act(async () => { await new Promise((r) => setTimeout(r, 20)); }); };

describe('plan change', () => {
  it('invalidates the tenant features and the viewer permissions', async () => {
    qc.setQueryData(primitivesQueryKeys.tenant.features(), { features: {} });
    qc.setQueryData(primitivesQueryKeys.auth.permissions(), ['settings.read']);
    api.POST.mockResolvedValue({ data: { ok: true }, response: { ok: true, status: 200 } });
    let change!: ReturnType<typeof useChangePlan>;
    function Probe() { change = useChangePlan(); return null; }
    await act(async () => { root.render(<QueryClientProvider client={qc}><Probe /></QueryClientProvider>); });

    await act(async () => { change.mutate({ tier_id: 'enterprise' }); });
    await flush();

    expect(qc.getQueryState(primitivesQueryKeys.tenant.features())?.isInvalidated).toBe(true);
    expect(qc.getQueryState(primitivesQueryKeys.auth.permissions())?.isInvalidated).toBe(true);
  });
});

describe('scopes: one cache entry for Settings and the CBOM picker', () => {
  it('a rename saved in Settings reaches the CBOM picker', async () => {
    let name = 'Old name';
    api.GET.mockImplementation(async () => ({ data: { scopes: [{ id: 's1', name, version: 1, query: '' }] }, response: { ok: true, status: 200 } }));
    api.PUT.mockImplementation(async (_p: string, opts: { body: { name: string } }) => {
      name = opts.body.name;
      return { data: {}, response: { ok: true, status: 200 } };
    });
    function Picker() {
      const q = useScopes();
      return <ul>{(q.data ?? []).map((s) => <li key={s.id} data-testid="picker-item">{s.name}</li>)}</ul>;
    }
    await act(async () => {
      root.render(
        <QueryClientProvider client={qc}>
          <Picker />
          <ScopeEditModal open onClose={() => undefined} scope={{ id: 's1', name: 'Old name', version: 1, query: '' } as never} />
        </QueryClientProvider>,
      );
    });
    await flush();
    expect(host.querySelector('[data-testid="picker-item"]')?.textContent).toBe('Old name');

    const input = document.querySelector<HTMLInputElement>('input[data-autofocus]')!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, 'New name');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    const save = [...document.querySelectorAll('button')].find((b) => b.textContent === 'Save changes')!;
    await act(async () => { save.click(); });
    await flush();

    expect(api.PUT).toHaveBeenCalled();
    expect(host.querySelector('[data-testid="picker-item"]')?.textContent).toBe('New name');
  });
});
