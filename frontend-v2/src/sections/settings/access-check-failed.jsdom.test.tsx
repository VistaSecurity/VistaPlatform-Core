// @vitest-environment jsdom
//
// A failed permissions/features lookup leaves the lists empty - the same state
// as a real denial. SettingsPage must tell them apart: a 500 shows a retryable
// "couldn't verify" state, a real 200-with-no-grant still shows the access
// notice. Driven through the REAL PermissionProvider / useFeatures.
//
// MUTATIONS (recorded in the PR): remove the `permsError` branch in
// SettingsPage -> the 500 test fails (AccessNotice appears); drop `isError`
// from the PermissionProvider value -> same.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('@vistasecurity/api-contract', async (orig) => ({
  ...(await orig<typeof import('@vistasecurity/api-contract')>()),
  createAuthServiceClient: () => api,
}));
vi.mock('../../lib/clients', () => ({ clients: new Proxy({}, { get: () => api }) }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { SettingsPage } from './settings-page';

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset();
  qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });
const flush = async () => { await act(async () => { await new Promise((r) => setTimeout(r, 20)); }); };

async function mount(at = '/settings/members') {
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[at]}>
            <Routes><Route path="/settings/:page" element={<SettingsPage />} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await flush();
}
const text = () => host.textContent ?? '';

describe('SettingsPage access check', () => {
  it('a 500 on /user/permissions is a retryable failure, not "no access"', async () => {
    api.GET.mockImplementation(async (path: string) => (
      path === '/user/permissions'
        ? { error: { error: 'boom' }, response: { ok: false, status: 500 } }
        : { data: { features: {} }, response: { ok: true, status: 200 } }));
    await mount();

    expect(text()).toContain('Couldn\'t verify your access');
    expect(text()).not.toContain('You don\'t have access to this page');

    // Retry refetches, and a good answer then renders the page (no failure state).
    api.GET.mockImplementation(async (path: string) => (
      path === '/user/permissions'
        ? { data: { permissions: [] }, response: { ok: true, status: 200 } }
        : { data: { features: {} }, response: { ok: true, status: 200 } }));
    const retry = [...host.querySelectorAll('button')].find((b) => b.textContent === 'Retry')!;
    await act(async () => { retry.click(); });
    await flush();
    expect(text()).not.toContain('Couldn\'t verify your access');
    expect(text()).toContain('You don\'t have access to this page');
  });

  it('a real answer with no grant still shows the access notice', async () => {
    api.GET.mockImplementation(async (path: string) => (
      path === '/user/permissions'
        ? { data: { permissions: [] }, response: { ok: true, status: 200 } }
        : { data: { features: {} }, response: { ok: true, status: 200 } }));
    await mount();
    expect(text()).toContain('You don\'t have access to this page');
    expect(text()).not.toContain('Couldn\'t verify your access');
  });
});
