// @vitest-environment jsdom
//
// Server-backed search boxes on the REAL InventoryPage (certificates lens):
// a burst of keystrokes is ONE request carrying the final text, and a request
// made superseded by a newer key is cancelled through React Query's `signal`.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Init = { signal?: AbortSignal; params?: { query?: { search?: string } } };
const mocks = vi.hoisted(() => ({ get: vi.fn(), hang: false }));
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { InventoryPage } from './inventory-page';

const certCalls = (): Init[] =>
  mocks.get.mock.calls.filter((c) => c[0] === '/certificates').map((c) => (c[1] ?? {}) as Init);

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  mocks.hang = false;
  mocks.get.mockReset().mockImplementation((path: string) => {
    if (path === '/certificates') {
      if (mocks.hang) return new Promise(() => {});
      return Promise.resolve({ data: { certificates: [], pagination: { total: 0, page: 1, page_size: 50 } } });
    }
    return Promise.resolve({ data: { assets: [], pagination: { total: 0, page: 1, page_size: 50 } } });
  });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

const sleep = (ms: number) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });

async function renderLens() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], []);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={['/inventory?lens=certificate']}>
            <Routes><Route path="/inventory" element={<InventoryPage />} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await sleep(30);
}

async function type(text: string) {
  const input = host.querySelector('input[placeholder="Search inventory…"]') as HTMLInputElement;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  await act(async () => { setter.call(input, text); input.dispatchEvent(new Event('input', { bubbles: true })); });
}

describe('Inventory certificates lens search', () => {
  it('three quick keystrokes make one request with the final value', async () => {
    await renderLens();
    const before = certCalls().length;
    await type('a'); await sleep(40);
    await type('ab'); await sleep(40);
    await type('abc');
    expect(certCalls().length).toBe(before); // nothing yet: still inside the quiet period
    await sleep(500);
    const fresh = certCalls().slice(before);
    expect(fresh).toHaveLength(1);
    expect(fresh[0]!.params!.query!.search).toBe('abc');
  });

  it('aborts the superseded request through the signal when the key changes', async () => {
    mocks.hang = true;
    await renderLens();
    const first = certCalls()[0]!;
    expect(first.signal).toBeInstanceOf(AbortSignal);
    expect(first.signal!.aborted).toBe(false);
    await type('zzz');
    await sleep(500);
    expect(certCalls().length).toBeGreaterThanOrEqual(2);
    expect(first.signal!.aborted).toBe(true);
  });
});
