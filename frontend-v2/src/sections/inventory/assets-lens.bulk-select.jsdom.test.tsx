// @vitest-environment jsdom
//
// Inventory → All assets and Stale: multi-select and the bulk bar,
// on the REAL InventoryPage. The pieces have their own tests; this one holds
// the wiring — that the lens renders the checkboxes, offers "Select all N
// matching" when more match than the page shows, and that the bar's Scan
// sends the QUERY with the confirmed count rather than the page's ids.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type PostInit = { body: Record<string, unknown> };
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn<(path: string, init: PostInit) => Promise<unknown>>() }));
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { InventoryPage } from './inventory-page';

const asset = (i: number) => ({
  id: `asset-${i}`, hostname: `web-${i}.example.test`, display_name: `web-${i}.example.test`,
  class_key: 'server', asset_status: 'monitoring', risk_score: 10, deleted_at: null,
});
const PAGE = [asset(1), asset(2), asset(3)];
const TOTAL = 120;

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  mocks.get.mockReset();
  mocks.post.mockReset();
  mocks.get.mockImplementation(async (path: string) => {
    if (path === '/infrastructure-assets') return { data: { assets: PAGE, pagination: { total: TOTAL, page: 1, page_size: 50 } } };
    if (path === '/crypto-configurations') return { data: { crypto_implementations: [] } };
    if (path === '/sensors') return { data: { sensors: [] } };
    return { data: {} };
  });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function renderAt(url: string, permissions = ['assets.read', 'assets.update']) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[url]}>
            <Routes><Route path="/inventory" element={<InventoryPage />} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await vi.waitFor(() => expect(box('Select web-1.example.test')).not.toBeNull());
}
const box = (label: string) => host.querySelector(`input[aria-label="${label}"]`);
// document, not host: the dialogs render in a portal.
const button = (re: RegExp) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent?.trim() ?? ''));
async function click(el: Element | null | undefined) {
  if (!el) throw new Error(`nothing to click in: ${host.textContent}`);
  await act(async () => { (el as HTMLElement).click(); });
}

describe('All assets', () => {
  it('ticking a row selects it without opening the drawer', async () => {
    await renderAt('/inventory?lens=assets&query=class%3Aserver');
    await click(box('Select web-1.example.test'));
    expect(host.textContent).toContain('1 asset selected');
    expect(host.querySelector('h2.mono')).toBeNull();
  });

  it('page → "Select all 120 matching" → Scan sends the query and its count', async () => {
    mocks.post.mockResolvedValueOnce({ data: { message: 'ok', job_id: 'j', count: 120, jobs: [{ job_id: 'j', executor: 'platform', count: 120 }], skipped: [] }, response: { ok: true, status: 200 } });
    await renderAt('/inventory?lens=assets&query=class%3Aserver');
    await click(box('Select every asset on this page'));
    expect(host.textContent).toContain('All 3 assets on this page are selected.');
    await click(button(/^Select all 120 assets matching$/));
    expect(host.textContent).toContain('All 120 assets matching this query are selected.');
    expect(host.textContent).toContain('120 assets selected');

    await click(button(/^Scan$/));
    // The dialog's Run from waits for the sensor list before it can send.
    await vi.waitFor(() => expect(button(/^Scan 120 assets$/)?.disabled).toBe(false));
    await click(button(/^Scan 120 assets$/));
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    const [path, init] = mocks.post.mock.calls[0];
    expect(path).toBe('/infrastructure-assets/scan');
    expect(init.body).toEqual({ query: 'class:server', expected_count: 120, run_from: 'platform' });
    // The jobs it started are shown under the bar.
    await vi.waitFor(() => expect(host.textContent).toContain('Scans started here'));
  });

  it('a reader sees the checkboxes and Export, not the writes', async () => {
    await renderAt('/inventory?lens=assets', ['assets.read']);
    await click(box('Select web-2.example.test'));
    expect(button(/^Export$/)).toBeDefined();
    expect(button(/^Scan$/)).toBeUndefined();
    expect(button(/^Archive$/)).toBeUndefined();
  });
});

describe('Stale', () => {
  it('ticks stale rows and archives exactly those', async () => {
    mocks.post.mockResolvedValueOnce({ data: { action: 'archive', matched: 2, changed: 2, unchanged: 0 }, response: { ok: true, status: 200 } });
    await renderAt('/inventory?lens=stale');
    await click(box('Select web-1.example.test'));
    await click(box('Select web-3.example.test'));
    await click(button(/^Archive$/));
    await click(button(/^Archive 2 assets$/));
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    expect(mocks.post.mock.calls[0][0]).toBe('/infrastructure-assets/bulk-actions/archive');
    expect(mocks.post.mock.calls[0][1].body).toEqual({ asset_ids: ['asset-1', 'asset-3'] });
  });

  it('"Select all" on Stale is the server\'s staleness cut, as a query', async () => {
    await renderAt('/inventory?lens=stale');
    await click(box('Select every stale asset on this page'));
    await click(button(/^Select all 120 assets matching$/));
    await click(button(/^Archive$/));
    mocks.post.mockResolvedValueOnce({ data: { action: 'archive', matched: 120, changed: 120, unchanged: 0 }, response: { ok: true, status: 200 } });
    await click(button(/^Archive 120 assets$/));
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    const body = mocks.post.mock.calls[0][1].body;
    // The same predicate the list's last_seen_before is translated into.
    expect(body.query).toMatch(/^last_seen < "\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z"$/);
    expect(body.expected_count).toBe(120);
  });
});
