// @vitest-environment jsdom
//
// The full asset page carries the same Active Scan button as the drawer.
//
// The page is where a person lands from "Open full page" (ADR-0006 D3), and it
// is where they send a link; having to go back to the drawer to probe the
// asset they are looking at was the gap. This renders the REAL AssetPage over a
// faked inventory client and the REAL permission gate (its list seeded in the
// query cache), so the conditions asserted are the ones the page applies, not
// ones a mock restates.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { AssetPage } from './asset-page';
import { SCANNING_POLL_MS } from '../discovery/active-scan-row-state';

const BASE = {
  id: 'asset-1',
  hostname: 'web-1.example.test',
  display_name: 'web-1.example.test',
  class_key: 'server',
  asset_status: 'monitoring',
  risk_score: 0,
  deleted_at: null,
};

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  mocks.get.mockReset();
  mocks.post.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
  vi.useRealTimers();
});

function answer(asset: Record<string, unknown> | (() => Record<string, unknown>)) {
  mocks.get.mockImplementation(async (path: string) => {
    if (path === '/infrastructure-assets/{id}') {
      return { data: { asset: { ...BASE, ...(typeof asset === 'function' ? asset() : asset) } } };
    }
    return { data: {} };
  });
}

async function renderPage(permissions: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={['/inventory/assets/asset-1']}>
            <Routes><Route path="/inventory/assets/:id" element={<AssetPage />} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await vi.waitFor(() => expect(host.querySelector('h1')?.textContent).toBe(BASE.hostname));
}

const scanButton = () => [...host.querySelectorAll('button')].find((b) => /Active Scan|Scanning…/.test(b.textContent ?? ''));

describe('asset page — Active Scan', () => {
  it('shows the button to a user who can update assets, and scans this asset through the scan dialog', async () => {
    answer({});
    mocks.post.mockResolvedValue({ data: { message: 'ok', job_id: 'j', count: 1, jobs: [{ job_id: 'j', executor: 'platform', count: 1 }], skipped: [] }, response: { ok: true, status: 200 } });
    await renderPage(['assets.update']);

    const b = scanButton();
    expect(b).toBeDefined();
    expect(b!.disabled).toBe(false);
    expect(b!.textContent).toContain('Active Scan');

    // The button opens the same dialog Inventory's bulk Scan does, so
    // a single scan also chooses where it runs. Nothing is sent until it is
    // confirmed there.
    await act(async () => { b!.click(); });
    expect(mocks.post).not.toHaveBeenCalled();
    // document, not host: the dialog renders in a portal.
    const confirm = () => [...document.querySelectorAll('button')].find((x) => x.textContent?.trim() === 'Scan 1 asset');
    await vi.waitFor(() => expect(confirm()?.disabled).toBe(false));
    await act(async () => { confirm()!.click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledWith('/infrastructure-assets/scan', { body: { asset_ids: ['asset-1'], run_from: 'platform' } }));
  });

  it('hides the button from a user who cannot update assets', async () => {
    answer({});
    await renderPage(['assets.read']);
    expect(scanButton()).toBeUndefined();
  });

  it.each([
    ['archived', { asset_status: 'archived' }],
    ['deleted', { deleted_at: '2026-10-01T00:00:00Z' }],
  ])('hides the button for an %s asset, even for a user who can update assets', async (_label, patch) => {
    answer(patch);
    await renderPage(['assets.update']);
    expect(scanButton()).toBeUndefined();
  });

  it('says a scan in flight is in flight, and offers a new scan once the page has re-read the asset', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let scanning = true;
    answer(() => (scanning
      ? { active_scan: { status: 'scanning', started_at: new Date().toISOString(), job_ids: ['j'] } }
      : { active_scan: { status: 'completed', finished_at: new Date().toISOString(), job_ids: ['j'] } }));
    await renderPage(['assets.update']);

    expect(scanButton()!.disabled).toBe(true);
    expect(scanButton()!.textContent).toContain('Scanning…');

    // The scan ends server-side; nobody touches the page. It must notice.
    scanning = false;
    await act(async () => { await vi.advanceTimersByTimeAsync(SCANNING_POLL_MS + 100); });

    await vi.waitFor(() => expect(scanButton()!.textContent).toContain('Active Scan'));
    expect(scanButton()!.disabled).toBe(false);
  });
});
