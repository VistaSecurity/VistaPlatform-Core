// @vitest-environment jsdom
//
// DCIM BUILD_PLAN row 5.4, driven through the REAL InventoryPage on the assets
// lens (the lens with a query bar): the Filters menu lists the organisation's
// shared filters before the caller's own, applying one writes its query into
// the page's `?query=`, and "Save current filter…" posts the canonical query
// for the lens's kind. All five states of the menu are covered.
//
// Mutation: remove <SavedFilters …/> from assets-lens.tsx -> every test here
// goes red; make the menu's apply a no-op -> the apply test goes red; drop
// `disabled={!canShare}` from the Share checkbox -> the share test goes red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), del: vi.fn() }));
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: vi.fn(), DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { InventoryPage } from './inventory-page';

const filter = (over: Record<string, unknown>) => ({
  id: 'f-' + String(over.name), description: null, object_kinds: ['asset'], user_id: null, shared: false, weight: 100,
  created_at: '2026-10-16T00:00:00Z', updated_at: '2026-10-16T00:00:00Z', slug: 'x', ...over,
});
const SHARED = filter({ name: 'Prod web', query: 'hostname:web*', shared: true });
const MINE = filter({ name: 'My risky', query: 'risk >= high' });

type ListState = { filters: unknown[]; canShare: boolean } | 'fail' | 'pending';
let list: ListState;

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="location">{decodeURIComponent(loc.pathname + loc.search)}</div>;
}

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  list = { filters: [SHARED, MINE], canShare: false };
  mocks.post.mockReset();
  mocks.del.mockReset().mockResolvedValue({ data: undefined, error: undefined });
  mocks.get.mockReset().mockImplementation(async (path: string) => {
    if (path === '/dcim/saved-filters') {
      if (list === 'pending') return new Promise(() => {});
      if (list === 'fail') return { data: undefined, error: { error: { message: 'boom' } } };
      return { data: { data: list.filters, can_share: list.canShare } };
    }
    if (path === '/infrastructure-assets') return { data: { assets: [], pagination: { total: 0, page: 1, page_size: 50 } } };
    return { data: {} };
  });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function renderLens(search = '') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], ['assets.read']);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[`/inventory?lens=assets${search}`]}>
            <Routes><Route path="/inventory" element={<InventoryPage />} /></Routes>
            <LocationProbe />
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
}

const button = (re: RegExp) => [...host.querySelectorAll<HTMLButtonElement>('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));
const bodyButton = (re: RegExp) => [...document.body.querySelectorAll<HTMLButtonElement>('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));
const menu = () => host.querySelector('[data-testid="saved-filters-menu"]');
const location = () => host.querySelector('[data-testid="location"]')!.textContent;

async function openMenu() {
  await act(async () => { host.querySelector<HTMLButtonElement>('button[aria-haspopup="menu"]')!.click(); });
}
function typeInto(el: HTMLInputElement, value: string) {
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  act(() => { set.call(el, value); el.dispatchEvent(new Event('input', { bubbles: true })); });
}

describe('Filters menu on the assets lens', () => {
  it('lists shared filters before the caller’s own and applies one into ?query=', async () => {
    await renderLens();
    await openMenu();
    const text = menu()!.textContent!;
    expect(text.indexOf('Prod web')).toBeGreaterThan(-1);
    expect(text.indexOf('Prod web')).toBeLessThan(text.indexOf('My risky'));
    expect(text.indexOf('Shared')).toBeLessThan(text.indexOf('Mine'));

    await act(async () => { button(/Prod web/)!.click(); });
    expect(location()).toContain('query=hostname:web*');
    expect(menu()).toBeNull();
    // The list read asks for this lens's kind.
    expect(mocks.get).toHaveBeenCalledWith('/dcim/saved-filters', { params: { query: { kind: 'asset' } } });
  });

  it('shows the empty state when there are none', async () => {
    list = { filters: [], canShare: false };
    await renderLens();
    await openMenu();
    expect(host.querySelector('[data-testid="saved-filters-empty"]')).not.toBeNull();
  });

  it('says the read failed, not that there are none, and offers a retry', async () => {
    list = 'fail';
    await renderLens();
    await openMenu();
    expect(host.querySelector('[data-testid="saved-filters-error"]')).not.toBeNull();
    expect(host.querySelector('[data-testid="saved-filters-empty"]')).toBeNull();
    expect(button(/^Retry$/)).toBeDefined();
  });

  it('shows a loading line while the list is in flight', async () => {
    list = 'pending';
    await renderLens();
    await openMenu();
    expect(menu()!.textContent).toContain('Loading filters…');
  });

  it('offers no delete for a shared filter to someone who cannot manage shared filters', async () => {
    await renderLens();
    await openMenu();
    expect(button(/Delete My risky/)).toBeDefined();
    expect(button(/Delete Prod web/)).toBeUndefined();
  });

  it('offers it to someone who can', async () => {
    list = { filters: [SHARED, MINE], canShare: true };
    await renderLens();
    await openMenu();
    expect(button(/Delete Prod web/)).toBeDefined();
  });
});

describe('Save current filter…', () => {
  it('is disabled with no query', async () => {
    await renderLens();
    await openMenu();
    expect(button(/Save current filter/)!.disabled).toBe(true);
  });

  it('posts the canonical query for the lens’s kind, personal when the caller cannot share', async () => {
    mocks.post.mockResolvedValue({ data: { data: MINE }, error: undefined });
    await renderLens('&query=risk%20%20%3E%3D%20high');
    await openMenu();
    await act(async () => { button(/Save current filter/)!.click(); });

    const share = document.body.querySelector('input[aria-label="Share with my organization"]') as HTMLInputElement;
    expect(share.disabled).toBe(true);
    typeInto(document.body.querySelector('input[aria-label="Filter name"]') as HTMLInputElement, 'Risky');
    await act(async () => { bodyButton(/^Save filter$/)!.click(); });

    expect(mocks.post).toHaveBeenCalledWith('/dcim/saved-filters', {
      body: { name: 'Risky', object_kinds: ['asset'], query: 'risk >= high', shared: false },
    });
  });

  it('shares when the caller may', async () => {
    list = { filters: [], canShare: true };
    mocks.post.mockResolvedValue({ data: { data: SHARED }, error: undefined });
    await renderLens('&query=risk%20%3E%3D%20high');
    await openMenu();
    await act(async () => { button(/Save current filter/)!.click(); });
    const share = document.body.querySelector('input[aria-label="Share with my organization"]') as HTMLInputElement;
    expect(share.disabled).toBe(false);
    act(() => { share.click(); });
    typeInto(document.body.querySelector('input[aria-label="Filter name"]') as HTMLInputElement, 'Team');
    await act(async () => { bodyButton(/^Save filter$/)!.click(); });
    expect(mocks.post).toHaveBeenCalledWith('/dcim/saved-filters', { body: { name: 'Team', object_kinds: ['asset'], query: 'risk >= high', shared: true } });
  });

  it('shows the server’s reason when the save is refused', async () => {
    mocks.post.mockResolvedValue({ data: undefined, error: { error: { code: 'invalid_query', message: 'The query is not valid for this kind.', details: [{ message: 'unknown field' }] } } });
    await renderLens('&query=risk%20%3E%3D%20high');
    await openMenu();
    await act(async () => { button(/Save current filter/)!.click(); });
    typeInto(document.body.querySelector('input[aria-label="Filter name"]') as HTMLInputElement, 'Risky');
    await act(async () => { bodyButton(/^Save filter$/)!.click(); });
    await vi.waitFor(() => expect(document.body.querySelector('[role="alert"]')?.textContent).toContain('The query is not valid for this kind. unknown field'));
  });
});
