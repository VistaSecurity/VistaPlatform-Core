// @vitest-environment jsdom
//
// Inventory → All assets: a row opens the asset DRAWER, not the full page.
//
// ADR-0006 D3 keeps the drawer as the peek from a list, with "Open full page"
// as the way out. The list used to navigate straight to the page, which left the
// drawer unreachable from the one list a person actually works in.
//
// This renders the REAL InventoryPage on the assets lens, because the click
// handler is only half of it: the page returns early for this lens, and the
// drawer stack has to be rendered on that branch too or the row queues a drawer
// nothing draws. Reverting the row to `navigate(...)`, or dropping the stack
// from the early return, turns the first tests red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn() }));
// Every service client answers through the one `get`, so a hook this page
// mounts that the test does not care about gets an empty answer.
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { InventoryPage } from './inventory-page';

const ASSET = {
  id: 'asset-1',
  hostname: 'web-1.example.test',
  display_name: 'web-1.example.test',
  class_key: 'server',
  asset_status: 'monitoring',
  risk_score: 55,
  risk_level: 'medium',
  deleted_at: null,
};

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="location">{loc.pathname + loc.search}</div>;
}

let host: HTMLDivElement;
let root: Root;
let openSpy: MockInstance<typeof window.open>;

beforeEach(() => {
  mocks.get.mockReset();
  mocks.get.mockImplementation(async (path: string) => {
    if (path === '/infrastructure-assets') {
      return { data: { assets: [ASSET], pagination: { total: 1, page: 1, page_size: 50 } } };
    }
    // The detail read never returns: whatever the drawer's header shows came
    // from the row's seed, which is the point of passing one.
    if (path === '/infrastructure-assets/{id}') return new Promise(() => {});
    if (path === '/crypto-configurations') return { data: { crypto_implementations: [] } };
    return { data: {} };
  });
  openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
  openSpy.mockRestore();
});

async function renderLens() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  // The permission list is read from the cache; seeding it keeps the REAL gate
  // in play without a network call.
  qc.setQueryData(['user-permissions'], ['assets.update']);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={['/inventory?lens=assets']}>
            <Routes>
              <Route path="/inventory" element={<InventoryPage />} />
              <Route path="/inventory/assets/:id" element={<div data-testid="full-page" />} />
            </Routes>
            <LocationProbe />
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await vi.waitFor(() => expect(nameLink()).not.toBeNull());
}

const nameLink = () => [...host.querySelectorAll('a')].find((a) => a.textContent === ASSET.hostname) ?? null;
const row = () => nameLink()!.closest('.row-hover') as HTMLElement;
// A cell that is not the link: the row's own click target.
const addressCell = () => row().querySelector('span[title], span') as HTMLElement;
const location = () => host.querySelector('[data-testid="location"]')!.textContent;
const drawerTitle = () => host.querySelector('h2.mono');

// Reports whether anything in the page called preventDefault on the click. The
// last listener records that and then prevents it itself, because jsdom would
// otherwise try (and log that it cannot) to follow a link the page let through.
function click(el: Element, init: MouseEventInit = {}) {
  const ev = new MouseEvent('click', { bubbles: true, cancelable: true, button: 0, ...init });
  let pagePrevented = false;
  const last = (e: Event) => { pagePrevented = e.defaultPrevented; e.preventDefault(); };
  window.addEventListener('click', last);
  act(() => { el.dispatchEvent(ev); });
  window.removeEventListener('click', last);
  return { pagePrevented };
}

describe('All assets — a row opens the drawer', () => {
  it('opens the drawer from the name, without navigating, and paints its header from the row', async () => {
    await renderLens();
    expect(drawerTitle()).toBeNull();

    const { pagePrevented } = click(nameLink()!);

    // The link's own navigation is what the drawer replaces.
    expect(pagePrevented).toBe(true);
    // The detail read is still pending, so this text is the seed.
    expect(drawerTitle()?.textContent).toBe(ASSET.hostname);
    expect(location()).toBe('/inventory?lens=assets');
    expect(host.querySelector('[data-testid="full-page"]')).toBeNull();
  });

  it('opens the drawer from anywhere else on the row', async () => {
    await renderLens();
    click(addressCell());
    expect(drawerTitle()?.textContent).toBe(ASSET.hostname);
    expect(location()).toBe('/inventory?lens=assets');
  });

  it('opens the drawer from the keyboard (Space on the focused name; Enter is the link\'s own click)', async () => {
    await renderLens();
    const ev = new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true });
    act(() => { nameLink()!.dispatchEvent(ev); });
    expect(ev.defaultPrevented).toBe(true);
    expect(drawerTitle()?.textContent).toBe(ASSET.hostname);
  });

  it('keeps the full page one click away: the drawer\'s "Open full page"', async () => {
    await renderLens();
    click(nameLink()!);
    const full = [...host.querySelectorAll('a')].find((a) => /Open full page/.test(a.textContent ?? ''));
    expect(full).toBeDefined();
    expect(full!.getAttribute('href')).toBe('/inventory/assets/asset-1');
    click(full!);
    expect(location()).toBe('/inventory/assets/asset-1');
    expect(host.querySelector('[data-testid="full-page"]')).not.toBeNull();
  });
});

describe('All assets — modified clicks still reach the full page', () => {
  it('leaves a ctrl/cmd/shift-click on the name to the browser', async () => {
    await renderLens();
    expect(nameLink()!.getAttribute('href')).toBe('/inventory/assets/asset-1');
    for (const init of [{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }]) {
      const { pagePrevented } = click(nameLink()!, init);
      // Not prevented: the browser follows the href in a new tab or window.
      expect(pagePrevented).toBe(false);
    }
    expect(drawerTitle()).toBeNull();
    expect(location()).toBe('/inventory?lens=assets');
  });

  it('opens the full page in a new tab on a ctrl-click elsewhere on the row', async () => {
    await renderLens();
    click(addressCell(), { ctrlKey: true });
    expect(openSpy).toHaveBeenCalledWith('/inventory/assets/asset-1', '_blank', 'noopener');
    expect(drawerTitle()).toBeNull();
    expect(location()).toBe('/inventory?lens=assets');
  });

  it('opens the full page in a new tab on a middle-click elsewhere on the row', async () => {
    await renderLens();
    const ev = new MouseEvent('auxclick', { bubbles: true, cancelable: true, button: 1 });
    act(() => { addressCell().dispatchEvent(ev); });
    expect(openSpy).toHaveBeenCalledWith('/inventory/assets/asset-1', '_blank', 'noopener');
    expect(drawerTitle()).toBeNull();
  });
});
