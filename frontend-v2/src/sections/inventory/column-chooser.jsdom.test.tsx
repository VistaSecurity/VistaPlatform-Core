// @vitest-environment jsdom
//
// Inventory → All assets → Columns, on the REAL InventoryPage: a hidden column
// (the DCIM gap 4 lifecycle ones above all) can be shown, the choice survives a
// remount, it is remembered per user and per lens, Reset puts the defaults back,
// and the selection export carries what the table shows. The five states: the
// default menu, an empty search, the lens still loading, storage that throws
// (an error the person never sees), and a successful change.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  download: vi.fn<(name: string, header: string[], rows: unknown[][]) => void>(),
  userId: null as string | null,
}));
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));
vi.mock('../findings/export-csv', async (orig) => ({
  ...(await orig<typeof import('../findings/export-csv')>()),
  downloadCsv: mocks.download,
}));
vi.mock('@vistasecurity/primitives/auth', async (orig) => ({
  ...(await orig<typeof import('@vistasecurity/primitives/auth')>()),
  useOptionalAuth: () => (mocks.userId ? { user: { id: mocks.userId } } : null),
}));

import { InventoryPage } from './inventory-page';
import { columnPrefsKey } from './column-chooser';

const ASSET = {
  id: 'asset-1', hostname: 'web-1.example.test', display_name: 'web-1.example.test',
  class_key: 'server', asset_status: 'monitoring', risk_score: 10, deleted_at: null,
  warranty_end: '2027-03-31', support_group: 'Core network',
};

let host: HTMLDivElement;
let root: Root;
let listResponse: () => Promise<unknown>;
beforeEach(() => {
  window.localStorage.clear();
  mocks.userId = null;
  mocks.download.mockReset();
  listResponse = async () => ({ data: { assets: [ASSET], pagination: { total: 1, page: 1, page_size: 50 } } });
  mocks.get.mockReset();
  mocks.get.mockImplementation(async (path: string) => {
    if (path === '/infrastructure-assets') return listResponse();
    if (path === '/crypto-configurations') return { data: { crypto_implementations: [] } };
    return { data: {} };
  });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); vi.restoreAllMocks(); });

async function renderAt(url = '/inventory?lens=assets', wait = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], ['assets.read']);
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
  if (wait) await vi.waitFor(() => expect(host.textContent).toContain('web-1.example.test'));
}
async function remount(url?: string) {
  act(() => root.unmount());
  root = createRoot(host);
  await renderAt(url);
}
const button = (re: RegExp) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent?.trim() ?? ''));
const box = (label: string) => host.querySelector<HTMLInputElement>(`[data-testid="column-chooser"] input[aria-label="${label}"]`);
/** The table's column headings: the eyebrows of the header row, the one row
 *  holding the select-the-page checkbox (the facet rail and the open menu
 *  have eyebrows too). */
const headings = () => {
  const row = host.querySelector('input[aria-label="Select every asset on this page"]')?.parentElement;
  return row ? [...row.querySelectorAll('.eyebrow-app')].map((e) => e.textContent?.trim()) : [];
};
async function click(el: Element | null | undefined) {
  if (!el) throw new Error(`nothing to click in: ${host.textContent}`);
  await act(async () => { (el as HTMLElement).click(); });
}
const openMenu = () => click(button(/^Columns/));

describe('All assets → Columns', () => {
  it('default: lists every column by group, the defaults ticked and the lifecycle ones not', async () => {
    await renderAt();
    expect(headings()).not.toContain('Warranty end');
    await openMenu();
    const groups = [...host.querySelectorAll('[data-testid="column-chooser"] [role="group"]')].map((g) => g.getAttribute('aria-label'));
    expect(groups).toEqual(['Standard', 'More', 'Lifecycle']);
    expect(box('Class')?.checked).toBe(true);
    expect(box('Network')?.checked).toBe(true);
    for (const l of ['Warranty end', 'End of support', 'Purchased', 'Vendor (seller)', 'Support group']) {
      expect(box(l)?.checked).toBe(false);
    }
    expect(button(/^Reset to default$/)?.disabled).toBe(true);
  });

  it('a class adds ALL of its attributes, not just the three shown by default', async () => {
    await renderAt('/inventory?lens=assets&query=class%3Aserver');
    await openMenu();
    const group = host.querySelector('[data-testid="column-chooser"] [role="group"][aria-label="Server attributes"]');
    expect(group).not.toBeNull();
    expect(group!.querySelectorAll('input').length).toBeGreaterThan(3);
  });

  it('empty: a search that matches nothing says so', async () => {
    await renderAt();
    await openMenu();
    const input = host.querySelector<HTMLInputElement>('input[aria-label="Search columns"]')!;
    await act(async () => {
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
      set.call(input, 'warr');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    expect(box('Warranty end')).not.toBeNull();
    expect(box('Class')).toBeNull();
    await act(async () => {
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
      set.call(input, 'no-such-column');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    expect(host.querySelector('[data-testid="column-chooser-empty"]')?.textContent).toContain('no-such-column');
  });

  it('loading: the menu works before the list arrives, and the skeleton takes the new column', async () => {
    listResponse = () => new Promise(() => {});
    await renderAt('/inventory?lens=assets', false);
    await vi.waitFor(() => expect(host.querySelector('[data-testid="assets-skeleton"]')).not.toBeNull());
    const cells = () => host.querySelector('[data-testid="assets-skeleton"] > div')!.children.length;
    const before = cells();
    await openMenu();
    await click(box('Warranty end'));
    expect(cells()).toBe(before + 1);
  });

  it('error: storage that throws leaves the defaults and still applies a change for this visit', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked'); });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked'); });
    await renderAt();
    expect(headings()).toContain('Class');
    await openMenu();
    await click(box('Warranty end'));
    expect(headings()).toContain('Warranty end');
    expect(host.textContent).toContain('2027-03-31');
  });

  it('success: a hidden lifecycle column can be shown, survives a remount, and Reset hides it again', async () => {
    await renderAt();
    await openMenu();
    await click(box('Warranty end'));
    expect(headings()).toContain('Warranty end');
    expect(host.textContent).toContain('2027-03-31');
    expect(button(/^Reset to default$/)?.disabled).toBe(false);

    await remount();
    expect(headings()).toContain('Warranty end');
    expect(host.textContent).toContain('2027-03-31');

    await openMenu();
    await click(button(/^Reset to default$/));
    expect(headings()).not.toContain('Warranty end');
    expect(window.localStorage.getItem(columnPrefsKey(null, 'assets'))).toBeNull();
  });

  it('unticking a column back to its default stores no choice, so it follows the class again', async () => {
    await renderAt();
    await openMenu();
    await click(box('Warranty end'));
    await click(box('Warranty end'));
    expect(window.localStorage.getItem(columnPrefsKey(null, 'assets'))).toBeNull();
    expect(button(/^Reset to default$/)?.disabled).toBe(true);
  });

  it('a default column can be hidden', async () => {
    await renderAt();
    await openMenu();
    await click(box('Environment'));
    expect(headings()).not.toContain('Environment');
  });

  it('is remembered per user: another person on the same browser gets the defaults', async () => {
    mocks.userId = 'user-a';
    await renderAt();
    await openMenu();
    await click(box('Warranty end'));
    expect(window.localStorage.getItem(columnPrefsKey('user-a', 'assets'))).toBe('{"warranty_end":true}');

    mocks.userId = 'user-b';
    await remount();
    expect(headings()).not.toContain('Warranty end');
    mocks.userId = 'user-a';
    await remount();
    expect(headings()).toContain('Warranty end');
  });

  it('the selection export carries every visible column', async () => {
    await renderAt();
    await openMenu();
    await click(box('Support group'));
    await click(host.querySelector('input[aria-label="Select web-1.example.test"]'));
    await click(button(/^Export$/));
    await vi.waitFor(() => expect(mocks.download).toHaveBeenCalled());
    const [, header, rows] = mocks.download.mock.calls[0];
    expect(header).toContain('support_group');
    expect(header).toContain('warranty_end'); // the fixed layout keeps its columns
    expect(rows[0][header.indexOf('support_group')]).toBe('Core network');
  });
});
