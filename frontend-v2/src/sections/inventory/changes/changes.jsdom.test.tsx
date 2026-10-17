// @vitest-environment jsdom
//
// Inventory → Changes (DCIM BUILD_PLAN row 5.2), mounted through the REAL
// InventoryPage over a faked inventory client and the REAL permission gate: the
// lens registered and reachable, filters reaching the request, the diff drawer,
// the CSV export, a related change on a panel, and the five states.
//
// Mutation: drop the `changes` entry from lenses.ts or the `changes` branch
// from InventoryPage → "is registered and reached through the real page" fails
// (the default lens renders instead); drop `include_related` from
// useObjectChanges → the related-change test fails.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { InventoryPage } from '../inventory-page';
import { ObjectChanges } from '../dcim/object-changes';
import { INVENTORY_LENSES, findLens } from '../lenses';
import { changesCsv, objectHref } from './changes-lens';
import { diffValueText } from '../dcim/change-diff';

const NOW = new Date().toISOString();
const ASSET_ID = '11111111-1111-4111-8111-111111111111';
const IFACE_ID = '22222222-2222-4222-8222-222222222222';
const change = (over: Record<string, unknown>) => ({
  id: 'ch1', object_kind: 'asset', object_id: ASSET_ID, action: 'update', prechange_data: {}, postchange_data: {},
  changed_fields: ['hostname'], user_id: 'u1', user_name: 'ops@example.test', request_id: null, source: 'ui',
  related_kind: null, related_id: null, object_label: 'core-sw-1', created_at: NOW, ...over,
});
const C_ASSET = change({});
const C_IFACE = change({
  id: 'ch2', object_kind: 'interface', object_id: IFACE_ID, changed_fields: ['mtu'], object_label: 'eth0',
  related_kind: 'asset', related_id: ASSET_ID,
});
const C_SYNC = change({ id: 'ch3', action: 'create', source: 'sync:netbox', user_id: null, user_name: null, object_kind: 'prefix', object_label: '10.0.0.0/24', changed_fields: ['prefix'] });
const DETAIL = {
  ...C_IFACE,
  diff: [
    { field: 'mtu', before: 1500, after: 9000 },
    { field: 'psk', before: '[redacted]', after: '[redacted]' },
  ],
};

const page = (rows: unknown[], total = rows.length) => ({ data: { data: rows, pagination: { total, limit: 50, offset: 0, next_offset: null } } });
type Routes = Record<string, (init?: unknown) => unknown>;
function answer(routes: Routes) {
  mocks.get.mockImplementation(async (path: string, init?: unknown) => (routes[path] ? routes[path](init) : page([])));
}
const happy: Routes = {
  '/dcim/changes': () => page([C_ASSET, C_IFACE, C_SYNC]),
  '/dcim/changes/{id}': () => ({ data: { data: DETAIL } }),
};

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  mocks.get.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); document.body.innerHTML = ''; });

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 20)); });
const READ = ['dcim.read'];

async function mount(path: string, permissions: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes><Route path="/inventory" element={<InventoryPage />} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await flush();
}
const q = (sel: string) => document.querySelector(sel);
const qa = (sel: string) => [...document.querySelectorAll(sel)];
const click = (el: Element | null) => act(async () => { (el as HTMLElement).click(); });
const setSelect = async (label: string, value: string) => {
  const sel = document.querySelector(`select[aria-label="${label}"]`) as HTMLSelectElement;
  await act(async () => { sel.value = value; sel.dispatchEvent(new Event('change', { bubbles: true })); });
  await flush();
};
const lastQuery = () => {
  const calls = mocks.get.mock.calls.filter((c) => c[0] === '/dcim/changes');
  return (calls[calls.length - 1][1] as { params: { query: Record<string, unknown> } }).params.query;
};

describe('Inventory → Changes', () => {
  it('is registered in the Lifecycle group and reached through the real page (default)', async () => {
    expect(INVENTORY_LENSES.find((l) => l.key === 'changes')).toMatchObject({ group: 'lifecycle', live: true, anchor: 'change' });
    expect(findLens('changes').key).toBe('changes');
    answer(happy);
    await mount('/inventory?lens=changes', READ);
    expect(q('[data-testid="changes-lens"]')).not.toBeNull();
    const rows = qa('[data-testid="change-log-row"]').map((r) => r.textContent ?? '');
    expect(rows).toHaveLength(3);
    expect(rows[0]).toContain('ops@example.test');
    expect(rows[0]).toContain('Web UI');
    expect(rows[0]).toContain('core-sw-1');
    expect(rows[0]).toContain('hostname');
    expect(rows[2]).toContain('Sync (netbox)');
    expect(rows[2]).toContain('Created');
    expect(rows[2]).toContain('10.0.0.0/24');
    // An asset's name links to its page; an interface's does not.
    expect(qa('[data-testid="change-object-link"]').map((a) => a.getAttribute('href'))).toEqual([`/inventory/assets/${ASSET_ID}`]);
  });

  it('sends every filter to the server and clears them', async () => {
    answer(happy);
    await mount('/inventory?lens=changes&kind=interface&q=eth&who=ops&source=intake:&action=update&from=2026-10-01&to=2026-10-02', READ);
    const query = lastQuery();
    expect(query).toMatchObject({ object_kind: 'interface', q: 'eth', user_name: 'ops', source: 'intake:', action: 'update', limit: 50, offset: 0 });
    expect(String(query.since)).toMatch(/^2026-10-0[01]T/);
    expect(String(query.until)).toMatch(/^2026-10-0[23]T/);
    await setSelect('Action', 'delete');
    expect(lastQuery()).toMatchObject({ action: 'delete', object_kind: 'interface' });
    await click(q('[data-testid="clear-filters"]'));
    await flush();
    expect(lastQuery()).not.toHaveProperty('action');
    expect(lastQuery()).not.toHaveProperty('object_kind');
  });

  it('a row opens the diff drawer; a secret shows only its marker', async () => {
    answer(happy);
    await mount('/inventory?lens=changes', READ);
    await click(qa('[data-testid="change-log-row"]')[1]);
    await flush();
    expect(q('[data-testid="change-drawer"]')?.textContent).toContain('eth0');
    const diffRows = qa('[data-testid="change-diff-row"]').map((r) => r.textContent ?? '');
    expect(diffRows).toHaveLength(2);
    expect(diffRows[0]).toContain('mtu');
    expect(diffRows[0]).toContain('1500');
    expect(diffRows[0]).toContain('9000');
    expect(diffRows[1]).toContain('psk');
    expect(diffRows[1]).toContain('[redacted]');
    const detail = mocks.get.mock.calls.find((c) => c[0] === '/dcim/changes/{id}');
    expect((detail?.[1] as { params: { path: { id: string } } }).params.path.id).toBe('ch2');
  });

  it('empty (unfiltered and filtered), loading and error states', async () => {
    answer({ '/dcim/changes': () => page([]) });
    await mount('/inventory?lens=changes', READ);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No changes recorded yet');
    answer({ '/dcim/changes': () => page([]) });
    act(() => root.unmount()); root = createRoot(host);
    await mount('/inventory?lens=changes&action=delete', READ);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No changes match');
    answer({ '/dcim/changes': () => new Promise(() => {}) });
    act(() => root.unmount()); root = createRoot(host);
    await mount('/inventory?lens=changes', READ);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
    answer({ '/dcim/changes': () => ({ error: { error: { code: 'x', message: 'change log unavailable' } } }) });
    act(() => root.unmount()); root = createRoot(host);
    await mount('/inventory?lens=changes', READ);
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('change log unavailable');
  });

  it('without dcim.read it explains the permission and fetches nothing', async () => {
    answer(happy);
    await mount('/inventory?lens=changes', ['assets.read']);
    expect(q('[data-testid="changes-lens"]')).toBeNull();
    expect(document.body.textContent).toContain("You can't view changes");
    expect(mocks.get.mock.calls.some(([p]) => String(p).startsWith('/dcim/'))).toBe(false);
  });

  it('pages 50 at a time', async () => {
    answer({ '/dcim/changes': () => page([C_ASSET], 120) });
    await mount('/inventory?lens=changes', READ);
    expect(document.body.textContent).toContain('Page 1 of 3');
    await click(q('[data-testid="changes-next"]'));
    await flush();
    expect(lastQuery()).toMatchObject({ offset: 50, limit: 50 });
  });
});

describe('<ObjectChanges> with related changes', () => {
  it('asks for related changes and names the related object on its row', async () => {
    answer({ '/dcim/changes': () => page([C_IFACE, C_ASSET]), '/dcim/changes/{id}': () => ({ data: { data: DETAIL } }) });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    await act(async () => {
      root.render(<QueryClientProvider client={qc}><MemoryRouter><ObjectChanges kind="asset" id={ASSET_ID} includeRelated /></MemoryRouter></QueryClientProvider>);
    });
    await flush();
    expect(lastQuery()).toMatchObject({ object_kind: 'asset', object_id: ASSET_ID, include_related: true });
    const rows = qa('[data-testid="change-row"]').map((r) => r.textContent ?? '');
    expect(rows[0]).toContain('Interface eth0');
    expect(rows[0]).toContain('updated');
    expect(rows[1]).not.toContain('Interface');
    await click(qa('[data-testid="change-toggle"]')[0]);
    await flush();
    expect(q('[data-testid="change-diff"]')?.textContent).toContain('9000');
  });
});

describe('helpers', () => {
  it('CSV: header, joined fields, and a formula-looking cell is neutralised', () => {
    const csv = changesCsv([change({ object_label: '=HYPERLINK("x")', changed_fields: ['a', 'b'] }) as never]).split('\n');
    expect(csv[0]).toBe('when,who,source,kind,object,object_id,action,fields_changed');
    expect(csv[1]).toContain('"\'=HYPERLINK(""x"")"');
    expect(csv[1]).toContain('a;b');
  });
  it('links only live assets', () => {
    expect(objectHref({ object_kind: 'asset', object_id: 'x', action: 'update' })).toBe('/inventory/assets/x');
    expect(objectHref({ object_kind: 'asset', object_id: 'x', action: 'delete' })).toBeNull();
    expect(objectHref({ object_kind: 'interface', object_id: 'x', action: 'update' })).toBeNull();
  });
  it('diff values', () => {
    expect([diffValueText(null), diffValueText(''), diffValueText('a'), diffValueText(3), diffValueText({ a: 1 })]).toEqual(['—', '(empty)', 'a', '3', '{"a":1}']);
  });
});
