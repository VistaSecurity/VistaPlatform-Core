// @vitest-environment jsdom
// Settings → Module Types (DCIM row 2.4): the five states, platform rows
// read-only, the write controls behind dcim.manage, creating a module type,
// and the page's registration in the Settings nav and router.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ModuleTypesPage } from './module-types-page';
import { settingsPageMeta } from './nav';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

const mt = (id: string, model: string, tenant: string | null) => ({ id, tenant_id: tenant, manufacturer_id: 'cisco', model, slug: id, part_number: model });
const DATA: Record<string, unknown> = {
  '/dcim/module-types': { data: [mt('a', 'C9300-NM-8X', null), mt('b', 'ACME-LC-48', 't')], pagination: {} },
  '/dcim/manufacturers': { data: [{ id: 'cisco', name: 'Cisco' }], pagination: {} },
};
const serve = (data = DATA) => api.GET.mockImplementation(async (path: string) => (path in data ? { data: data[path] } : { data: {} }));

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } }, });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); document.body.innerHTML = ''; });

async function render(perms: string[]) {
  cache.setQueryData(['user-permissions'], perms);
  const meta = { key: 'module-types', label: 'Module Types', icon: 'blocks', job: 'Module types' };
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={cache}><PermissionProvider><ModuleTypesPage meta={meta} /></PermissionProvider></QueryClientProvider></MemoryRouter>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const text = () => document.body.textContent ?? '';
const btn = (re: RegExp) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));
const set = (el: Element, v: string) => act(async () => {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement : HTMLInputElement;
  Object.getOwnPropertyDescriptor(proto.prototype, 'value')!.set!.call(el, v);
  el.dispatchEvent(new Event(proto === HTMLInputElement ? 'input' : 'change', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 0));
});

it('default: platform and tenant rows; only the tenant row can be deleted', async () => {
  serve();
  await render(['dcim.read', 'dcim.manage']);
  await vi.waitFor(() => expect(document.querySelectorAll('[data-testid="module-type-row"]')).toHaveLength(2));
  expect(text()).toContain('Platform');
  expect(text()).toContain('Yours');
  expect(btn(/Delete ACME-LC-48/)).toBeDefined();
  expect(btn(/Delete C9300-NM-8X/)).toBeUndefined();
});

it('empty: says how module types are used', async () => {
  serve({ ...DATA, '/dcim/module-types': { data: [], pagination: {} } });
  await render(['dcim.read']);
  await vi.waitFor(() => expect(text()).toContain('No module types'));
  expect(text()).toContain('install it into an asset');
});

it('loading: says it is fetching', async () => {
  api.GET.mockImplementation(() => new Promise(() => {}));
  await render(['dcim.read']);
  expect(text()).toContain('Loading module types');
});

it('error: the reason', async () => {
  api.GET.mockImplementation(async () => ({ error: { error: { code: 'internal_error', message: 'database unavailable' } } }));
  await render(['dcim.read']);
  await vi.waitFor(() => expect(text()).toContain("Couldn't load module types"));
});

it('read-only: no New module type and no delete', async () => {
  serve();
  await render(['dcim.read']);
  await vi.waitFor(() => expect(document.querySelectorAll('[data-testid="module-type-row"]')).toHaveLength(2));
  expect(btn(/New module type/)).toBeUndefined();
  expect(btn(/Delete ACME-LC-48/)).toBeUndefined();
});

it('success: creates a module type with its manufacturer, model and part number', async () => {
  serve();
  api.POST.mockResolvedValue({ data: { data: mt('c', 'C9300-NM-2Y', 't') } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/New module type/)!.click(); });
  await vi.waitFor(() => expect(document.querySelector('select[aria-label="Manufacturer"] option[value="cisco"]')).not.toBeNull());
  await set(document.querySelector('select[aria-label="Manufacturer"]')!, 'cisco');
  await set(document.querySelector('input[aria-label="Model"]')!, 'C9300-NM-2Y');
  await set(document.querySelector('input[aria-label="Part number"]')!, 'C9300-NM-2Y');
  await act(async () => { btn(/^Create$/)!.click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledWith('/dcim/module-types', { body: { manufacturer_id: 'cisco', model: 'C9300-NM-2Y', part_number: 'C9300-NM-2Y' } }));
});

it('is registered in the Settings nav behind dcim.read', () => {
  const meta = settingsPageMeta('module-types');
  expect(meta.label).toBe('Module Types');
  expect(meta.built).toBe(true);
  expect(meta.permission).toBe('dcim.read');
});
