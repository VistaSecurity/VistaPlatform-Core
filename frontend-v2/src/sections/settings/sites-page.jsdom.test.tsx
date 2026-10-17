// @vitest-environment jsdom
// Settings → Sites (DCIM row 2.1): the five states, the Region › Site group ›
// Site › Location tree, the write controls behind dcim.manage, creating a site
// and a location inside it, and delete-with-reassign for a site holding assets.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { SitesPage } from './sites-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const sub = { source_kind: 'declared', custom_fields: {}, created_at: '', updated_at: '', description: null, comments: null };
const region = (id: string, name: string, parent_id: string | null = null) => ({ ...sub, id, tenant_id: 't', name, slug: name.toLowerCase(), parent_id, site_count: 0 });
const site = (id: string, name: string, region_id: string | null, group_id: string | null, asset_count = 0) => ({
  ...sub, id, tenant_id: 't', name, slug: name.toLowerCase(), operational_status: 'active', region_id, group_id, facility: null, time_zone: null,
  physical_address: null, shipping_address: null, latitude: null, longitude: null, business_unit_id: null, asns: [], external_ids: {}, asset_count,
});
const location = (id: string, site_id: string, name: string, parent_id: string | null = null) => ({
  ...sub, id, tenant_id: 't', site_id, parent_id, name, slug: name.toLowerCase(), operational_status: 'active', facility: null, business_unit_id: null, path: name, asset_count: 0,
});
const DATA: Record<string, unknown> = {
  '/dcim/regions': { regions: [region('eu', 'Europe'), region('nl', 'Netherlands', 'eu')], total: 2 },
  '/dcim/site-groups': { site_groups: [region('br', 'Branches')], total: 1 },
  '/dcim/sites': { sites: [site('ams', 'AMS-1', 'nl', 'br', 3), site('nyc', 'NYC-1', null, null)], total: 2 },
  '/dcim/locations': { locations: [location('h2', 'ams', 'Hall 2'), location('c7', 'ams', 'Cage 7', 'h2')], total: 2 },
};
const serve = (data = DATA) => api.GET.mockImplementation(async (path: string) => (path in data ? { data: data[path] } : { data: { changes: [], journal_entries: [], entries: [], total: 0 } }));

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(perms: string[]) {
  cache.setQueryData(['user-permissions'], perms);
  const meta = { key: 'sites', label: 'Sites', icon: 'map-pin', job: 'Sites' };
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={cache}><PermissionProvider><SitesPage meta={meta} /></PermissionProvider></QueryClientProvider></MemoryRouter>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const btn = (re: RegExp) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));
const rows = (kind: string) => [...host.querySelectorAll(`[data-testid="sites-row-${kind}"]`)].map((e) => e.textContent ?? '');
const set = (el: Element, v: string) => act(async () => {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement : HTMLInputElement;
  Object.getOwnPropertyDescriptor(proto.prototype, 'value')!.set!.call(el, v);
  el.dispatchEvent(new Event(proto === HTMLInputElement ? 'input' : 'change', { bubbles: true }));
});

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read']);
  expect(host.textContent).toContain('Loading sites');
});

it('error', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: 'x' } });
  await render(['dcim.read']);
  expect(host.textContent).toContain("Couldn't load sites");
});

it('empty', async () => {
  serve({ '/dcim/regions': { regions: [], total: 0 }, '/dcim/site-groups': { site_groups: [], total: 0 }, '/dcim/sites': { sites: [], total: 0 }, '/dcim/locations': { locations: [], total: 0 } });
  await render(['dcim.read', 'dcim.manage']);
  expect(host.textContent).toContain('No sites');
});

it('default: Region › Site group › Site › Location, and no write controls for a reader', async () => {
  serve();
  await render(['dcim.read']);
  expect(rows('region')).toEqual(['Europe', 'Netherlands']);
  expect(rows('site_group')).toEqual(['Branches']);
  expect(rows('site')).toEqual(['AMS-1', 'NYC-1']);
  expect(rows('location')).toEqual(['Hall 2', 'Cage 7']);
  // The site row links to the site page.
  expect(host.querySelector('a[href="/inventory/sites/ams"]')).not.toBeNull();
  expect(btn(/New site/)).toBeUndefined();
  expect(btn(/Edit AMS-1/)).toBeUndefined();
});

it('success: a manager creates a site in a region, then a location inside it', async () => {
  serve();
  api.POST.mockImplementation(async (path: string) => ({ data: path === '/dcim/sites' ? site('new', 'RTM-1', 'nl', null) : location('l', 'ams', 'Hall 3'), response: { ok: true, status: 201 } }));
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/New site/)!.click(); });
  await set(document.querySelector('input[aria-label="Name"]')!, 'RTM-1');
  await set(document.querySelector('select[aria-label="Region"]')!, 'nl');
  await set(document.querySelector('input[aria-label="Time zone"]')!, 'Europe/Amsterdam');
  await act(async () => { btn(/^Create site$/)!.click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
  expect(api.POST.mock.calls[0][0]).toBe('/dcim/sites');
  expect((api.POST.mock.calls[0][1] as { body: unknown }).body).toMatchObject({ name: 'RTM-1', region_id: 'nl', time_zone: 'Europe/Amsterdam', group_id: null });

  await act(async () => { btn(/Add a location in AMS-1/)!.click(); });
  expect((document.querySelector('select[aria-label="Site"]') as HTMLSelectElement).value).toBe('ams');
  await set(document.querySelector('input[aria-label="Name"]')!, 'Hall 3');
  await act(async () => { btn(/^Create location$/)!.click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(2));
  expect(api.POST.mock.calls[1][0]).toBe('/dcim/locations');
  expect((api.POST.mock.calls[1][1] as { body: unknown }).body).toMatchObject({ site_id: 'ams', name: 'Hall 3', parent_id: null });
});

it('delete: a site with assets must name where they go, and sends reassign_to', async () => {
  serve();
  api.DELETE.mockResolvedValue({ response: { ok: true, status: 204 } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/Delete AMS-1/)!.click(); });
  expect(btn(/^Delete$/)!.disabled).toBe(true);
  await set(document.querySelector('select[aria-label="Move its assets to"]')!, 'nyc');
  expect(btn(/^Delete$/)!.disabled).toBe(false);
  await act(async () => { btn(/^Delete$/)!.click(); });
  await vi.waitFor(() => expect(api.DELETE).toHaveBeenCalledTimes(1));
  expect(api.DELETE.mock.calls[0][0]).toBe('/dcim/sites/{id}');
  expect((api.DELETE.mock.calls[0][1] as { params: unknown }).params).toEqual({ path: { id: 'ams' }, query: { reassign_to: 'nyc' } });
});

it('edit: a site\'s dialog carries its Changes and Journal panels', async () => {
  serve();
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/Edit AMS-1/)!.click(); });
  expect(document.querySelector('[data-testid="sites-history"]')).not.toBeNull();
  await vi.waitFor(() => expect(api.GET.mock.calls.some((c) => String(c[0]).includes('/dcim/changes'))).toBe(true));
});
