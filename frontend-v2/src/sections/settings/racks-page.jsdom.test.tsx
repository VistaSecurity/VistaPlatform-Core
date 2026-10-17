// @vitest-environment jsdom
// Settings → Racks (DCIM row 2.3): the five states, the table (site ›
// location, role, status, utilisation — a real 0 % for an empty rack), the
// write controls behind dcim.manage, creating a rack with a rack type, and
// the Reservations tab (list, reserve, a refusal naming what is in the way).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { RacksPage } from './racks-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const sub = { source_kind: 'declared', custom_fields: {}, created_at: '', updated_at: '', created_by: null, description: null, comments: null, external_ids: {} };
const rack = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  ...sub, id, tenant_id: 't', name, facility_id: null, site_id: 'ams', location_id: 'row3', business_unit_id: null, role_id: 'net', rack_type_id: null,
  operational_status: 'active', serial: null, asset_tag: null, form_factor: null, width: 19, u_height: 42, starting_unit: 1, desc_units: false,
  outer_width: null, outer_depth: null, outer_unit: null, mounting_depth: null, weight: null, max_weight: null, weight_unit: null, airflow: null,
  site: { id: 'ams', name: 'AMS-1', slug: 'ams-1' }, location: { id: 'row3', name: 'Row 3' }, role: { id: 'net', name: 'Network', slug: 'network', color: '4caf50' },
  rack_type: null, utilization: { used_units: 12, total_units: 42, utilization: 28.57 }, device_count: 9, ...extra,
});
const DATA: Record<string, unknown> = {
  '/dcim/racks': { data: [rack('r12', 'R12'), rack('r13', 'R13', { location_id: null, location: null, role_id: null, role: null, utilization: { used_units: 0, total_units: 42, utilization: 0 }, device_count: 0 })], pagination: {} },
  '/dcim/sites': { sites: [{ id: 'ams', name: 'AMS-1' }], total: 1 },
  '/dcim/locations': { locations: [{ id: 'row3', site_id: 'ams', parent_id: null, name: 'Row 3' }], total: 1 },
  '/dcim/rack-roles': { data: [{ id: 'net', name: 'Network' }], pagination: {} },
  '/dcim/rack-types': { data: [{ id: 'ar', model: 'AR3100', u_height: 48, manufacturer: { id: 'm', name: 'APC', slug: 'apc' } }], pagination: {} },
  '/dcim/rack-reservations': { data: [{ ...sub, id: 'res1', rack_id: 'r12', units: [1, 2], description: 'Future PDU', user_id: null, business_unit_id: null }], pagination: {} },
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
  const meta = { key: 'racks', label: 'Racks', icon: 'server', job: 'Racks' };
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={cache}><PermissionProvider><RacksPage meta={meta} /></PermissionProvider></QueryClientProvider></MemoryRouter>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const btn = (re: RegExp) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent ?? '') || re.test(b.getAttribute('aria-label') ?? ''));
const set = (el: Element, v: string) => act(async () => {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement : HTMLInputElement;
  Object.getOwnPropertyDescriptor(proto.prototype, 'value')!.set!.call(el, v);
  el.dispatchEvent(new Event(proto === HTMLInputElement ? 'input' : 'change', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 0));
});
const option = (label: string, value: string) => vi.waitFor(() => expect(document.querySelector(`select[aria-label="${label}"] option[value="${value}"]`)).not.toBeNull());

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render(['dcim.read']);
  expect(host.textContent).toContain('Loading racks');
});

it('error', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: 'x' } });
  await render(['dcim.read']);
  expect(host.textContent).toContain("Couldn't load racks");
});

it('empty', async () => {
  serve({ ...DATA, '/dcim/racks': { data: [], pagination: {} } });
  await render(['dcim.read', 'dcim.manage']);
  expect(host.textContent).toContain('No racks');
});

it('default: the table, utilisation (a real 0 %), and no write controls for a reader', async () => {
  serve();
  await render(['dcim.read']);
  const rows = [...host.querySelectorAll('[data-testid="racks-row"]')].map((e) => e.textContent);
  expect(rows).toEqual(['R12', 'R13']);
  const util = [...host.querySelectorAll('[data-testid="racks-utilisation"]')].map((e) => e.textContent);
  expect(util).toEqual(['12 / 42U · 28.57%', '0 / 42U · 0%']);
  expect(host.textContent).toContain('AMS-1 › Row 3');
  expect(btn(/New rack/)).toBeUndefined();
  expect(btn(/Edit R12/)).toBeUndefined();
});

it('success: a manager creates a rack in a site and row with a rack type', async () => {
  serve();
  api.POST.mockResolvedValue({ data: { data: rack('new', 'R14') }, response: { ok: true, status: 201 } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/New rack/)!.click(); });
  await set(document.querySelector('input[aria-label="Name"]')!, 'R14');
  await option('Site', 'ams');
  await set(document.querySelector('select[aria-label="Site"]')!, 'ams');
  await option('Location', 'row3');
  await set(document.querySelector('select[aria-label="Location"]')!, 'row3');
  await option('Rack type', 'ar');
  await set(document.querySelector('select[aria-label="Rack type"]')!, 'ar');
  // The type supplies the dimensions: the inputs lock and are not sent.
  expect((document.querySelector('input[aria-label="Height (U)"]') as HTMLInputElement).disabled).toBe(true);
  await act(async () => { btn(/^Create rack$/)!.click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
  expect(api.POST.mock.calls[0][0]).toBe('/dcim/racks');
  const body = (api.POST.mock.calls[0][1] as { body: Record<string, unknown> }).body;
  expect(body).toMatchObject({ name: 'R14', site_id: 'ams', location_id: 'row3', rack_type_id: 'ar' });
  expect(body).not.toHaveProperty('u_height');
});

it('reservations: listed, a manager reserves units, and a refusal names the device in the way', async () => {
  serve();
  api.POST.mockResolvedValue({ error: { error: { code: 'placement_conflict', message: 'U10 is occupied', blocking_asset: { id: 'sw1', name: 'core-sw-1', position: 10, face: 'front', u_height: 2 } } }, response: { ok: false, status: 409 } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/Edit R12/)!.click(); });
  await act(async () => { btn(/^Reservations$/)!.click(); });
  await vi.waitFor(() => expect(document.querySelector('[data-testid="reservation-row"]')?.textContent).toContain('U1–U2'));
  expect(document.querySelector('[data-testid="reservation-row"]')!.textContent).toContain('Future PDU');
  await set(document.querySelector('input[aria-label="Units"]')!, '10-11');
  await set(document.querySelector('input[aria-label="Reservation description"]')!, 'Spare');
  await act(async () => { btn(/^Reserve$/)!.click(); });
  await vi.waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
  expect(api.POST.mock.calls[0][1]).toMatchObject({ body: { rack_id: 'r12', units: [10, 11], description: 'Spare' } });
  await vi.waitFor(() => expect(document.querySelector('[data-testid="placement-conflict-asset"]')?.getAttribute('href')).toBe('/inventory/assets/sw1'));
});

it('delete: says the devices leave the rack and stay in the site', async () => {
  serve();
  api.DELETE.mockResolvedValue({ response: { ok: true, status: 204 } });
  await render(['dcim.read', 'dcim.manage']);
  await act(async () => { btn(/Delete R12/)!.click(); });
  expect(document.body.textContent).toContain('Its 9 devices leave the rack and stay in the site.');
  await act(async () => { btn(/^Delete$/)!.click(); });
  await vi.waitFor(() => expect(api.DELETE).toHaveBeenCalledWith('/dcim/racks/{id}', { params: { path: { id: 'r12' } } }));
});
