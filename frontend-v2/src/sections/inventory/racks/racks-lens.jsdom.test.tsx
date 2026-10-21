// @vitest-environment jsdom
// Inventory → Racks (DCIM row 2.5): the five states, the columns (site ›
// location, role, status, height, a real 0 % utilisation, devices, business
// unit), the filters reaching the API (site from the URL, so the site page's
// card lands filtered), a row opening the rack page, and the CSV export.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { RacksLens, racksCsvRows } from './racks-lens';
import { fillColor } from '../../dashboard/facilities-dashboard-metrics';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
type ApiCall = (path: string, opts?: { params?: { path?: Record<string, string>; query?: Record<string, unknown> }; body?: unknown }) => Promise<unknown>;
const api = vi.hoisted(() => ({ GET: vi.fn<ApiCall>() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

const rack = (id: string, name: string, over: Record<string, unknown> = {}) => ({
  id, name, facility_id: null, site_id: 'ams', location_id: 'row3', business_unit_id: 'bu1', role_id: 'net', rack_type_id: null,
  operational_status: 'active', u_height: 42, starting_unit: 1, desc_units: false,
  site: { id: 'ams', name: 'AMS-1' }, location: { id: 'row3', name: 'Row 3' }, role: { id: 'net', name: 'Network' },
  utilization: { used_units: 12, total_units: 42, utilization: 28.6 }, device_count: 9, ...over,
});
const RACKS = [rack('r12', 'R12'), rack('r13', 'R13', { location: null, role: null, utilization: { used_units: 0, total_units: 42, utilization: 0 }, device_count: 0, business_unit_id: null })];

function serve(racks: unknown[] | Promise<never> | 'error') {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/racks') {
      if (racks === 'error') return { data: undefined, error: { error: 'x' } };
      if (racks instanceof Promise) return racks;
      return { data: { data: racks, pagination: {} } };
    }
    if (path === '/dcim/sites') return { data: { sites: [{ id: 'ams', name: 'AMS-1' }, { id: 'nyc', name: 'NYC-1' }], total: 2 } };
    if (path === '/dcim/business-units') return { data: { business_units: [{ id: 'bu1', name: 'Platform' }] } };
    if (path === '/dcim/rack-roles') return { data: { data: [{ id: 'net', name: 'Network' }] } };
    return { data: { locations: [], data: [], total: 0 } };
  });
}

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.GET.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(url = '/inventory?lens=racks') {
  cache.setQueryData(['user-permissions'], ['dcim.read']);
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><MemoryRouter initialEntries={[url]}><RacksLens /></MemoryRouter></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const racksQuery = () => { const calls = api.GET.mock.calls.filter((c) => c[0] === '/dcim/racks'); return calls[calls.length - 1]?.[1]?.params?.query; };

it('loading', async () => {
  serve(new Promise<never>(() => {}));
  await render();
  expect(host.textContent).toContain('Loading racks');
});

it('error', async () => {
  serve('error');
  await render();
  expect(host.querySelector('[data-testid="substrate-error"]')?.textContent).toContain('Failed to load racks');
});

it('empty: no racks yet says where to add them', async () => {
  serve([]);
  await render();
  expect(host.textContent).toContain('No racks yet');
  expect(host.textContent).toContain('Infrastructure → Racks');
});

it('filtered empty is its own state', async () => {
  serve([]);
  await render('/inventory?lens=racks&status=planned');
  expect(host.textContent).toContain('No racks match');
});

it('default: the columns, a real 0 %, and rows that open the rack page', async () => {
  serve(RACKS);
  await render();
  const rows = [...host.querySelectorAll('[data-testid="rack-row"]')];
  expect(rows).toHaveLength(2);
  expect(rows[0].getAttribute('href')).toBe('/inventory/racks/r12');
  expect(rows[0].textContent).toContain('AMS-1 › Row 3');
  expect(rows[0].textContent).toContain('Network');
  expect(rows[0].textContent).toContain('12 / 42U · 28.6%');
  expect(rows[0].textContent).toContain('Platform');
  expect(rows[1].textContent).toContain('0 / 42U · 0%');
  expect(host.querySelector('[data-testid="racks-count"]')?.textContent).toBe('2 racks');
});

it('filters: the site from the URL and the role/status selects reach the API', async () => {
  serve(RACKS);
  await render('/inventory?lens=racks&site=ams');
  expect(racksQuery()).toMatchObject({ site_id: 'ams' });
  const status = host.querySelector('select[aria-label="Status"]') as HTMLSelectElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(status, 'planned');
    status.dispatchEvent(new Event('change', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 0));
  });
  expect(racksQuery()).toMatchObject({ site_id: 'ams', operational_status: 'planned' });
});

it('power (row 6.2): the budget share in the capacity colour; a rack no feed serves says so, never 0 %', async () => {
  serve([rack('r12', 'R12', { power_utilization: { feed_count: 2, available_power: 10566, allocated_draw: 9600, utilization: 90.9, measured_draw: null } }), RACKS[1]]);
  await render();
  const cells = [...host.querySelectorAll('[data-testid="rack-power-cell"]')];
  expect(cells.map((c) => c.textContent)).toEqual(['90.9%', 'no feed']);
  expect((cells[0] as HTMLElement).style.color).toBe(fillColor(90.9));
  expect(cells[0].getAttribute('title')).toBe('9600 W of 10566 VA on 2 feeds');
});

it('CSV rows carry what the list shows', () => {
  const rows = racksCsvRows(RACKS as never, (id) => (id === 'bu1' ? 'Platform' : ''));
  expect(rows[0]).toEqual(['R12', null, 'AMS-1', 'Row 3', 'Network', 'Active', 42, 12, 28.6, '', 9, 'Platform', 'r12']);
  expect(rows[1].slice(3, 5)).toEqual(['', '']);
});
