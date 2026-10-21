// @vitest-environment jsdom
// Dashboard · Facilities: the five states (loading, error, empty, default,
// success-after-sort), the permission notice, the tiles' null-not-zero rule and
// every drill-through link.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { FacilitiesDashboardPage } from './facilities-dashboard';
import { report } from './facilities-test-fixture';
import type { CapacityReport } from './facilities-queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
type ApiCall = (path: string) => Promise<unknown>;
const api = vi.hoisted(() => ({ GET: vi.fn<ApiCall>() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const FULL: CapacityReport = report({
  sites_total: 2,
  rack_totals: { racks: 3, total_units: 126, used_units: 60, reserved_units: 6, free_units: 60, racks_over_80: 1, racks_over_95: 1, racks_with_power: 2, racks_over_power_budget: 1 },
  sites: [
    { site_id: 's-ams', site_name: 'AMS-1', racks: 2, total_units: 84, used_units: 70, reserved_units: 6, free_units: 8, utilization: 83.3, racks_over_80: 1, racks_over_95: 1, racks_with_power: 2, racks_over_power_budget: 1 },
    { site_id: 's-nyc', site_name: 'NYC-1', racks: 1, total_units: 42, used_units: 4, reserved_units: 0, free_units: 38, utilization: 9.5, racks_over_80: 0, racks_over_95: 0, racks_with_power: 0, racks_over_power_budget: 0 },
  ],
  racks_top: [{ rack_id: 'r12', rack_name: 'R12', site_id: 's-ams', site_name: 'AMS-1', used_units: 41, total_units: 42, utilization: 97.6 }],
  ports: { switches: 2, total: 96, cabled: 40, marked_connected: 2, free: 7, fewest_free: [{ asset_id: 'sw1', name: 'core-sw-1', total: 48, cabled: 45, marked_connected: 0, free: 3 }] },
  prefixes: {
    total: 5, no_addresses_recorded: 2, over_80: 2, over_95: 1,
    fullest: [
      { prefix_id: 'p1', prefix: '10.0.0.0/24', vrf_id: null, vrf_name: null, size: '256', ip_count: 250, child_count: 0, utilization: 97.7 },
      { prefix_id: 'p2', prefix: '10.1.0.0/24', vrf_id: 'v1', vrf_name: 'blue', size: '256', ip_count: 210, child_count: 0, utilization: 82 },
    ],
  },
  cables: {
    by_status: { connected: 30, planned: 4, decommissioning: 1 }, proposed_pending: 3, planned_over_30_days: 2, planned_over_90_days: 1,
    oldest_planned: [{ cable_id: 'c5', label: 'patch-7', created_at: '2026-03-30T00:00:00Z', age_days: 92 }, { cable_id: 'c4', label: null, created_at: '2026-05-01T00:00:00Z', age_days: 60 }],
    declared_never_confirmed: 1,
  },
});

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.GET.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(perms: string[] = ['dcim.read']) {
  cache.setQueryData(['user-permissions'], perms);
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><MemoryRouter><FacilitiesDashboardPage /></MemoryRouter></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const serve = (data: CapacityReport) => api.GET.mockResolvedValue({ data: { data } });

it('loading: tiles show an em dash, never a zero, and panels say so', async () => {
  api.GET.mockReturnValue(new Promise<never>(() => {}));
  await render();
  expect(host.textContent).toContain('Loading…');
  // Value and label are adjacent in the tile, so "—Label" is a dash, not a zero.
  for (const l of ['Free rack space', 'Racks over 95%', 'Racks over power budget', 'Prefixes over 95%', 'Planned cables over 90 days', 'Free switch interfaces']) {
    expect(host.textContent).toContain('—' + l);
  }
});

it('error: a failed roll-up is an error page, not a row of zeros', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: 'x' } });
  await render();
  expect(host.textContent).toContain("Couldn't load the Facilities dashboard");
  expect(host.querySelector('[data-testid="facilities-site-row"]')).toBeNull();
});

it('empty: nothing recorded points at Racks instead of drawing zeros', async () => {
  serve(report());
  await render();
  expect(host.textContent).toContain('Nothing to roll up yet');
  expect(host.querySelector('a[href="/inventory?lens=racks"]')).not.toBeNull();
});

it('default: tiles carry the roll-up figures', async () => {
  serve(FULL);
  await render();
  const t = host.textContent ?? '';
  expect(t).toContain('Free rack space');
  expect(t).toContain('60'); // free U
  expect(t).toContain('Racks over 95%');
  expect(t).toContain('Planned cables over 90 days');
  expect(t).toContain('Free switch interfaces');
  expect(t).toContain('2 with no addresses recorded');
  expect(t).toContain('1 declared cable has never been confirmed');
});

it('power budget (row 6.2): the tile counts racks over their feeds, the site table says which site; no feed is a dash, not 0', async () => {
  serve(FULL);
  await render();
  expect(host.textContent).toContain('1Racks over power budget');
  expect(host.textContent).toContain('of 2 with power feeds');
  const cells = [...host.querySelectorAll('[data-testid="facilities-site-power"]')];
  expect(cells.map((c) => c.textContent)).toEqual(['1', '—']);
  expect(cells[1].getAttribute('title')).toBe('No rack here has a power feed declared');
});

it('every drill-through link lands on the list that counted the number', async () => {
  serve(FULL);
  await render();
  const all = [...host.querySelectorAll('a')].map((a) => a.getAttribute('href'));
  expect(all).toContain('/inventory?lens=racks&site=s-ams');
  expect(all).toContain('/inventory/racks/r12');
  expect(all).toContain('/inventory/assets/sw1/ports');
  expect(all).toContain('/inventory/prefixes/p1');
  expect(all).toContain('/inventory?lens=cabling&status=planned');
  expect(all).toContain('/inventory?lens=cabling&status=pending');
  expect(all).toContain('/inventory/cables/c5');
});

it('the VRF is named, and a global prefix says Global rather than nothing', async () => {
  serve(FULL);
  await render();
  const rows = [...host.querySelectorAll('[data-testid="facilities-prefix-row"]')].map((r) => r.textContent);
  expect(rows[0]).toContain('Global');
  expect(rows[1]).toContain('blue');
});

it('the site table sorts by a clicked header, flipping on a second click', async () => {
  serve(FULL);
  await render();
  const names = () => [...host.querySelectorAll('[data-testid="facilities-site-row"] a')].map((a) => a.textContent);
  expect(names()).toEqual(['AMS-1', 'NYC-1']); // utilisation, fullest first
  const free = [...host.querySelectorAll('th button')].find((b) => b.textContent?.startsWith('Free')) as HTMLButtonElement;
  await act(async () => { free.click(); });
  expect(names()).toEqual(['NYC-1', 'AMS-1']); // most free first
  await act(async () => { free.click(); });
  expect(names()).toEqual(['AMS-1', 'NYC-1']); // flipped: least free first
  expect(host.querySelector('th[aria-sort="ascending"]')?.textContent).toContain('Free');
});

it('a truncated site table says how many sites there are', async () => {
  serve({ ...FULL, sites_total: 500 });
  await render();
  expect(host.textContent).toContain('Showing the 2 fullest of 500 sites.');
});

it('a panel with no rows says why, per panel', async () => {
  serve(report({ prefixes: { ...report().prefixes, total: 3, no_addresses_recorded: 3 }, rack_totals: { ...report().rack_totals, racks: 1 } }));
  await render();
  expect(host.textContent).toContain('No prefix has addresses recorded yet.');
  expect(host.textContent).toContain('No switch has interfaces recorded.');
  expect(host.textContent).toContain('No planned cable is older than 30 days.');
});

it('without dcim.read the page says what permission it needs and asks for nothing', async () => {
  serve(FULL);
  await render(['assets.read']);
  expect(host.textContent).toContain('needs the data-centre read permission');
  expect(api.GET).not.toHaveBeenCalled();
});
