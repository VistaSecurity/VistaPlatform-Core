// @vitest-environment jsdom
// The site page (DCIM row 2.1): its five states, the counts and the locations,
// and that it is reachable — the route is registered and the Sites lens has a
// nav home.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { SitePage } from './site-page';
import { SECTIONS } from '../../../app/nav';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

const SITE = {
  id: 'ams', tenant_id: 't', name: 'AMS-1', slug: 'ams-1', operational_status: 'active', region_id: 'nl', group_id: null,
  facility: 'Equinix AM3', time_zone: 'Europe/Amsterdam', physical_address: 'Science Park 610, Amsterdam', shipping_address: null,
  latitude: 52.35, longitude: 4.95, business_unit_id: null, asns: [64512], external_ids: {}, description: null, comments: null,
  source_kind: 'declared', custom_fields: {}, created_at: '', updated_at: '', region_name: 'Netherlands', group_name: null,
  business_unit_name: null, asset_count: 3, counts: { assets: 3, locations: 2, racks: 0, prefixes: 4, vlans: 1 },
};
const LOC = (id: string, name: string, parent_id: string | null) => ({ id, tenant_id: 't', site_id: 'ams', parent_id, name, slug: id, operational_status: 'active', facility: null, business_unit_id: null, source_kind: 'declared', custom_fields: {}, created_at: '', updated_at: '', path: name, asset_count: 1 });

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.GET.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(permissions: string[] = ['dcim.read', 'dcim.manage']) {
  cache.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><PermissionProvider><MemoryRouter initialEntries={['/inventory/sites/ams']}>
      <Routes><Route path="/inventory/sites/:id" element={<SitePage />} /></Routes>
    </MemoryRouter></PermissionProvider></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}

it('loading', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render();
  expect(host.textContent).toContain('Loading site');
});

it('error', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: 'x' }, response: { status: 500 } });
  await render();
  expect(host.textContent).toContain('Failed to load the site');
});

it('not found is its own empty state', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: 'x' }, response: { status: 404 } });
  await render();
  expect(host.textContent).toContain('Site not found');
});

it('default: the overview — where, the counts, the location tree and the findings by environment', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/sites/{id}') return { data: SITE, response: { status: 200 } };
    if (path === '/dcim/locations') return { data: { locations: [LOC('c7', 'Cage 7', 'h2'), LOC('h2', 'Hall 2', null)], total: 2 } };
    if (path === '/operational/sites/{id}/environments') return { data: { environments: [{ environment: 'production', asset_count: 3, crypto_config_count: 0, certificate_count: 0, critical_findings: 1, high_findings: 0, medium_findings: 0, low_findings: 0, expiring_certs_30d: 0, expired_certs: 0 }] } };
    return { data: { changes: [], journal_entries: [], entries: [], total: 0 } };
  });
  await render();
  expect(host.querySelector('[data-testid="site-page"]')).not.toBeNull();
  expect(host.textContent).toContain('AMS-1');
  expect(host.textContent).toContain('Science Park 610, Amsterdam');
  expect(host.textContent).toContain('Europe/Amsterdam');
  expect(host.querySelector('[data-testid="site-count-prefixes"]')!.textContent).toContain('4');
  expect(host.querySelector('[data-testid="site-count-racks"]')!.textContent).toContain('0');
  // The assets count opens the asset list filtered to this site.
  expect(host.querySelector('[data-testid="site-count-assets"]')!.getAttribute('href')).toContain(encodeURIComponent('site.id = "ams"'));
  expect([...host.querySelectorAll('[data-testid="site-location"]')].map((e) => e.textContent)).toEqual(['Hall 21', 'Cage 71']);
  expect(host.textContent).toContain('1 critical');
  // Contacts and Images of the site itself (row 2.8): the panels are mounted
  // with kind=site and this site's id.
  expect(host.querySelector('[data-testid="site-contacts"] [data-testid="object-contacts"]')).not.toBeNull();
  expect(host.querySelector('[data-testid="site-images"] [data-testid="object-images"]')).not.toBeNull();
  expect(api.GET).toHaveBeenCalledWith('/dcim/objects/{kind}/{id}/contacts', { params: { path: { kind: 'site', id: 'ams' }, query: { limit: 200 } } });
  expect(api.GET).toHaveBeenCalledWith('/dcim/objects/{kind}/{id}/images', { params: { path: { kind: 'site', id: 'ams' }, query: { limit: 200 } } });
  expect(api.GET).toHaveBeenCalledWith('/dcim/locations', { params: { query: { site_id: 'ams' } } });
});

it('without dcim.read the contacts and images panels are not mounted or fetched', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/sites/{id}') return { data: SITE, response: { status: 200 } };
    if (path === '/dcim/locations') return { data: { locations: [], total: 0 } };
    if (path === '/operational/sites/{id}/environments') return { data: { environments: [] } };
    return { data: { changes: [], journal_entries: [], entries: [], total: 0 } };
  });
  await render(['sites.read']);
  expect(host.querySelector('[data-testid="site-page"]')).not.toBeNull();
  expect(host.querySelector('[data-testid="object-contacts"]')).toBeNull();
  expect(host.querySelector('[data-testid="object-images"]')).toBeNull();
  expect(api.GET.mock.calls.some(([p]) => String(p).includes('/contacts') || String(p).includes('/images'))).toBe(false);
});

it('empty: a site with no locations says where to add them', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/sites/{id}') return { data: { ...SITE, counts: { assets: 0, locations: 0, racks: 0, prefixes: 0, vlans: 0 } }, response: { status: 200 } };
    if (path === '/dcim/locations') return { data: { locations: [], total: 0 } };
    if (path === '/operational/sites/{id}/environments') return { data: { environments: [] } };
    return { data: { changes: [], journal_entries: [], entries: [], total: 0 } };
  });
  await render();
  expect(host.textContent).toContain('No locations inside this site yet');
  expect(host.textContent).toContain('No assets in this site have been summarised yet');
});

it('the Racks card lists the site\'s racks and links into the Racks lens filtered by site (row 2.5)', async () => {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/dcim/sites/{id}') return { data: { ...SITE, counts: { ...SITE.counts, racks: 1 } }, response: { status: 200 } };
    if (path === '/dcim/locations') return { data: { locations: [], total: 0 } };
    if (path === '/operational/sites/{id}/environments') return { data: { environments: [] } };
    if (path === '/dcim/racks') return { data: { data: [{ id: 'r12', name: 'R12', location: { id: 'row3', name: 'Row 3' }, utilization: { utilization: 28.6 }, device_count: 9 }] } };
    return { data: { changes: [], journal_entries: [], entries: [], total: 0 } };
  });
  await render();
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  expect(host.querySelector('[data-testid="site-racks-lens"]')!.getAttribute('href')).toBe('/inventory?lens=racks&site=ams');
  expect(host.querySelector('[data-testid="site-count-racks"]')!.getAttribute('href')).toBe('/inventory?lens=racks&site=ams');
  const r = host.querySelector('[data-testid="site-rack"]')!;
  expect(r.getAttribute('href')).toBe('/inventory/racks/r12');
  expect(r.textContent).toContain('28.6%');
  expect(api.GET).toHaveBeenCalledWith('/dcim/racks', { params: { query: { limit: 1000, site_id: 'ams' } } });
});

it('is reachable: the route is registered and the Sites lens is in the Inventory nav', () => {
  const app = readFileSync(resolve(process.cwd(), 'src/App.tsx'), 'utf8');
  expect(app).toMatch(/<Route path="\/inventory\/sites\/:id" element={<SitePage \/>} \/>/);
  const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
  expect(inventory.groups!.flatMap((g) => g.items).some((i) => i.lens === 'sites' && i.path === '/inventory?lens=sites')).toBe(true);
});
