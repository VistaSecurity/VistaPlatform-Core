// @vitest-environment jsdom
//
// Spares & RMA (DCIM gap 8): the workspace page's stock and RMA tables —
// loading, error (never "no spares"), empty, the rows — the request bodies of
// Add spare, Install, Reserve and an RMA step, a refusal's reason, the
// dcim.manage gate on every write control; the site page's Spares card in its
// states; and the registrations: the page through the REAL WorkspacePage, the
// card through the REAL site page, the rail item and the catalog hub.
//
// Mutation: drop the `case 'spares'` from settings-page.tsx, the `spares` nav
// item, the SiteSparesCard mount in site-page.tsx, the rail entry in app/nav.ts
// or the hub card → a registration test fails; drop the PermissionGate around a
// row's actions → the read-only test fails.
import { Route, Routes } from 'react-router';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: mocks.patch, DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { SparesPage } from './spares-page';
import { SiteSparesCard } from './site-spares-card';
import { SitePage } from '../sites/site-page';
import { InfrastructureCatalogPage } from '../workspace-hubs';
import { WorkspacePage } from '../../settings/settings-page';
import { workspacePageMeta } from '../../settings/nav';
import { SECTIONS } from '../../../app/nav';
import { MANAGE, READ, button, byLabel, byTest, mountUi, page, routeGets, setValue, text, tick, unmount, type Mounted } from '../cabling/cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { for (const f of Object.values(mocks)) f.mockReset(); });
afterEach(() => { unmount(m); m = null; });

const NOW = new Date().toISOString();
const SITE = '44444444-4444-4444-8444-444444444444';
const LOC = { id: 'loc-1', site_id: SITE, name: 'Stores', path: 'DC1 / Stores', asset_count: 0 };
const life = {
  tenant_id: 't', source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {}, description: null, comments: null,
  status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
  created_at: NOW, updated_at: NOW, created_by: null, label: null, role_id: null, manufacturer_id: null, asset_tag: null,
  discovered: false, component_kind: null, component_id: null, parent_id: null,
};
const BOX = { ...life, id: 'sp-1', asset_id: null, name: 'SFP-10G-SR', part_id: 'SFP-10G-SR', serial: null, location_id: 'loc-1', quantity: 12, stock_state: 'in_stock' };
const LC = { ...life, id: 'sp-2', asset_id: null, name: 'LC-48', part_id: 'WS-X4748', serial: 'SN-9', location_id: 'loc-1', quantity: 1, stock_state: 'reserved' };
const UNIT = { ...life, id: 'sp-3', asset_id: null, name: 'QSFP-40G', part_id: null, serial: null, location_id: null, quantity: 1, stock_state: 'rma' };
const CASE = {
  id: 'rc-1', tenant_id: 't', inventory_item_id: 'sp-3', vendor: 'Acme Networks', case_number: 'RMA-1001', opened_at: '2026-10-01',
  shipped_at: null, received_at: null, replacement_item_id: null, replacement_location_id: 'loc-1', state: 'open', notes: null,
  description: null, comments: null, source_kind: 'declared', source_ref: null, custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const META = { key: 'spares', label: 'Spares & RMA', icon: 'package', job: 'Keep the spare parts on your shelves.' };

const filled = {
  '/dcim/inventory-items': () => page([BOX, LC, UNIT]),
  '/dcim/rma-cases': () => page([CASE]),
  '/dcim/inventory-items/{id}': () => ({ data: { data: UNIT } }),
  '/dcim/locations': () => ({ data: { locations: [LOC] } }),
};

describe('<SparesPage>', () => {
  it('loading: both tables say so', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<SparesPage meta={META} />, READ);
    expect(text()).toContain('Loading the spares');
    expect(text()).toContain('Loading the RMA cases');
  });

  it('error is not "no spares"', async () => {
    routeGets(mocks.get, { '/dcim/inventory-items': () => ({ error: { error: { message: 'stock unavailable' } } }) });
    m = await mountUi(<SparesPage meta={META} />, READ);
    await tick();
    expect(text()).toContain('stock unavailable');
    expect(byTest('spares-empty')).toHaveLength(0);
  });

  it('empty: none recorded, which says nothing about the shelves', async () => {
    routeGets(mocks.get, {});
    m = await mountUi(<SparesPage meta={META} />, READ);
    await tick();
    expect(byTest('spares-empty')[0].textContent).toContain('says nothing about what is on your shelves');
    expect(byTest('rma-empty')[0].textContent).toContain('No open RMA cases');
  });

  it('success: the stock with location, quantity and state, the open cases; read-only without dcim.manage', async () => {
    routeGets(mocks.get, filled);
    m = await mountUi(<SparesPage meta={META} />, READ);
    await tick();
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/inventory-items', { params: { query: { limit: 500, asset_id: 'null' } } });
    expect(mocks.get).toHaveBeenCalledWith('/dcim/rma-cases', { params: { query: { limit: 500, open: 'true' } } });
    const rows = byTest('spare-row').map((r) => r.textContent ?? '');
    expect(rows).toHaveLength(3);
    expect(rows[0]).toContain('DC1 / Stores');
    expect(rows[0]).toContain('12');
    expect(rows[1]).toContain('SN SN-9');
    expect(byTest('spare-state').map((s) => s.textContent)).toEqual(['In stock', 'Reserved', 'Out for RMA']);
    expect(rows[2]).toContain('with the vendor');
    expect(byTest('spares-units')[0].textContent).toBe('14 units in 3 rows');
    const c = byTest('rma-row')[0].textContent ?? '';
    expect(c).toContain('Acme Networks');
    expect(c).toContain('RMA-1001');
    expect(c).toContain('QSFP-40G');
    expect(byTest('rma-state')[0].textContent).toBe('Open');
    expect(text()).not.toContain('Add spare');
    expect(byLabel('Install SFP-10G-SR')).toBeNull();
    expect(byLabel('Mark RMA-1001 shipped')).toBeNull();
  });

  it('adds a spare with its body', async () => {
    routeGets(mocks.get, { '/dcim/locations': () => ({ data: { locations: [LOC] } }) });
    mocks.post.mockResolvedValue({ data: { data: BOX } });
    m = await mountUi(<SparesPage meta={META} />, MANAGE);
    await tick();
    await act(async () => { button('Add spare').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Spare name')!, 'SFP-10G-SR'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Part number')!, 'SFP-10G-SR'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Quantity')!, '12'); });
    await vi.waitFor(() => expect(document.body.querySelector('select[aria-label="Stock location"] option[value="loc-1"]')).not.toBeNull());
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Stock location')!, 'loc-1'); });
    const submit = [...document.body.querySelectorAll('button')].filter((b) => b.textContent?.trim() === 'Add spare').pop()!;
    await act(async () => { submit.click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    expect(mocks.post.mock.calls[0]).toEqual(['/dcim/inventory-items', {
      body: { name: 'SFP-10G-SR', location_id: 'loc-1', quantity: 12, part_id: 'SFP-10G-SR', serial: null, stock_state: 'in_stock' },
    }]);
  });

  it('a serialised spare counts one: the form refuses another quantity before the server', async () => {
    routeGets(mocks.get, { '/dcim/locations': () => ({ data: { locations: [LOC] } }) });
    m = await mountUi(<SparesPage meta={META} />, MANAGE);
    await tick();
    await act(async () => { button('Add spare').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Spare name')!, 'LC-48'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Serial')!, 'SN-9'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Quantity')!, '2'); });
    expect(text()).toContain('a serialised unit counts 1');
  });

  it('installs a spare on an asset found by search, with the units and name', async () => {
    routeGets(mocks.get, {
      ...filled,
      '/infrastructure-assets': () => ({ data: { assets: [{ id: 'a-1', display_name: 'core-1', hostname: 'core-1' }], pagination: { total: 1, page: 1, page_size: 50 } } }),
    });
    mocks.post.mockResolvedValue({ data: { data: { item: { ...BOX, asset_id: 'a-1', quantity: 2 }, stock: { ...BOX, quantity: 10 } } } });
    m = await mountUi(<SparesPage meta={META} />, MANAGE);
    await tick();
    await tick();
    await act(async () => { button('Install SFP-10G-SR').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Search for an asset')!, 'core'); });
    await tick(400);
    await vi.waitFor(() => expect(byTest('spare-asset-results')[0]?.textContent).toContain('core-1'));
    await act(async () => { [...byTest('spare-asset-results')[0].querySelectorAll('button')][0].click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Units')!, '2'); });
    // The dialog's Install (the row's own button reads the same).
    const confirm = [...document.body.querySelectorAll('button')].filter((b) => b.textContent?.trim() === 'Install' && !b.getAttribute('aria-label')).pop()!;
    await act(async () => { confirm.click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    expect(mocks.post.mock.calls[0]).toEqual(['/dcim/inventory-items/{id}/install', { params: { path: { id: 'sp-1' } }, body: { asset_id: 'a-1', name: 'SFP-10G-SR', quantity: 2 } }]);
  });

  it('reserves a spare and moves an RMA case on; a refusal shows its reason', async () => {
    routeGets(mocks.get, filled);
    mocks.patch.mockResolvedValueOnce({ data: { data: { ...BOX, stock_state: 'reserved' } } });
    mocks.patch.mockResolvedValueOnce({ error: { error: { message: 'the replacement needs a stock location' } } });
    m = await mountUi(<SparesPage meta={META} />, MANAGE);
    await tick();
    await tick();
    await act(async () => { button('Reserve SFP-10G-SR').click(); });
    await vi.waitFor(() => expect(mocks.patch).toHaveBeenCalledTimes(1));
    expect(mocks.patch.mock.calls[0]).toEqual(['/dcim/inventory-items/{id}', { params: { path: { id: 'sp-1' } }, body: { stock_state: 'reserved' } }]);
    expect(byLabel('Release LC-48')).not.toBeNull();
    // An open case can ship, be received or close.
    expect(byLabel('Mark RMA-1001 shipped')).not.toBeNull();
    expect(byLabel('Mark RMA-1001 closed')).not.toBeNull();
    await act(async () => { button('Mark RMA-1001 replacement received').click(); });
    await vi.waitFor(() => expect(mocks.patch).toHaveBeenCalledTimes(2));
    expect(mocks.patch.mock.calls[1]).toEqual(['/dcim/rma-cases/{id}', { params: { path: { id: 'rc-1' } }, body: { state: 'received' } }]);
    await vi.waitFor(() => expect(byTest('rma-error')[0]?.textContent).toContain('needs a stock location'));
  });

  it('opens an RMA for one unit of a box', async () => {
    routeGets(mocks.get, filled);
    mocks.post.mockResolvedValue({ data: { data: { item: UNIT, rma_case: CASE } } });
    m = await mountUi(<SparesPage meta={META} />, MANAGE);
    await tick();
    await tick();
    await act(async () => { button('Open RMA for SFP-10G-SR').click(); });
    expect(text()).toContain('One unit of the 12 goes out for RMA');
    await act(async () => { setValue(byLabel<HTMLInputElement>('Vendor')!, 'Acme Networks'); });
    await act(async () => { button('Open RMA').click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    expect(mocks.post.mock.calls[0]).toEqual(['/dcim/inventory-items/{id}/rma', { params: { path: { id: 'sp-1' } }, body: { vendor: 'Acme Networks' } }]);
  });
});

describe('<SiteSparesCard>', () => {
  it('loading, error, empty and the site\'s spares', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<SiteSparesCard siteId={SITE} />, READ);
    expect(text()).toContain('Loading spares');
    unmount(m);

    mocks.get.mockReset();
    routeGets(mocks.get, { '/dcim/inventory-items': () => ({ error: { error: { message: 'spares down' } } }) });
    m = await mountUi(<SiteSparesCard siteId={SITE} />, READ);
    await tick();
    expect(text()).toContain('spares down');
    expect(byTest('site-spares-empty')).toHaveLength(0);
    unmount(m);

    mocks.get.mockReset();
    routeGets(mocks.get, {});
    m = await mountUi(<SiteSparesCard siteId={SITE} />, READ);
    await tick();
    expect(byTest('site-spares-empty')[0].textContent).toContain('says nothing about its shelves');
    unmount(m);

    mocks.get.mockReset();
    routeGets(mocks.get, { '/dcim/inventory-items': () => page([BOX, LC]), '/dcim/locations': () => ({ data: { locations: [LOC] } }) });
    m = await mountUi(<SiteSparesCard siteId={SITE} />, READ);
    await tick();
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/inventory-items', { params: { query: { limit: 500, asset_id: 'null', site_id: SITE } } });
    expect(byTest('site-spare')).toHaveLength(2);
    expect(byTest('site-spare')[0].textContent).toContain('DC1 / Stores');
    expect(byTest('site-spare')[0].textContent).toContain('×12 · In stock');
    expect(byTest('site-spares-units')[0].textContent).toBe('13 units in 2 rows');
    expect(byTest('site-spares-link')[0].getAttribute('href')).toBe('/inventory/manage/spares');
  });
});

describe('registrations', () => {
  it('the page is served by the real WorkspacePage under dcim.read', async () => {
    routeGets(mocks.get, {});
    expect(workspacePageMeta('spares')?.workspacePath).toBe('/inventory/manage/spares');
    m = await mountUi(<WorkspacePage page="spares" />, READ);
    await tick();
    expect(byTest('spares-page')).toHaveLength(1);
  });

  it('the card is on the real site page', async () => {
    routeGets(mocks.get, {
      '/dcim/sites/{id}': () => ({ data: { id: SITE, name: 'DC1', operational_status: 'active', asns: [], asset_count: 0 }, response: { status: 200 } }),
    });
    m = await mountUi(<Routes><Route path="/inventory/sites/:id" element={<SitePage />} /></Routes>, READ, `/inventory/sites/${SITE}`);
    await tick();
    await tick();
    expect(byTest('site-spares-card')).toHaveLength(1);
  });

  it('the rail lists it under Infrastructure → Catalog & Data, and the catalog hub links it', async () => {
    const infra = SECTIONS.find((s) => s.label === 'Infrastructure');
    const group = infra?.groups?.find((g) => g.label === 'Catalog & Data');
    expect(group?.items.map((i) => i.path)).toContain('/inventory/manage/spares');
    m = await mountUi(<InfrastructureCatalogPage />, READ);
    expect([...document.body.querySelectorAll('a')].map((a) => a.getAttribute('href'))).toContain('/inventory/manage/spares');
  });
});
