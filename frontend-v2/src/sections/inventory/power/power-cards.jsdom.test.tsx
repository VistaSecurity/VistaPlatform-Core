// @vitest-environment jsdom
//
// The power cards (DCIM row 6.1): the site page's Power panels card and the
// rack page's Power feeds card — loading, error (never "no panels"), empty,
// the list (feeds per panel, status, rating, available power, the PDU inlet a
// feed powers) — the add-panel and add-feed request bodies, the feed form's
// NetBox rules, and the dcim.manage gate on every write control. Both cards
// are mounted through the REAL site and rack pages, so removing one from its
// page fails here.
import { act } from 'react';
import { Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), del: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: vi.fn(), DELETE: mocks.del }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { RackPowerCard, SitePowerCard, availablePower, emptyFeedDraft, feedProblem } from './power-cards';
import { SitePage } from '../sites/site-page';
import { MANAGE, READ, button, byLabel, byTest, mountUi, page, routeGets, setValue, text, tick, unmount, type Mounted } from '../cabling/cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { for (const f of Object.values(mocks)) f.mockReset(); });
afterEach(() => { unmount(m); m = null; });

const SITE = '44444444-4444-4444-8444-444444444444';
const RACK = '55555555-5555-4555-8555-555555555555';
const PANEL = { id: 'pn-1', name: 'Panel 1', site_id: SITE, location_id: null, feed_count: 1, site: { id: SITE, name: 'DC1' }, location: null };
const FEED = {
  id: 'pf-1', name: 'Feed A', power_panel_id: 'pn-1', rack_id: RACK, operational_status: 'active', type: 'primary', supply: 'ac',
  phase: 'single-phase', voltage: 230, amperage: 16, max_utilization: 80, available_power: 2944, mark_connected: false, cable_id: 'c1',
  power_panel: { id: 'pn-1', name: 'Panel 1', site_id: SITE }, rack: { id: RACK, name: 'R7' },
  connected_endpoint: { kind: 'power_port', id: 'in', name: 'Inlet', asset_id: 'pdu', asset_name: 'pdu-1' },
};

describe('<SitePowerCard>', () => {
  it('loading', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<SitePowerCard siteId={SITE} />, READ);
    expect(text()).toContain('Loading power panels');
  });

  it('error is not "no panels"', async () => {
    mocks.get.mockResolvedValue({ error: { error: { message: 'panels down' } } });
    m = await mountUi(<SitePowerCard siteId={SITE} />, READ);
    await tick();
    expect(text()).toContain('panels down');
    expect(byTest('power-panels-empty')).toHaveLength(0);
  });

  it('empty: none declared, which says nothing about the site', async () => {
    routeGets(mocks.get, {});
    m = await mountUi(<SitePowerCard siteId={SITE} />, READ);
    await tick();
    expect(byTest('power-panels-empty')[0].textContent).toContain('No power panels are declared');
  });

  it('success: each panel with its feeds, what each feed powers; read-only without dcim.manage', async () => {
    routeGets(mocks.get, { '/dcim/power-panels': () => page([PANEL]), '/dcim/power-feeds': () => page([FEED]) });
    m = await mountUi(<SitePowerCard siteId={SITE} />, READ);
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/power-feeds', { params: { query: { limit: 500, site_id: SITE } } });
    expect(byTest('power-panel')[0].textContent).toContain('Panel 1');
    const row = byTest('power-feed-row')[0].textContent ?? '';
    expect(row).toContain('Feed A');
    expect(row).toContain('R7');
    expect(row).toContain('2944 VA');
    expect(byTest('feed-endpoint')[0].textContent).toContain('powers pdu-1:Inlet');
    expect(text()).not.toContain('Add panel');
  });

  it('adds a panel and a feed with their bodies', async () => {
    routeGets(mocks.get, {
      '/dcim/power-panels': () => page([PANEL]),
      '/dcim/racks': () => page([{ id: RACK, name: 'R7' }]),
      '/dcim/locations': () => ({ data: { locations: [] } }),
    });
    mocks.post.mockImplementation(async (path: string) => ({ data: { data: path === '/dcim/power-panels' ? PANEL : FEED } }));
    m = await mountUi(<SitePowerCard siteId={SITE} />, MANAGE);
    await tick();
    await act(async () => { button('Add panel').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Panel name')!, ' Panel 2 '); });
    await act(async () => { byTest('add-panel-modal')[0].closest('[role="dialog"]')!.querySelectorAll('button').forEach((b) => { if (b.textContent === 'Add panel') b.click(); }); });
    await tick();
    expect(mocks.post).toHaveBeenCalledWith('/dcim/power-panels', { body: { site_id: SITE, name: 'Panel 2', location_id: null, description: null } });

    await act(async () => { button('Add a feed to Panel 1').click(); });
    await tick();
    await act(async () => { setValue(byLabel<HTMLInputElement>('Feed name')!, 'Feed B'); });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Feed rack')!, RACK); });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Feed phase')!, 'three-phase'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Feed voltage')!, '208'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Feed amperage')!, '30'); });
    expect(byTest('feed-preview')[0].textContent).toContain('8646 VA');
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Feed supply')!, 'dc'); });
    expect(byTest('power-form-error')[0].textContent).toContain('A DC supply cannot be three-phase');
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Feed supply')!, 'ac'); });
    await act(async () => { button('Add feed').click(); });
    await tick();
    expect(mocks.post).toHaveBeenCalledWith('/dcim/power-feeds', {
      body: { power_panel_id: 'pn-1', name: 'Feed B', rack_id: RACK, operational_status: 'active', type: 'primary', supply: 'ac',
        phase: 'three-phase', voltage: 208, amperage: 30, max_utilization: 80 },
    });
  });

  it('the site page shows the card', async () => {
    routeGets(mocks.get, {
      '/dcim/sites/{id}': () => ({ data: { id: SITE, name: 'DC1', operational_status: 'active', asns: [], asset_count: 0 }, response: { status: 200 } }),
      '/dcim/power-panels': () => page([PANEL]),
    });
    m = await mountUi(<Routes><Route path="/inventory/sites/:id" element={<SitePage />} /></Routes>, READ, `/inventory/sites/${SITE}`);
    await tick();
    await tick();
    expect(byTest('site-power')).toHaveLength(1);
  });
});

describe('<RackPowerCard>', () => {
  it('loading, error, empty and the feeds serving the rack', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<RackPowerCard rackId={RACK} />, READ);
    expect(text()).toContain('Loading power feeds');
    unmount(m);

    mocks.get.mockReset();
    mocks.get.mockResolvedValue({ error: { error: { message: 'feeds down' } } });
    m = await mountUi(<RackPowerCard rackId={RACK} />, READ);
    await tick();
    expect(text()).toContain('feeds down');
    unmount(m);

    mocks.get.mockReset();
    routeGets(mocks.get, {});
    m = await mountUi(<RackPowerCard rackId={RACK} />, READ);
    await tick();
    expect(text()).toContain('No power feeds');
    unmount(m);

    mocks.get.mockReset();
    routeGets(mocks.get, { '/dcim/power-feeds': () => page([FEED, { ...FEED, id: 'pf-2', name: 'Feed B', operational_status: 'failed', connected_endpoint: null, cable_id: null }]) });
    m = await mountUi(<RackPowerCard rackId={RACK} />, READ);
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/power-feeds', { params: { query: { limit: 500, rack_id: RACK } } });
    expect(byTest('rack-power-total')[0].textContent).toBe('2 feeds · 2944 VA available on the active ones');
    expect(byTest('feed-endpoint')[1].textContent).toContain('not cabled');
  });
});

describe('feed form rules', () => {
  it('NetBox PowerFeed.clean and available power', () => {
    expect(feedProblem({ ...emptyFeedDraft(), name: 'F' })).toBeNull();
    expect(feedProblem({ ...emptyFeedDraft(), name: 'F', voltage: '0' })).toContain('not zero');
    expect(feedProblem({ ...emptyFeedDraft(), name: 'F', voltage: '-48', supply: 'dc' })).toBeNull();
    expect(feedProblem({ ...emptyFeedDraft(), name: 'F', max_utilization: '101' })).toContain('1 to 100');
    expect(availablePower({ voltage: '120', amperage: '20', max_utilization: '80', phase: 'single-phase' })).toBe(1920);
    expect(availablePower({ voltage: '-48', amperage: '10', max_utilization: '80', phase: 'single-phase' })).toBe(384);
  });
});
