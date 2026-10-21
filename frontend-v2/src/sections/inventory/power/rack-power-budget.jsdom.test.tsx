// @vitest-environment jsdom
//
// The rack page's Power card (DCIM row 6.2): loading, error (never "no
// budget"), empty (no feed declared), the budget — per feed allocated /
// available with the 80 / 95 capacity colour, a three-phase feed's legs, a feed
// whose devices declare no draw (never 0 W), measured load beside, and the
// rack total. Mounted through the REAL rack page too, so removing the card
// from the page fails here.
import { act } from 'react';
import { Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { RackPowerBudgetCard } from './rack-power-budget';
import { RackPage } from '../racks/rack-page';
import { fillColor } from '../../dashboard/facilities-dashboard-metrics';
import type { RackPowerBudget, RackPowerFeed } from './power-queries';
import { READ, byTest, mountUi, routeGets, text, tick, unmount, type Mounted } from '../cabling/cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { mocks.get.mockReset(); });
afterEach(() => { unmount(m); m = null; });

const RACK = '55555555-5555-4555-8555-555555555555';
const feed = (over: Partial<RackPowerFeed>): RackPowerFeed => ({
  id: 'f', name: 'Feed', power_panel_id: 'pn', power_panel_name: 'Panel 1', operational_status: 'active', phase: 'single-phase',
  available_power: 1920, power_port: { kind: 'power_port', id: 'in', name: 'Inlet', asset_id: 'pdu', asset_name: 'pdu-1' },
  aggregated: true, allocated_draw: 0, maximum_draw: 0, recorded_count: 0, outlet_count: 0, utilization: 0,
  measured_draw: null, measured_at: null, legs: [], ...over,
});
const BUDGET: RackPowerBudget = {
  rack_id: RACK, feed_count: 3, available_power: 1920 + 8646 + 1920, allocated_draw: 2600, maximum_draw: 450, utilization: 20.8, measured_draw: 760,
  feeds: [
    feed({ id: 'fa', name: 'Feed A', allocated_draw: 1600, recorded_count: 2, outlet_count: 2, utilization: 83.3, measured_draw: 760, measured_at: '2026-10-20T12:00:00Z' }),
    feed({ id: 'fb', name: 'Feed B', phase: 'three-phase', available_power: 8646, allocated_draw: 1000, recorded_count: 2, utilization: 11.6,
      legs: [
        { leg: 'A', outlet_count: 1, allocated_draw: 600, maximum_draw: 0, available_power: 2882, utilization: 20.8, measured_draw: 450 },
        { leg: 'B', outlet_count: 1, allocated_draw: 400, maximum_draw: 0, available_power: 2882, utilization: 13.9, measured_draw: null },
        { leg: 'C', outlet_count: 0, allocated_draw: 0, maximum_draw: 0, available_power: 2882, utilization: 0, measured_draw: null },
      ] }),
    feed({ id: 'fc', name: 'Feed C', power_port: null }),
  ],
  devices: [],
};
const budgetRoute = (b: RackPowerBudget) => ({ '/dcim/racks/{id}/power': () => ({ data: { data: b } }) });

describe('<RackPowerBudgetCard>', () => {
  it('loading', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<RackPowerBudgetCard rackId={RACK} />, READ);
    expect(text()).toContain('Loading the power budget');
  });

  it('error is not "no budget"', async () => {
    mocks.get.mockResolvedValue({ error: { error: { message: 'budget down' } } });
    m = await mountUi(<RackPowerBudgetCard rackId={RACK} />, READ);
    await tick();
    expect(text()).toContain('budget down');
    expect(text()).not.toContain('No power budget');
  });

  it('empty: no feed declared, which is not "draws nothing"', async () => {
    routeGets(mocks.get, budgetRoute({ ...BUDGET, feed_count: 0, available_power: 0, allocated_draw: 0, utilization: null, measured_draw: null, feeds: [] }));
    m = await mountUi(<RackPowerBudgetCard rackId={RACK} />, READ);
    await tick();
    expect(text()).toContain('No power budget');
    expect(text()).toContain('No power feed is declared as serving this rack');
    expect(byTest('rack-power-feed')).toHaveLength(0);
  });

  it('success: per feed and per leg, the capacity colour, unrecorded never 0 W, measured beside', async () => {
    routeGets(mocks.get, budgetRoute(BUDGET));
    m = await mountUi(<RackPowerBudgetCard rackId={RACK} />, READ);
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/racks/{id}/power', { params: { path: { id: RACK } } });
    expect(byTest('rack-power-budget-total')[0].textContent).toContain('2,600 W / 12,486 VA · 20.8%');
    const rows = byTest('rack-power-feed');
    expect(rows).toHaveLength(3);
    expect(rows[0].textContent).toContain('Panel 1:Feed A');
    expect(rows[0].textContent).toContain('pdu-1 Inlet');
    const bar = rows[0].querySelector('[data-testid="rack-power-feed-bar"]') as HTMLElement;
    expect(bar.dataset.color).toBe(fillColor(83.3));
    expect(fillColor(83.3)).not.toBe(fillColor(11.6));
    expect(rows[0].textContent).toContain('760 W measured');
    expect(byTest('rack-power-legs')).toHaveLength(1);
    expect(byTest('rack-power-legs')[0].textContent).toContain('Leg A');
    expect(byTest('rack-power-legs')[0].textContent).toContain('600 W / 2,882 VA · 20.8%');
    expect(byTest('rack-power-legs')[0].textContent).toContain('450 W measured');
    expect(rows[2].textContent).toContain('not cabled');
    expect(rows[2].textContent).toContain('Nothing cabled to it');
    expect(rows[2].textContent).not.toContain('0 W /');
  });

  it('a feed whose devices declare nothing reads "No draw declared"', async () => {
    routeGets(mocks.get, budgetRoute({ ...BUDGET, feed_count: 1, feeds: [feed({ id: 'fz', name: 'Feed Z' })] }));
    m = await mountUi(<RackPowerBudgetCard rackId={RACK} />, READ);
    await tick();
    expect(byTest('rack-power-feed-unrecorded')[0].textContent).toContain('No draw declared');
    expect(byTest('rack-power-budget-total')[0].textContent).toContain('No device on these feeds declares a draw');
  });
});

it('the rack page shows the card', async () => {
  const el = {
    rack: { id: RACK, name: 'R7', site_id: 's', site: { id: 's', name: 'DC1', slug: 'dc1' }, u_height: 42, starting_unit: 1, desc_units: false, width: 19, operational_status: 'active', rack_type_id: null },
    devices: [], units: [], reservations: [], non_racked: 0, utilization: null,
  };
  routeGets(mocks.get, { '/dcim/racks/{id}/elevation': () => ({ data: { data: el } }), ...budgetRoute(BUDGET) });
  await act(async () => {
    m = await mountUi(<Routes><Route path="/inventory/racks/:id" element={<RackPage />} /></Routes>, READ, `/inventory/racks/${RACK}`);
  });
  await tick();
  await tick();
  expect(byTest('rack-power-budget')).toHaveLength(1);
  expect(byTest('rack-power-feed')).toHaveLength(3);
});
