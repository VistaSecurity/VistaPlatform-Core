// @vitest-environment jsdom
//
// Power on the asset page (DCIM row 6.1): the Ports tab's Power ports and
// Power outlets sections (draw columns, "not recorded" never shown as 0 W, the
// outlet's power port and feed leg), the power summary's five states, the add
// flow's request body, the faceplate's power rows, the Connect modal for power
// ends (an outlet offers a power port; a power port offers a power feed picked
// by site) and the trace model's power hops.
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ GET: mocks.get, POST: mocks.post, PATCH: vi.fn(), DELETE: vi.fn() }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { ConnectCableModal, connectProblem, type CablePort } from '../dcim/cable-column';
import { PortsTab, bodyOf, draftOf, draftProblem } from '../dcim/ports-tab';
import { PowerSummary } from '../dcim/power-summary';
import type { AssetPowerSummary, PowerOutlet, PowerPort } from '../dcim/component-queries';
import { nodeText, pathHops } from './trace-model';
import { ASSET, ASSET_ID, MANAGE, READ, button, byLabel, byTest, cable, mountUi, node, page, routeGets, setValue, text, tick, unmount, type Mounted } from './cabling-test-kit';

let m: Mounted | null = null;
beforeEach(() => { mocks.get.mockReset(); mocks.post.mockReset(); });
afterEach(() => { unmount(m); m = null; });

const NOW = new Date().toISOString();
const base = {
  tenant_id: 't', asset_id: ASSET_ID, module_id: null, label: null, mark_connected: false, cable_id: null, cable_end: null,
  source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {}, description: null, comments: null,
  status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
  created_at: NOW, updated_at: NOW, created_by: null,
};
const UNMEASURED = { measured_draw: null, measured_current: null, measured_at: null };
const INLET: PowerPort = { ...base, ...UNMEASURED, measured_legs: null, id: 'pp-in', name: 'Inlet', type: 'nema-l5-30p', maximum_draw: null, allocated_draw: null };
const PSU: PowerPort = { ...base, ...UNMEASURED, measured_legs: null, id: 'pp-1', name: 'PSU1', type: 'iec-60320-c14', maximum_draw: 500, allocated_draw: 300, cable_id: 'cab1' };
const OUT: PowerOutlet = { ...base, ...UNMEASURED, measured_state: null, id: 'po-1', name: 'Outlet 1', type: 'iec-60320-c13', power_port_id: 'pp-in', feed_leg: 'A' };

const SUMMARY: AssetPowerSummary = {
  asset_id: ASSET_ID,
  power_ports: [
    { id: 'pp-1', name: 'PSU1', type: 'iec-60320-c14', maximum_draw: 500, allocated_draw: 300, cable_id: 'cab1', mark_connected: false,
      path_complete: true, endpoint: { kind: 'power_feed', id: 'pf-1', name: 'Feed A', asset_id: null, asset_name: null, power_panel_id: 'pn', power_panel_name: 'Panel 1' },
      downstream: { outlet_count: 0, connected_count: 0, recorded_count: 0, maximum_draw: 0, allocated_draw: 0 } },
    { id: 'pp-2', name: 'PSU2', type: null, maximum_draw: null, allocated_draw: null, cable_id: null, mark_connected: false,
      path_complete: false, endpoint: null, downstream: { outlet_count: 0, connected_count: 0, recorded_count: 0, maximum_draw: 0, allocated_draw: 0 } },
  ],
  power_outlets: [],
  feeds: [{ id: 'pf-1', name: 'Feed A', power_panel_id: 'pn', power_panel_name: 'Panel 1', operational_status: 'active', supply: 'ac', phase: 'single-phase', voltage: 120, amperage: 20, available_power: 1920 }],
  totals: { outlet_count: 0, connected_count: 1, recorded_count: 1, maximum_draw: 500, allocated_draw: 300 },
};
const EMPTY_SUMMARY: AssetPowerSummary = { asset_id: ASSET_ID, power_ports: [], power_outlets: [], feeds: [], totals: { outlet_count: 0, connected_count: 0, recorded_count: 0, maximum_draw: 0, allocated_draw: 0 } };

const sectionButton = (label: string) => [...document.body.querySelectorAll('[role="tab"]')].find((t) => t.textContent?.startsWith(label)) as HTMLButtonElement;

describe('<PowerSummary> states', () => {
  it('loading', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    m = await mountUi(<PowerSummary assetId={ASSET_ID} />, READ);
    expect(text()).toContain("Loading the asset's power");
  });

  it('error is not "no power"', async () => {
    mocks.get.mockResolvedValue({ error: { error: { message: 'boom' } } });
    m = await mountUi(<PowerSummary assetId={ASSET_ID} />, READ);
    await tick();
    expect(text()).toContain('boom');
    expect(text()).not.toContain('No power recorded');
  });

  it('empty: nothing reported or declared', async () => {
    routeGets(mocks.get, { '/dcim/assets/{id}/power': () => ({ data: { data: EMPTY_SUMMARY } }) });
    m = await mountUi(<PowerSummary assetId={ASSET_ID} />, READ);
    await tick();
    expect(text()).toContain('No power recorded');
  });

  it('success: totals say how many declared a draw, the feed and each port\'s far end', async () => {
    routeGets(mocks.get, { '/dcim/assets/{id}/power': () => ({ data: { data: SUMMARY } }) });
    m = await mountUi(<PowerSummary assetId={ASSET_ID} />, READ);
    await tick();
    expect(byTest('power-totals')[0].textContent).toContain('2 power ports · maximum 500 W · allocated 300 W (declared on 1 of 2)');
    expect(byTest('power-feed')[0].textContent).toContain('Panel 1:Feed A');
    expect(byTest('power-feed')[0].textContent).toContain('1920 VA available');
    const lines = byTest('power-port-line').map((l) => l.textContent);
    expect(lines[0]).toContain('reaches Panel 1:Feed A');
    expect(lines[1]).toContain('not cabled');
  });

  it('a PDU inlet shows what its outlets feed', async () => {
    const pdu: AssetPowerSummary = { ...EMPTY_SUMMARY, power_ports: [{ ...SUMMARY.power_ports[1], name: 'Inlet',
      downstream: { outlet_count: 8, connected_count: 2, recorded_count: 2, maximum_draw: 900, allocated_draw: 600 } }] };
    routeGets(mocks.get, { '/dcim/assets/{id}/power': () => ({ data: { data: pdu } }) });
    m = await mountUi(<PowerSummary assetId={ASSET_ID} />, READ);
    await tick();
    expect(byTest('power-downstream')[0].textContent).toContain('feeds 2 of 8 outlets, drawing 600 W allocated / 900 W maximum');
    expect(byTest('power-totals')[0].textContent).toContain('no draw declared');
  });
});

describe('<PortsTab> power sections', () => {
  const routes = {
    '/dcim/assets/{id}/power-ports': () => page([PSU, INLET]),
    '/dcim/assets/{id}/power-outlets': () => page([OUT]),
    '/dcim/assets/{id}/power': () => ({ data: { data: SUMMARY } }),
    '/dcim/cables': () => page([cable({ a_terminations: [{ termination_kind: 'power_port', termination_id: 'pp-1', asset_id: ASSET_ID, asset_name: 'sw-1', circuit_id: null, name: 'PSU1' }],
      b_terminations: [{ termination_kind: 'power_outlet', termination_id: 'x', asset_id: 'pdu', asset_name: 'pdu-1', circuit_id: null, name: 'Outlet 3' }] })]),
  };

  it('power ports: draw columns, "not recorded" for an undeclared draw, the summary above, the cable column', async () => {
    routeGets(mocks.get, routes);
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    expect(byTest('count-power-ports')[0].textContent).toBe('2');
    await act(async () => { sectionButton('Power ports').click(); });
    await tick();
    expect(byTest('power-summary')).toHaveLength(1);
    const rows = byTest('port-row').map((r) => r.textContent ?? '');
    expect(rows[0]).toContain('PSU1');
    expect(rows[0]).toContain('500 W');
    expect(rows[0]).toContain('300 W');
    expect(rows[0]).toContain('pdu-1:Outlet 3');
    expect(rows[1]).toContain('not recorded');
    expect(rows[1]).not.toContain('0 W');
  });

  it('power outlets: the power port it draws from and its feed leg', async () => {
    routeGets(mocks.get, routes);
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    await act(async () => { sectionButton('Power outlets').click(); });
    await tick();
    const row = byTest('port-row')[0].textContent ?? '';
    expect(row).toContain('Outlet 1');
    expect(row).toContain('Inlet');
    expect(row).toContain('A');
  });

  it('measured (row 6.2): a PDU collector\'s reading beside the declared draws; "not measured" is never 0 W', async () => {
    const at = '2026-10-20T12:00:00Z';
    routeGets(mocks.get, {
      ...routes,
      '/dcim/assets/{id}/power-ports': () => page([{ ...PSU, measured_draw: 280, measured_current: 1.2, measured_at: at }, INLET]),
      '/dcim/assets/{id}/power-outlets': () => page([{ ...OUT, measured_draw: 40, measured_current: 0.2, measured_state: 'on', measured_at: at }]),
    });
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    await act(async () => { sectionButton('Power ports').click(); });
    await tick();
    let cells = byTest('power-measured').map((c) => c.textContent);
    expect(cells).toEqual(['280 W · 1.2 A', 'not measured']);
    // The declared allocated draw still reads as declared.
    expect(byTest('port-row')[0].textContent).toContain('300 W');
    await act(async () => { sectionButton('Power outlets').click(); });
    await tick();
    cells = byTest('power-measured').map((c) => c.textContent);
    expect(cells).toEqual(['On · 40 W · 0.2 A']);
  });

  it('empty: no power ports declared is not "this asset has none"', async () => {
    routeGets(mocks.get, { '/dcim/assets/{id}/power': () => ({ data: { data: EMPTY_SUMMARY } }) });
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    await act(async () => { sectionButton('Power ports').click(); });
    await tick();
    expect(text()).toContain('No power ports yet');
    expect(text()).toContain('says nothing about whether it has any');
  });

  it('loading and error per section', async () => {
    mocks.get.mockImplementation((path: string) => (path === '/dcim/assets/{id}/power-ports'
      ? Promise.resolve({ error: { error: { message: 'power down' } } })
      : new Promise(() => {})));
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    await act(async () => { sectionButton('Power ports').click(); });
    await tick();
    expect(text()).toContain('power down');
    await act(async () => { sectionButton('Power outlets').click(); });
    expect(text()).toContain('Loading power outlets');
  });

  it('adding a power port with one draw sends the other as null; allocated above maximum is refused', async () => {
    routeGets(mocks.get, routes);
    mocks.post.mockResolvedValue({ data: { data: { ...PSU, id: 'new', name: 'PSU3' } } });
    m = await mountUi(<PortsTab asset={ASSET as never} />, MANAGE);
    await tick();
    await act(async () => { sectionButton('Power ports').click(); });
    await act(async () => { button('Add power port').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Name')!, 'PSU3'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Maximum draw')!, '200'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Allocated draw')!, '250'); });
    expect(byTest('port-form-error')[0].textContent).toContain('cannot exceed the maximum');
    await act(async () => { setValue(byLabel<HTMLInputElement>('Allocated draw')!, ''); });
    const save = [...byTest('port-drawer')[0].querySelectorAll('button')].find((b) => b.textContent === 'Add power port')!;
    await act(async () => { save.click(); });
    await tick();
    expect(mocks.post).toHaveBeenCalledWith('/dcim/assets/{id}/power-ports', {
      params: { path: { id: ASSET_ID } },
      body: { name: 'PSU3', label: null, description: null, type: null, maximum_draw: 200, allocated_draw: null, asset_id: ASSET_ID },
    });
  });

  it('draft helpers round-trip an outlet and refuse a non-integer draw', () => {
    const d = draftOf('power-outlets', OUT);
    expect(bodyOf('power-outlets', d)).toEqual({ name: 'Outlet 1', label: null, description: null, type: 'iec-60320-c13', power_port_id: 'pp-in', feed_leg: 'A' });
    expect(draftProblem('power-ports', { ...draftOf('power-ports', null), name: 'x', maximum_draw: '1.5' }, [])).toContain('whole number of watts');
  });

  it('the faceplate draws the power rows', async () => {
    routeGets(mocks.get, routes);
    m = await mountUi(<PortsTab asset={ASSET as never} />, READ);
    await tick();
    expect(text()).toContain('Power ports');
    expect(text()).toContain('Power outlets');
    expect(document.body.querySelector('[aria-label^="PSU1"]')).not.toBeNull();
  });
});

describe('Connect for power ends', () => {
  const OUTLET: CablePort = { kind: 'power_outlet', id: 'po-1', name: 'Outlet 1', cableId: null, markConnected: false };
  const PORT: CablePort = { kind: 'power_port', id: 'pp-2', name: 'PSU2', cableId: null, markConnected: false };

  it('the matrix: an outlet takes a power port only; a feed a power port only', () => {
    expect(connectProblem('power_outlet', 'power_port')).toBeNull();
    expect(connectProblem('power_port', 'power_feed')).toBeNull();
    expect(connectProblem('power_outlet', 'power_feed')).toContain('cannot be cabled to a power feed');
    expect(connectProblem('interface', 'power_outlet')).toContain('compatibility matrix');
  });

  it('an outlet defaults to a power port far end and a power cable', async () => {
    routeGets(mocks.get, {});
    m = await mountUi(<ConnectCableModal port={OUTLET} onClose={() => {}} />, MANAGE);
    await tick();
    expect(byLabel<HTMLSelectElement>('Far port kind')!.value).toBe('power_port');
    expect(byLabel<HTMLSelectElement>('Cable type')!.value).toBe('power');
    const opts = [...byLabel<HTMLSelectElement>('Far port kind')!.options].map((o) => o.textContent);
    expect(opts).toContain('Interface (not compatible)');
  });

  it('a power port to a power feed: pick the site, then the feed; posts the cable', async () => {
    routeGets(mocks.get, {
      '/dcim/sites': () => ({ data: { sites: [{ id: 'site-1', name: 'DC1' }] } }),
      '/dcim/power-feeds': () => page([
        { id: 'pf-1', name: 'Feed A', power_panel: { id: 'pn', name: 'Panel 1', site_id: 'site-1' }, cable_id: null, mark_connected: false },
        { id: 'pf-2', name: 'Feed B', power_panel: { id: 'pn', name: 'Panel 1', site_id: 'site-1' }, cable_id: 'c9', mark_connected: false },
      ]),
    });
    mocks.post.mockResolvedValue({ data: { data: cable({}) } });
    const onClose = vi.fn();
    m = await mountUi(<ConnectCableModal port={PORT} onClose={onClose} />, MANAGE);
    await tick();
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Far port kind')!, 'power_feed'); });
    expect(byLabel('Search for the far asset')).toBeNull();
    expect(byLabel<HTMLSelectElement>('Far port')!.options[0].textContent).toBe('Pick a site first');
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Site')!, 'site-1'); });
    await tick();
    expect(mocks.get).toHaveBeenCalledWith('/dcim/power-feeds', { params: { query: { limit: 500, site_id: 'site-1' } } });
    const feeds = [...byLabel<HTMLSelectElement>('Far port')!.options].map((o) => [o.textContent, o.disabled]);
    expect(feeds).toContainEqual(['Panel 1:Feed A', false]);
    expect(feeds).toContainEqual(['Panel 1:Feed B (in use)', true]);
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Far port')!, 'pf-1'); });
    await act(async () => { button('Connect cable').click(); });
    await tick();
    expect(mocks.post).toHaveBeenCalledWith('/dcim/cables', {
      body: {
        a_terminations: [{ termination_kind: 'power_port', termination_id: 'pp-2' }],
        b_terminations: [{ termination_kind: 'power_feed', termination_id: 'pf-1' }],
        operational_status: 'connected', type: 'power',
      },
    });
    expect(onClose).toHaveBeenCalled();
  });
});

describe('trace model: power hops', () => {
  it('a PSU through a PDU to its feed: outlet → inlet, the feed named by its panel', () => {
    const psu = node({ kind: 'power_port', id: 'psu', name: 'PSU1', asset_id: ASSET_ID, asset_name: 'srv-1' });
    const out = node({ kind: 'power_outlet', id: 'out', name: 'Outlet 1', asset_id: 'pdu', asset_name: 'pdu-1' });
    const inlet = node({ kind: 'power_port', id: 'in', name: 'Inlet', asset_id: 'pdu', asset_name: 'pdu-1' });
    const feed = node({ kind: 'power_feed', id: 'pf', name: 'Feed A', power_panel_name: 'Panel 1' });
    const hops = pathHops({
      origin: psu, destination: feed, is_complete: true, is_active: true, is_split: false,
      steps: [
        { near_end: [psu], cables: [node({ kind: 'cable', id: 'c1', name: 'Cable' })], far_end: [out] },
        { near_end: [inlet], cables: [node({ kind: 'cable', id: 'c2', name: 'Cable' })], far_end: [feed] },
      ],
    });
    expect(hops.find((h) => h.type === 'through')).toEqual({ type: 'through', label: 'outlet → inlet' });
    expect(nodeText(feed)).toBe('Panel 1:Feed A');
  });
});
