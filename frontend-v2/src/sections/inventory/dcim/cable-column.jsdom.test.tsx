// @vitest-environment jsdom
//
// The Cable column on the asset page's Interfaces and Ports tabs, the Connect
// modal and Disconnect (DCIM BUILD_PLAN row 3.2). Mounted through the REAL
// tabs, so dropping the column from either tab fails here. Five states: the
// cables loading, failing (not shown as "uncabled"), a cabled port naming its
// far end, an uncabled port offering Connect, and a successful Connect with
// the request body it sends; plus Disconnect and the read-only gate.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type ApiCall = (path: string, opts?: { params?: { path?: Record<string, string>; query?: Record<string, unknown> }; body?: unknown }) => Promise<unknown>;
const mocks = vi.hoisted(() => ({ get: vi.fn<ApiCall>(), post: vi.fn<ApiCall>(), patch: vi.fn<ApiCall>(), del: vi.fn<ApiCall>() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: mocks.patch, DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { InterfacesTab } from './interfaces-tab';
import { PortsTab } from './ports-tab';
import type { Cable } from './cable-queries';
import type { Interface } from './interface-queries';

const ASSET_ID = '11111111-1111-4111-8111-111111111111';
const FAR_ID = '22222222-2222-4222-8222-222222222222';
const NOW = new Date().toISOString();
const ASSET = { id: ASSET_ID, hostname: 'sw-1', display_name: 'sw-1', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };

function iface(over: Partial<Interface>): Interface {
  return {
    id: 'x', asset_id: ASSET_ID, module_id: null, name: 'eth0', label: null,
    type: '1000base-t', type_label: '1000BASE-T (1GE)', enabled: true, mgmt_only: false, mtu: null, mac_address: null,
    mac_addresses: [], speed_kbps: null, duplex: null, mode: null, untagged_vlan_id: null, tagged_vlan_ids: [],
    vrf_id: null, parent_id: null, bridge_id: null, lag_id: null, rf_role: null, rf_channel: null,
    rf_channel_frequency: null, rf_channel_width: null, tx_power: null, poe_mode: null, poe_type: null, wwn: null,
    operational_status: null, admin_status: null, vdcs: [], mark_connected: false, cable_id: null, cable_end: null,
    source_kind: 'declared', source_ref: null, custom_fields: {}, description: null, comments: null, status: 'active',
    first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
    created_at: NOW, updated_at: NOW, created_by: null,
    ...over,
  };
}

const GI1 = iface({ id: 'gi1', name: 'GigabitEthernet1/0/1', cable_id: 'cab1', cable_end: 'A' });
const GI2 = iface({ id: 'gi2', name: 'GigabitEthernet1/0/2' });
const VLAN = iface({ id: 'v10', name: 'Vlan10', type: 'virtual', type_label: 'Virtual' });
const FAR_ETH0 = iface({ id: 'far-eth0', asset_id: FAR_ID, name: 'eth0' });
const FAR_ETH1 = iface({ id: 'far-eth1', asset_id: FAR_ID, name: 'eth1', cable_id: 'other', cable_end: 'B' });

const CABLE: Cable = {
  id: 'cab1', tenant_id: 't', type: 'cat6', operational_status: 'connected', label: null, color: '2f6fdb', length: null,
  length_unit: null, business_unit_id: null, source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {},
  description: null, comments: null, status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, lldp_confirmed_at: null,
  approved_by: null, approved_at: null, created_at: NOW, updated_at: NOW, created_by: null,
  a_terminations: [{ termination_kind: 'interface', termination_id: 'gi1', asset_id: ASSET_ID, asset_name: 'sw-1', circuit_id: null, name: 'GigabitEthernet1/0/1' }],
  b_terminations: [{ termination_kind: 'interface', termination_id: 'far-eth9', asset_id: FAR_ID, asset_name: 'srv-9', circuit_id: null, name: 'eth9' }],
};

const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
  document.body.innerHTML = '';
});

type Handler = (opts?: { params?: { path?: { id?: string }; query?: Record<string, unknown> } }) => unknown;
function answer(routes: Record<string, Handler>) {
  mocks.get.mockImplementation(async (path: string, opts?: Parameters<Handler>[0]) => {
    const fn = routes[path];
    return fn ? fn(opts) : { data: { data: [], pagination: { total: 0, limit: 1000, offset: 0, next_offset: null } } };
  });
}

const interfacesOf = (byAsset: Record<string, Interface[]>): Handler => (opts) => page(byAsset[opts?.params?.path?.id ?? ''] ?? []);

async function mount(ui: React.ReactNode, permissions: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter>{ui}</MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
}

const READ = ['dcim.read'];
const MANAGE = ['dcim.read', 'dcim.manage'];
const text = () => document.body.textContent ?? '';
const byTest = (id: string) => [...document.body.querySelectorAll(`[data-testid="${id}"]`)];
const byLabel = <T extends Element>(label: string) => document.body.querySelector<T>(`[aria-label="${label}"]`);
const tick = (ms = 0) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });

function setValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}
function button(label: string): HTMLButtonElement {
  const b = [...document.body.querySelectorAll('button')].find((x) => x.textContent?.trim() === label || x.getAttribute('aria-label') === label);
  if (!b) throw new Error(`no button "${label}" in: ${text()}`);
  return b;
}

describe('Cable column on the Interfaces tab', () => {
  it('default: a cabled interface names its far end as asset:port and links to the far asset', async () => {
    answer({ '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI1, GI2, VLAN] }), '/dcim/cables': () => page([CABLE]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await tick();
    const header = [...document.body.querySelectorAll('[data-testid="interfaces-table"] th')].map((th) => th.textContent);
    expect(header).toContain('Cable');
    const peer = byTest('cable-peer');
    expect(peer).toHaveLength(1);
    expect(peer[0].textContent).toContain('srv-9:eth9');
    expect(peer[0].querySelector('a')?.getAttribute('href')).toBe(`/inventory/assets/${FAR_ID}`);
    // The cables are asked for by this asset.
    const cablesCall = mocks.get.mock.calls.find(([p]) => p === '/dcim/cables');
    expect(cablesCall?.[1]?.params?.query?.asset_id).toBe(ASSET_ID);
  });

  it('proposed: an LLDP proposal is marked Proposed (linking to Approvals), distinct from a cable of record (row 3.3)', async () => {
    const proposed = { ...CABLE, status: 'pending', source_kind: 'measured', label: 'lldp', color: null };
    answer({ '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI1] }), '/dcim/cables': () => page([proposed]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await tick();
    const chip = byTest('cable-proposed');
    expect(chip).toHaveLength(1);
    expect(chip[0].getAttribute('href')).toBe('/discovery/approvals');
    expect(chip[0].getAttribute('title')).toContain('LLDP');
    expect(byTest('cable-peer')[0].textContent).toContain('srv-9:eth9');
    act(() => root.unmount());
    root = createRoot(host);
    answer({ '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI1] }), '/dcim/cables': () => page([CABLE]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await tick();
    expect(byTest('cable-proposed')).toHaveLength(0);
  });

  it('empty: an uncabled interface offers Connect to a manager, nothing to a reader; a virtual one never', async () => {
    answer({ '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI2, VLAN] }), '/dcim/cables': () => page([]) });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await tick();
    expect(byTest('cable-none')).toHaveLength(1);
    expect(byLabel('Connect GigabitEthernet1/0/2')).not.toBeNull();
    expect(byLabel('Connect Vlan10')).toBeNull();
    act(() => root.unmount());
    root = createRoot(host);
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await tick();
    expect(byLabel('Connect GigabitEthernet1/0/2')).toBeNull();
  });

  it('loading: the column waits for the asset\'s cables', async () => {
    answer({ '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI2] }), '/dcim/cables': () => new Promise(() => {}) });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await tick();
    expect(byTest('cable-loading')).toHaveLength(1);
    expect(byLabel('Connect GigabitEthernet1/0/2')).toBeNull();
  });

  it('error: a failed cable read is not "uncabled" — no Connect is offered', async () => {
    answer({ '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI2] }), '/dcim/cables': () => ({ error: { error: { message: 'boom' } } }) });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await tick();
    expect(byTest('cable-error')).toHaveLength(1);
    expect(byLabel('Connect GigabitEthernet1/0/2')).toBeNull();
  });

  it('success: Connect picks site › asset › kind › port and posts both ends with the cable fields', async () => {
    answer({
      '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI2], [FAR_ID]: [FAR_ETH0, FAR_ETH1] }),
      '/dcim/cables': () => page([]),
      '/dcim/sites': () => ({ data: { sites: [{ id: 'site-dc1', name: 'DC1' }] } }),
      '/infrastructure-assets': () => ({ data: { assets: [{ id: FAR_ID, hostname: 'srv-1', display_name: 'srv-1', class_key: 'server' }], pagination: { total: 1, page: 1, page_size: 50 } } }),
    });
    mocks.post.mockResolvedValue({ data: { data: CABLE } });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await tick();
    await act(async () => { button('Connect GigabitEthernet1/0/2').click(); });
    expect(byTest('connect-cable-modal')).toHaveLength(1);
    // Connect is not available until a far port is chosen.
    expect(button('Connect cable').disabled).toBe(true);
    await tick();
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Site')!, 'site-dc1'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Search for the far asset')!, 'srv'); });
    await tick(350);
    await tick();
    const search = mocks.get.mock.calls.find(([p]) => p === '/infrastructure-assets');
    expect(search?.[1]?.params?.query?.query).toBe('site.id:site-dc1 and "srv"');
    await act(async () => { button('srv-1').click(); });
    await tick();
    const portSel = byLabel<HTMLSelectElement>('Far port')!;
    const opts = [...portSel.options].map((o) => [o.textContent, o.disabled]);
    expect(opts).toContainEqual(['eth1 (in use)', true]);
    await act(async () => { setValue(portSel, 'far-eth0'); });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Cable type')!, 'cat6a'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Cable label')!, 'P-42'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Cable length')!, '2.5'); });
    await act(async () => { button('Connect cable').click(); });
    await tick();
    expect(mocks.post).toHaveBeenCalledWith('/dcim/cables', {
      body: {
        a_terminations: [{ termination_kind: 'interface', termination_id: 'gi2' }],
        b_terminations: [{ termination_kind: 'interface', termination_id: 'far-eth0' }],
        operational_status: 'connected', type: 'cat6a', label: 'P-42', length: 2.5, length_unit: 'm',
      },
    });
    expect(byTest('connect-cable-modal')).toHaveLength(0);
  });

  it('a refused Connect keeps the modal open with the server\'s reason', async () => {
    answer({
      '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI2], [FAR_ID]: [FAR_ETH0] }),
      '/dcim/cables': () => page([]),
      '/infrastructure-assets': () => ({ data: { assets: [{ id: FAR_ID, hostname: 'srv-1', display_name: 'srv-1', class_key: 'server' }], pagination: { total: 1, page: 1, page_size: 50 } } }),
    });
    mocks.post.mockResolvedValue({ error: { error: { code: 'conflict', message: 'interface far-eth0 is already on cable x' } } });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await tick();
    await act(async () => { button('Connect GigabitEthernet1/0/2').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Search for the far asset')!, 'srv'); });
    await tick(350);
    await tick();
    await act(async () => { button('srv-1').click(); });
    await tick();
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Far port')!, 'far-eth0'); });
    await act(async () => { button('Connect cable').click(); });
    await tick();
    expect(byTest('connect-cable-modal')).toHaveLength(1);
    expect(byTest('connect-error')[0]?.textContent).toContain('already on cable');
  });

  it('Disconnect deletes the cable after a confirmation', async () => {
    answer({ '/dcim/assets/{id}/interfaces': interfacesOf({ [ASSET_ID]: [GI1] }), '/dcim/cables': () => page([CABLE]) });
    mocks.del.mockResolvedValue({});
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await tick();
    await act(async () => { button('Disconnect GigabitEthernet1/0/1').click(); });
    expect(text()).toContain('Disconnect GigabitEthernet1/0/1?');
    await act(async () => { button('Disconnect').click(); });
    await tick();
    expect(mocks.del).toHaveBeenCalledWith('/dcim/cables/{id}', { params: { path: { id: 'cab1' } } });
  });
});

describe('Cable column on the Ports tab', () => {
  it('front, rear and console ports carry the column; a device bay does not', async () => {
    const base = {
      tenant_id: 't', asset_id: ASSET_ID, module_id: null, label: null, mark_connected: false, cable_id: null, cable_end: null,
      source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {}, description: null, comments: null,
      status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
      created_at: NOW, updated_at: NOW, created_by: null,
    };
    const rear = { ...base, id: 'r1', name: 'Rear1', type: 'lc', color: null, positions: 1, cable_id: 'cab2', cable_end: 'A' };
    const trunk = { ...CABLE, id: 'cab2', a_terminations: [{ ...CABLE.a_terminations[0], termination_kind: 'rear_port' as const, termination_id: 'r1', name: 'Rear1' }],
      b_terminations: [{ ...CABLE.b_terminations[0], termination_kind: 'rear_port' as const, termination_id: 'r9', name: 'Rear1', asset_name: 'pp-9' }] };
    answer({
      '/dcim/assets/{id}/rear-ports': () => page([rear]),
      '/dcim/assets/{id}/console-ports': () => page([{ ...base, id: 'c1', name: 'con 0', type: 'rj-45', speed: 9600, mark_connected: true }]),
      '/dcim/cables': () => page([trunk]),
    });
    await mount(<PortsTab asset={ASSET as never} />, MANAGE);
    await tick();
    // Console ports section first: the marked-connected port says so and offers no Connect.
    expect(byTest('cable-marked')).toHaveLength(1);
    expect(byLabel('Connect con 0')).toBeNull();
    const rearTab = [...document.body.querySelectorAll('[role="tab"]')].find((t) => t.textContent?.startsWith('Rear ports')) as HTMLButtonElement;
    await act(async () => { rearTab.click(); });
    await tick();
    expect(byTest('cable-peer')[0]?.textContent).toContain('pp-9:Rear1');
    const bayTab = [...document.body.querySelectorAll('[role="tab"]')].find((t) => t.textContent?.startsWith('Device bays')) as HTMLButtonElement;
    await act(async () => { bayTab.click(); });
    await tick();
    expect(byTest('port-cable')).toHaveLength(0);
  });
});
