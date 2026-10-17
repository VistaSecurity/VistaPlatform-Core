// @vitest-environment jsdom
//
// The asset page's Interfaces tab (DCIM BUILD_PLAN row 1.2): its five states,
// the 802.1Q controls that disable per mode, the LAG choices, the add flow's
// request body, the permission gates, and its registration on the asset page
// (mounted through the REAL AssetPage route, so removing the tab from the
// registry or the page's switch fails here).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: mocks.patch, DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { AssetPage } from '../asset-page';
import { InterfacesTab, bodyOf, draftProblem, type Draft } from './interfaces-tab';
import { hierarchyChoices, lagChoices, modeControls, parseVlanIds, speedText } from './interface-rules';
import type { Interface } from './interface-queries';

const ASSET_ID = '11111111-1111-4111-8111-111111111111';
const NOW = new Date().toISOString();
const ASSET = { id: ASSET_ID, hostname: 'sw-1.example.test', display_name: 'sw-1.example.test', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };
const VLAN = '33333333-3333-4333-8333-333333333333';

function iface(over: Partial<Interface>): Interface {
  return {
    id: 'i-' + Math.random().toString(16).slice(2), asset_id: ASSET_ID, module_id: null, name: 'eth0', label: null,
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

const PO1 = iface({ id: 'po1', name: 'Port-channel1', type: 'lag', type_label: 'Link Aggregation Group (LAG)' });
const GI24 = iface({
  id: 'gi24', name: 'GigabitEthernet1/0/24', lag_id: 'po1', mode: 'tagged', tagged_vlan_ids: [VLAN],
  mac_address: '00:11:22:33:44:55', speed_kbps: 1_000_000, mtu: 9000, operational_status: 'up', description: 'to core',
});
const PENDING = iface({ id: 'p1', name: 'eth9', status: 'pending', source_kind: 'measured' });

const page = (rows: Interface[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });

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

type RouteMap = Record<string, (opts?: { params?: { query?: Record<string, unknown> } }) => unknown>;
function answer(routes: RouteMap) {
  mocks.get.mockImplementation(async (path: string, opts?: { params?: { query?: Record<string, unknown> } }) => {
    const fn = routes[path];
    return fn ? fn(opts) : { data: {} };
  });
}

async function mount(ui: React.ReactNode, permissions: string[], path = '/') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/" element={ui} />
              <Route path="/inventory/assets/:id/:tab?" element={<AssetPage />} />
            </Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
}

const READ = ['dcim.read'];
const MANAGE = ['dcim.read', 'dcim.manage'];
const text = () => document.body.textContent ?? '';
const byTest = (id: string) => document.body.querySelectorAll(`[data-testid="${id}"]`);
const byLabel = <T extends Element>(label: string) => document.body.querySelector<T>(`[aria-label="${label}"]`);

function setValue(el: HTMLTextAreaElement | HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
    : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}

function button(label: string): HTMLButtonElement {
  const b = [...document.body.querySelectorAll('button')].find((x) => x.textContent?.trim() === label || x.getAttribute('aria-label') === label);
  if (!b) throw new Error(`no button "${label}" in: ${text()}`);
  return b;
}

describe('<InterfacesTab> states', () => {
  it('default: one row per interface with type label, MAC, speed, MTU, 802.1Q, state, LAG and pending badge', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => page([PO1, GI24, PENDING]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('interface-row')).toHaveLength(3));
    expect(text()).toContain('GigabitEthernet1/0/24');
    expect(text()).toContain('in Port-channel1');
    expect(text()).toContain('00:11:22:33:44:55');
    expect(text()).toContain('1 Gbps');
    expect(text()).toContain('9000');
    expect(text()).toContain('Tagged · 1 VLAN');
    expect(byTest('oper-badge')).toHaveLength(1);
    expect(byTest('pending-badge')).toHaveLength(1);
    expect(mocks.get).toHaveBeenCalledWith('/dcim/assets/{id}/interfaces', { params: { path: { id: ASSET_ID }, query: { limit: 1000 } } });
  });

  it('empty: says nothing has been reported, not that the asset has none', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => page([]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No interfaces reported yet'));
    expect(text()).toContain('says nothing about whether it has any');
    expect(text()).not.toMatch(/has no interfaces/i);
  });

  it('loading: a skeleton while the request is in flight', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
  });

  it('error: the server reason and a retry', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => ({ error: { error: { code: 'internal_error', message: 'database unavailable' } } }) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('substrate-error')).toHaveLength(1));
    expect(text()).toContain('database unavailable');
    expect(text()).toContain('Retry');
  });

  it('a search with no match says so, distinct from the empty state', async () => {
    answer({ '/dcim/assets/{id}/interfaces': (o) => page(o?.params?.query?.q ? [] : [GI24]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('interface-row')).toHaveLength(1));
    await act(async () => { setValue(byLabel<HTMLInputElement>('Search interfaces')!, 'xe-'); });
    await vi.waitFor(() => expect(text()).toContain('No interfaces match'));
    expect(text()).not.toContain('No interfaces reported yet');
  });

  it('read-only: dcim.read sees the list but no add, edit or delete', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => page([GI24]) });
    await mount(<InterfacesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('interface-row')).toHaveLength(1));
    expect(text()).not.toContain('Add interface');
    expect(byLabel('Delete GigabitEthernet1/0/24')).toBeNull();
  });
});

describe('the add / edit drawer', () => {
  it('mode controls disable per rule: none → no VLANs; access → untagged only; tagged → both; tagged-all → no list', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => page([PO1]), '/dcim/changes': () => page([]) });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('interface-row')).toHaveLength(1));
    await act(async () => { button('Add interface').click(); });
    const untagged = () => byLabel<HTMLInputElement>('Untagged VLAN')!;
    const tagged = () => byLabel<HTMLTextAreaElement>('Tagged VLANs')!;
    const mode = byLabel<HTMLSelectElement>('Mode')!;
    expect(untagged().disabled).toBe(true);
    expect(tagged().disabled).toBe(true);
    await act(async () => { setValue(mode, 'access'); });
    expect(untagged().disabled).toBe(false);
    expect(tagged().disabled).toBe(true);
    await act(async () => { setValue(mode, 'tagged'); });
    expect(untagged().disabled).toBe(false);
    expect(tagged().disabled).toBe(false);
    await act(async () => { setValue(mode, 'tagged-all'); });
    expect(tagged().disabled).toBe(true);
  });

  it('adds GigabitEthernet1/0/24 as a tagged member of Port-channel1 with a VLAN', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => page([PO1]), '/dcim/changes': () => page([]) });
    mocks.post.mockResolvedValue({ data: { data: GI24 } });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('interface-row')).toHaveLength(1));
    await act(async () => { button('Add interface').click(); });
    await act(async () => {
      setValue(byLabel<HTMLInputElement>('Name')!, 'GigabitEthernet1/0/24');
      setValue(byLabel<HTMLSelectElement>('Type')!, '1000base-t');
    });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('LAG')!, 'po1'); });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Mode')!, 'tagged'); });
    // Tagged with no VLAN cannot be saved.
    expect(text()).toContain('Tagged mode needs at least one tagged VLAN');
    expect([...document.body.querySelectorAll('button')].filter((b) => b.textContent === 'Add interface').every((b) => b.disabled || !b.closest('[data-testid="interface-drawer"]'))).toBe(true);
    await act(async () => { setValue(byLabel<HTMLTextAreaElement>('Tagged VLANs')!, VLAN); });
    const save = [...document.body.querySelectorAll('[data-testid="interface-drawer"] button')].find((b) => b.textContent === 'Add interface') as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    await act(async () => { save.click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    const [path, opts] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/dcim/interfaces');
    expect(opts.body).toMatchObject({
      asset_id: ASSET_ID, name: 'GigabitEthernet1/0/24', type: '1000base-t', lag_id: 'po1',
      mode: 'tagged', tagged_vlan_ids: [VLAN], enabled: true,
    });
  });

  it('a server rule refusal is shown in the drawer', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => page([]) });
    mocks.post.mockResolvedValue({ error: { error: { code: 'invalid_interface', message: 'the LAG must be an interface of type "lag"', field: 'lag_id' } } });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('No interfaces reported yet'));
    await act(async () => { button('Add interface').click(); });
    await act(async () => {
      setValue(byLabel<HTMLInputElement>('Name')!, 'eth0');
      setValue(byLabel<HTMLSelectElement>('Type')!, '1000base-t');
    });
    const save = [...document.body.querySelectorAll('[data-testid="interface-drawer"] button')].find((b) => b.textContent === 'Add interface') as HTMLButtonElement;
    await act(async () => { save.click(); });
    await vi.waitFor(() => expect(byTest('interface-form-error')[0]?.textContent).toContain('type "lag"'));
  });

  it('an existing interface opens with its change record, and delete asks first', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => page([GI24]), '/dcim/changes': () => page([]) });
    mocks.del.mockResolvedValue({});
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('interface-row')).toHaveLength(1));
    await act(async () => { button('Open GigabitEthernet1/0/24').click(); });
    await vi.waitFor(() => expect(mocks.get).toHaveBeenCalledWith('/dcim/changes', { params: { query: { object_kind: 'interface', object_id: 'gi24', limit: 25 } } }));
    await act(async () => { button('Cancel').click(); });
    await act(async () => { button('Delete GigabitEthernet1/0/24').click(); });
    expect(text()).toContain('Delete GigabitEthernet1/0/24?');
    expect(mocks.del).not.toHaveBeenCalled();
    await act(async () => { button('Delete').click(); });
    await vi.waitFor(() => expect(mocks.del).toHaveBeenCalledWith('/dcim/interfaces/{id}', { params: { path: { id: 'gi24' } } }));
  });
});

describe('the VLAN picker (row 1.3 VLANs)', () => {
  const V10 = { id: '44444444-4444-4444-8444-444444444410', vid: 10, name: 'users', status: 'active' };
  const V20 = { id: '44444444-4444-4444-8444-444444444420', vid: 20, name: 'voice', status: 'active' };
  const WITH_IPAM = [...MANAGE, 'ipam.read'];

  it('with ipam.read: untagged is a VLAN select and tagged a checkbox list, and the chosen ids are sent', async () => {
    answer({
      '/dcim/assets/{id}/interfaces': () => page([PO1]),
      '/ipam/vlans': () => ({ data: { data: [V20, V10], pagination: { total: 2, limit: 1000, offset: 0, next_offset: null } } }),
    });
    mocks.post.mockResolvedValue({ data: { data: GI24 } });
    await mount(<InterfacesTab asset={ASSET as never} />, WITH_IPAM);
    await vi.waitFor(() => expect(byTest('interface-row')).toHaveLength(1));
    await act(async () => { button('Add interface').click(); });
    await act(async () => {
      setValue(byLabel<HTMLInputElement>('Name')!, 'GigabitEthernet1/0/24');
      setValue(byLabel<HTMLSelectElement>('Type')!, '1000base-t');
      setValue(byLabel<HTMLSelectElement>('Mode')!, 'tagged');
    });
    await vi.waitFor(() => expect(byTest('tagged-vlan-picker')).toHaveLength(1));
    const untagged = byLabel<HTMLSelectElement>('Untagged VLAN')!;
    expect(untagged.tagName).toBe('SELECT');
    expect([...untagged.options].map((o) => o.textContent)).toEqual(['None', '10 · users', '20 · voice']);
    await act(async () => {
      setValue(untagged, V10.id);
      byLabel<HTMLInputElement>('Tagged 20 · voice')!.click();
    });
    const save = [...document.body.querySelectorAll('[data-testid="interface-drawer"] button')].find((b) => b.textContent === 'Add interface') as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    await act(async () => { save.click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    const [, opts] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(opts.body).toMatchObject({ mode: 'tagged', untagged_vlan_id: V10.id, tagged_vlan_ids: [V20.id] });
  });

  it('when the VLAN list fails, the drawer falls back to typed ids rather than dead-ending', async () => {
    answer({
      '/dcim/assets/{id}/interfaces': () => page([]),
      '/ipam/vlans': () => ({ error: { error: { code: 'internal_error', message: 'down' } } }),
    });
    await mount(<InterfacesTab asset={ASSET as never} />, WITH_IPAM);
    await vi.waitFor(() => expect(text()).toContain('No interfaces reported yet'));
    await act(async () => { button('Add interface').click(); });
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Mode')!, 'tagged'); });
    await vi.waitFor(() => expect(mocks.get.mock.calls.some(([p]) => p === '/ipam/vlans')).toBe(true));
    expect(byLabel<HTMLElement>('Untagged VLAN')!.tagName).toBe('INPUT');
    expect(byTest('tagged-vlan-picker')).toHaveLength(0);
  });

  it('without ipam.read the VLAN list is never requested', async () => {
    answer({ '/dcim/assets/{id}/interfaces': () => page([]) });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('No interfaces reported yet'));
    await act(async () => { button('Add interface').click(); });
    expect(mocks.get.mock.calls.some(([p]) => p === '/ipam/vlans')).toBe(false);
  });
});

describe('asset page wiring', () => {
  it('the Interfaces tab is registered and lists the asset\'s interfaces', async () => {
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/assets/{id}/interfaces': () => page([GI24]),
      '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [] } }),
    });
    await mount(null, MANAGE, `/inventory/assets/${ASSET_ID}/interfaces`);
    await vi.waitFor(() => expect(byTest('interface-row')).toHaveLength(1));
    expect([...document.body.querySelectorAll('[role="tab"]')].some((t) => t.textContent === 'Interfaces' && t.getAttribute('aria-selected') === 'true')).toBe(true);
  });

  it('without dcim.read the tab explains the permission and fetches nothing', async () => {
    answer({ '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }) });
    await mount(null, ['assets.read'], `/inventory/assets/${ASSET_ID}/interfaces`);
    await vi.waitFor(() => expect(text()).toContain("You can't view interfaces"));
    expect(mocks.get.mock.calls.some(([p]) => String(p).startsWith('/dcim/assets'))).toBe(false);
  });
});

describe('interface rules (mirrors interface_rules.go)', () => {
  it('modeControls', () => {
    expect(modeControls('')).toEqual({ untagged: false, tagged: false, taggedRequired: false });
    expect(modeControls('access')).toEqual({ untagged: true, tagged: false, taggedRequired: false });
    expect(modeControls('tagged')).toEqual({ untagged: true, tagged: true, taggedRequired: true });
    expect(modeControls('tagged-all')).toEqual({ untagged: true, tagged: false, taggedRequired: false });
  });

  it('LAG choices: only LAGs, never for a LAG, virtual or bridge', () => {
    const all = [PO1, GI24, iface({ id: 'po2', name: 'Port-channel2', type: 'lag' })];
    expect(lagChoices(all, 'gi24', '1000base-t').map((i) => i.id)).toEqual(['po1', 'po2']);
    expect(lagChoices(all, 'po2', 'lag')).toEqual([]);
    expect(lagChoices(all, undefined, 'virtual')).toEqual([]);
  });

  it('parent choices exclude self and anything below it', () => {
    const a = iface({ id: 'a', name: 'a' });
    const b = iface({ id: 'b', name: 'b', parent_id: 'a' });
    const c = iface({ id: 'c', name: 'c', parent_id: 'b' });
    expect(hierarchyChoices([a, b, c], 'a', 'parent_id').map((i) => i.id)).toEqual([]);
    expect(hierarchyChoices([a, b, c], 'c', 'parent_id').map((i) => i.id)).toEqual(['a', 'b']);
  });

  it('a mode change clears what the mode does not allow', () => {
    const d: Draft = {
      name: 'eth0', label: '', type: '1000base-t', enabled: true, mgmt_only: false, mtu: '', mac_address: '',
      speed_kbps: '', duplex: '', mode: 'access', untagged_vlan_id: VLAN, tagged_vlan_ids: VLAN, lag_id: '',
      parent_id: '', bridge_id: '', description: '',
    };
    expect(bodyOf(d)).toMatchObject({ mode: 'access', untagged_vlan_id: VLAN, tagged_vlan_ids: [] });
    expect(bodyOf({ ...d, mode: '' })).toMatchObject({ mode: null, untagged_vlan_id: null, tagged_vlan_ids: [] });
    expect(draftProblem({ ...d, mode: 'tagged', tagged_vlan_ids: '' })).toMatch(/at least one/);
    expect(draftProblem({ ...d, mode: 'tagged', tagged_vlan_ids: 'vlan10' })).toMatch(/Not a VLAN id/);
    expect(draftProblem({ ...d, mtu: '0' })).toMatch(/MTU/);
  });

  it('parses VLAN ids and renders speeds', () => {
    expect(parseVlanIds(`${VLAN}, ${VLAN.toUpperCase()}\nbogus`)).toEqual({ ids: [VLAN], bad: ['bogus'] });
    expect(speedText(1_000_000)).toBe('1 Gbps');
    expect(speedText(2_500_000)).toBe('2.5 Gbps');
    expect(speedText(100_000)).toBe('100 Mbps');
    expect(speedText(null)).toBe('');
  });
});
