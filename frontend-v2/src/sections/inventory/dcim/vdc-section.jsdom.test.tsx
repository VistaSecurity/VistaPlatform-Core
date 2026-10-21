// @vitest-environment jsdom
//
// Virtual device contexts (DCIM gap 1): the Hardware tab's card in its five
// states (loading, error, empty, the table, a write's result), the add/edit
// request bodies and the delete, the dcim.manage gate, and — through the REAL
// AssetPage — that the card is on the Hardware tab. On the Interfaces tab: the
// Context column and the drawer's context picker, whose PATCH sends
// virtual_device_context_ids.
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
import { InterfacesTab } from './interfaces-tab';
import type { Interface } from './interface-queries';
import { VirtualDeviceContextsSection, vdcBodyOf, vdcDraftOf, vdcDraftProblem } from './vdc-section';
import type { VirtualDeviceContext } from './vdc-queries';

const ASSET_ID = '11111111-1111-4111-8111-111111111111';
const NOW = new Date().toISOString();
const ASSET = { id: ASSET_ID, hostname: 'fw-1.example.test', display_name: 'fw-1', class_key: 'firewall', asset_status: 'monitoring', risk_score: 0, deleted_at: null };
const life = {
  tenant_id: 't', source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {}, description: null, comments: null,
  status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
  created_at: NOW, updated_at: NOW, created_by: null,
};
const ctx = (id: string, name: string, extra: Partial<VirtualDeviceContext> = {}): VirtualDeviceContext => ({
  ...life, id, asset_id: ASSET_ID, name, identifier: null, operational_status: 'active', business_unit_id: null,
  primary_ip4_id: null, primary_ip6_id: null, ...extra,
});
const ROOT = ctx('vdc-root', 'root', { identifier: 0, primary_ip4_id: 'ip4', business_unit_id: 'bu-1' });
const CUST = ctx('vdc-cust', 'customer-b', { identifier: 2, operational_status: 'planned', primary_ip6_id: 'ip-hidden' });
const IP4 = { id: 'ip4', address: '192.0.2.10/24', status: 'active' };
const IP6 = { id: 'ip6', address: '2001:db8::10/64', status: 'active' };

function iface(over: Partial<Interface>): Interface {
  return {
    id: 'i-' + Math.random().toString(16).slice(2), asset_id: ASSET_ID, module_id: null, name: 'eth0', label: null,
    type: '1000base-t', type_label: '1000BASE-T (1GE)', enabled: true, mgmt_only: false, mtu: null, mac_address: null,
    mac_addresses: [], speed_kbps: null, duplex: null, mode: null, untagged_vlan_id: null, tagged_vlan_ids: [],
    vrf_id: null, parent_id: null, bridge_id: null, lag_id: null, rf_role: null, rf_channel: null,
    rf_channel_frequency: null, rf_channel_width: null, tx_power: null, poe_mode: null, poe_type: null, wwn: null,
    operational_status: null, admin_status: null, vdcs: [], virtual_device_contexts: [], virtual_device_context_ids: [],
    mark_connected: false, cable_id: null, cable_end: null,
    source_kind: 'declared', source_ref: null, custom_fields: {}, description: null, comments: null, status: 'active',
    first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
    created_at: NOW, updated_at: NOW, created_by: null, vlan_translation_policy_id: null,
    ...over,
  };
}
const ETH1 = iface({ id: 'eth1', name: 'ethernet1/1', vdcs: ['root'], virtual_device_contexts: [{ id: 'vdc-root', name: 'root' }], virtual_device_context_ids: ['vdc-root'] });
const ETH2 = iface({ id: 'eth2', name: 'ethernet1/2', vdcs: ['root'], virtual_device_contexts: [{ id: 'vdc-root', name: 'root' }], virtual_device_context_ids: ['vdc-root'] });
const ETH3 = iface({ id: 'eth3', name: 'ethernet1/3' });

const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });
type RouteMap = Record<string, () => unknown>;
const BASE: RouteMap = {
  '/dcim/assets/{id}/virtual-device-contexts': () => page([ROOT, CUST]),
  '/dcim/assets/{id}/interfaces': () => page([ETH1, ETH2, ETH3]),
  '/ipam/ip-addresses': () => page([IP4, IP6]),
  '/dcim/business-units': () => ({ data: { business_units: [{ id: 'bu-1', name: 'Finance', slug: 'finance' }] } }),
};
function answer(routes: RouteMap = {}) {
  const all = { ...BASE, ...routes };
  mocks.get.mockImplementation(async (path: string) => (all[path] ? all[path]() : { data: {} }));
}

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
const MANAGE = ['dcim.read', 'dcim.manage', 'ipam.read'];
const text = () => document.body.textContent ?? '';
const byTest = (id: string) => document.body.querySelectorAll(`[data-testid="${id}"]`);
const byLabel = <T extends Element>(label: string) => document.body.querySelector<T>(`[aria-label="${label}"]`);
type Call = [string, { params: { path: { id: string } }; body: Record<string, unknown> }];
const call = (m: { mock: { calls: unknown[][] } }, n = 0) => m.mock.calls[n] as Call;
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });

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

const section = (perms: string[]) => mount(<VirtualDeviceContextsSection asset={ASSET as never} canManage={perms.includes('dcim.manage')} />, perms);

describe('<VirtualDeviceContextsSection> states', () => {
  it('default: one row per context with identifier, status, business unit, primary IPs and interface count', async () => {
    answer();
    await section(MANAGE);
    await flush();
    const rows = byTest('vdc-row');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('root');
    expect(rows[0].textContent).toContain('Finance');
    expect(rows[0].textContent).toContain('192.0.2.10/24');
    expect(rows[1].textContent).toContain('Planned');
    // An address that is set but not readable says so — never a blank.
    expect(rows[1].textContent).toContain('set');
    const counts = [...byTest('vdc-interface-count')].map((c) => c.textContent);
    expect(counts).toEqual(['2', '0']);
  });

  it('discovered contexts say so, and a stale one is marked (DCIM gap 1, part 2)', async () => {
    answer({
      '/dcim/assets/{id}/virtual-device-contexts': () => page([
        ctx('vdc-v1', 'vsys1', { identifier: 1, source_kind: 'measured', status: 'pending' }),
        ctx('vdc-v2', 'vsys2', { identifier: 2, source_kind: 'measured', status: 'stale' }),
        ROOT,
      ]),
    });
    await section(READ);
    await flush();
    const rows = [...byTest('vdc-row')].map((r) => r.textContent ?? '');
    expect(rows[0]).toContain('Pending');
    expect(rows[0]).toContain('Discovered');
    expect(rows[0]).not.toContain('Stale');
    expect(rows[1]).toContain('Stale');
    expect(rows[1]).toContain('Discovered');
    // A declared context carries neither mark.
    expect(rows[2]).not.toContain('Discovered');
    expect(rows[2]).not.toContain('Stale');
  });

  it('empty: not recorded, which is not "none"', async () => {
    answer({ '/dcim/assets/{id}/virtual-device-contexts': () => page([]) });
    await section(MANAGE);
    await flush();
    expect(text()).toContain('No virtual device contexts recorded');
    expect(text()).toContain('says nothing about whether it is partitioned');
  });

  it('loading', async () => {
    answer({ '/dcim/assets/{id}/virtual-device-contexts': () => new Promise(() => {}) });
    await section(READ);
    expect(text()).toContain('Loading virtual device contexts');
  });

  it('error, with a retry', async () => {
    answer({ '/dcim/assets/{id}/virtual-device-contexts': () => ({ error: { error: { message: 'boom' } } }) });
    await section(READ);
    await flush();
    expect(text()).toContain('boom');
    expect(() => button('Retry')).not.toThrow();
  });

  it('read-only: no add, edit or delete without dcim.manage', async () => {
    answer();
    await section(READ);
    await flush();
    expect(byTest('vdc-row')).toHaveLength(2);
    expect(() => button('Add context')).toThrow();
    expect(byLabel('Edit root')).toBeNull();
    expect(byLabel('Delete root')).toBeNull();
  });
});

describe('<VirtualDeviceContextsSection> writes', () => {
  it('success: add posts the draft to the asset; the list refetches', async () => {
    answer();
    mocks.post.mockResolvedValue({ data: { data: ctx('vdc-new', 'vsys3') } });
    await section(MANAGE);
    await flush();
    await act(async () => { button('Add context').click(); });
    setValue(byLabel<HTMLInputElement>('Context name')!, ' vsys3 ');
    setValue(byLabel<HTMLInputElement>('Context identifier')!, '3');
    setValue(byLabel<HTMLSelectElement>('Context status')!, 'offline');
    setValue(byLabel<HTMLSelectElement>('Primary IPv4')!, 'ip4');
    const ip6 = byLabel<HTMLSelectElement>('Primary IPv6')!;
    expect([...ip6.options].map((o) => o.textContent)).toEqual(['None', '2001:db8::10/64']);
    const before = mocks.get.mock.calls.filter(([p]) => p === '/dcim/assets/{id}/virtual-device-contexts').length;
    // The dialog's own Add context (the card's header has one too).
    const adds = [...document.body.querySelectorAll('button')].filter((b) => b.textContent?.trim() === 'Add context');
    await act(async () => { adds[adds.length - 1].click(); });
    await flush();
    expect(mocks.post).toHaveBeenCalledTimes(1);
    const [path, init] = call(mocks.post);
    expect(path).toBe('/dcim/assets/{id}/virtual-device-contexts');
    expect(init.params.path.id).toBe(ASSET_ID);
    expect(init.body).toEqual({ name: 'vsys3', identifier: 3, operational_status: 'offline', business_unit_id: null, primary_ip4_id: 'ip4', primary_ip6_id: null, description: null });
    expect(mocks.get.mock.calls.filter(([p]) => p === '/dcim/assets/{id}/virtual-device-contexts').length).toBeGreaterThan(before);
    expect(byTest('vdc-modal')).toHaveLength(0);
  });

  it('a server refusal stays in the dialog', async () => {
    answer();
    mocks.patch.mockResolvedValue({ error: { error: { message: 'primary_ip4_id must be assigned to one of the asset\'s interfaces' } } });
    await section(MANAGE);
    await flush();
    await act(async () => { byLabel<HTMLButtonElement>('Edit root')!.click(); });
    expect(byLabel<HTMLInputElement>('Context name')!.value).toBe('root');
    await act(async () => { button('Save').click(); });
    await flush();
    expect(call(mocks.patch)[0]).toBe('/dcim/virtual-device-contexts/{id}');
    expect(call(mocks.patch)[1].params.path.id).toBe('vdc-root');
    expect(byTest('vdc-error')[0]?.textContent).toContain('assigned to one of the asset');
  });

  it('delete asks first, then deletes the context', async () => {
    answer();
    mocks.del.mockResolvedValue({});
    await section(MANAGE);
    await flush();
    await act(async () => { byLabel<HTMLButtonElement>('Delete customer-b')!.click(); });
    expect(text()).toContain('Its interfaces leave it');
    await act(async () => { button('Delete').click(); });
    await flush();
    expect(call(mocks.del)[0]).toBe('/dcim/virtual-device-contexts/{id}');
    expect(call(mocks.del)[1].params.path.id).toBe('vdc-cust');
  });

  it('without ipam.read the primary addresses are not sent (the server keeps them)', async () => {
    answer();
    mocks.patch.mockResolvedValue({ data: { data: ROOT } });
    await section(['dcim.read', 'dcim.manage']);
    await flush();
    await act(async () => { byLabel<HTMLButtonElement>('Edit root')!.click(); });
    expect(text()).toContain('Primary addresses need the IPAM read permission');
    await act(async () => { button('Save').click(); });
    await flush();
    const { body } = call(mocks.patch)[1];
    expect('primary_ip4_id' in body || 'primary_ip6_id' in body).toBe(false);
  });

  it('the draft rules', () => {
    const d = vdcDraftOf(null);
    expect(vdcDraftProblem(d)).toBe('A name is required.');
    expect(vdcDraftProblem({ ...d, name: 'x', identifier: '-1' })).toContain('0 to 32767');
    expect(vdcDraftProblem({ ...d, name: 'x', identifier: '40000' })).toContain('0 to 32767');
    expect(vdcDraftProblem({ ...d, name: 'x'.repeat(65) })).toContain('64');
    expect(vdcDraftProblem({ ...d, name: 'x', identifier: '7' })).toBeNull();
    expect(vdcBodyOf({ ...d, name: 'x' })).toMatchObject({ identifier: null, operational_status: 'active' });
  });
});

describe('the Hardware tab carries the card (through the REAL asset page)', () => {
  it('/inventory/assets/:id/hardware shows Virtual device contexts', async () => {
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [] } }),
    });
    await mount(null, MANAGE, `/inventory/assets/${ASSET_ID}/hardware`);
    await vi.waitFor(() => expect(byTest('hardware-virtual-device-contexts')).toHaveLength(1));
    await vi.waitFor(() => expect(byTest('vdc-row')).toHaveLength(2));
  });
});

describe('<InterfacesTab> contexts', () => {
  it('the Context column names each interface\'s contexts, or says none', async () => {
    answer();
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await flush();
    expect([...byTest('interface-contexts')].map((c) => c.textContent)).toEqual(['root', 'root', '—']);
  });

  it('the drawer picks contexts of the asset and PATCHes virtual_device_context_ids', async () => {
    answer();
    mocks.patch.mockResolvedValue({ data: { data: ETH3 } });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await flush();
    await act(async () => { byLabel<HTMLButtonElement>('Open ethernet1/3')!.click(); });
    await flush();
    const picker = byTest('context-picker')[0];
    expect(picker.textContent).toContain('root');
    expect(picker.textContent).toContain('customer-b');
    await act(async () => { byLabel<HTMLInputElement>('Context customer-b')!.click(); });
    await act(async () => { button('Save').click(); });
    await flush();
    expect(call(mocks.patch)[0]).toBe('/dcim/interfaces/{id}');
    expect(call(mocks.patch)[1].body.virtual_device_context_ids).toEqual(['vdc-cust']);
  });

  it('an asset with no contexts says where to add them', async () => {
    answer({ '/dcim/assets/{id}/virtual-device-contexts': () => page([]) });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await flush();
    await act(async () => { byLabel<HTMLButtonElement>('Open ethernet1/1')!.click(); });
    await flush();
    expect(byTest('context-picker-empty')[0]?.textContent).toContain('Add them on the Hardware tab');
  });

  it('when the contexts fail to load, the drawer keeps the memberships it has', async () => {
    answer({ '/dcim/assets/{id}/virtual-device-contexts': () => ({ error: { error: { message: 'nope' } } }) });
    mocks.patch.mockResolvedValue({ data: { data: ETH1 } });
    await mount(<InterfacesTab asset={ASSET as never} />, MANAGE);
    await flush();
    await act(async () => { byLabel<HTMLButtonElement>('Open ethernet1/1')!.click(); });
    await flush();
    expect(text()).toContain('memberships are kept as they are');
    await act(async () => { button('Save').click(); });
    await flush();
    expect(call(mocks.patch)[1].body.virtual_device_context_ids).toEqual(['vdc-root']);
  });
});
