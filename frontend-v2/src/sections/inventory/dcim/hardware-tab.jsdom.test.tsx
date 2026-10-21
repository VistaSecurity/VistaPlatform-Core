// @vitest-environment jsdom
//
// The asset page's Hardware tab (DCIM BUILD_PLAN row 2.4): the five states of
// its sections, the module bay grid with Install module (the request body) and
// Remove, the inventory item tree with its links and discovered badge, the
// virtual chassis panel (members, master, add member), device bays (install a
// child), the permission gates, and the tab's registration on the REAL asset
// page — removing it from the registry or the page's switch fails here.
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
import { ASSET_TABS } from '../asset-tabs';
import { HardwareTab } from './hardware-tab';
import { itemTree, type InventoryItem } from './hardware-queries';

const ASSET_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_ID = '33333333-3333-4333-8333-333333333333';
const NOW = new Date().toISOString();
const ASSET = { id: ASSET_ID, hostname: 'core-1.example.test', display_name: 'core-1', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };
const life = {
  tenant_id: 't', source_kind: 'declared', source_ref: null, custom_fields: {}, external_ids: {}, description: null, comments: null,
  status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 0, approved_by: null, approved_at: null,
  created_at: NOW, updated_at: NOW, created_by: null,
};
const BAY_NM = { ...life, id: 'bay-nm', asset_id: ASSET_ID, module_id: null, name: 'Network Module', label: null, position: '1' };
const BAY_PS2 = { ...life, id: 'bay-ps2', asset_id: ASSET_ID, module_id: null, name: 'PS2', label: null, position: '2' };
const MODULE = { ...life, id: 'mod-1', asset_id: ASSET_ID, module_bay_id: 'bay-nm', module_type_id: 'mt-nm', operational_status: 'active', serial: 'FOC1', asset_tag: null };
const MT_NM = { id: 'mt-nm', tenant_id: null, manufacturer_id: 'cisco', model: 'C9300-NM-8X', part_number: 'C9300-NM-8X' };
const MT_PSU = { id: 'mt-psu', tenant_id: null, manufacturer_id: 'cisco', model: 'PWR-C1-715WAC', part_number: 'PWR-C1-715WAC-P' };
const IFACE = { id: 'if-1', name: 'TenGigabitEthernet1/1/1', module_id: 'mod-1' };
const item = (id: string, name: string, extra: Partial<InventoryItem> = {}): InventoryItem => ({
  ...life, id, asset_id: ASSET_ID, parent_id: null, name, label: null, role_id: null, manufacturer_id: null, part_id: null,
  serial: null, asset_tag: null, discovered: false, component_kind: null, component_id: null,
  location_id: null, quantity: 1, stock_state: 'installed', ...extra,
});
const PSU = item('i1', 'Switch 1 - Power Supply A', { role_id: 'psu', serial: 'DCB1A', discovered: true, source_kind: 'measured' });
const SFP = item('i2', 'Te1/1/1', { role_id: 'opt', discovered: true, component_kind: 'interface', component_id: 'if-1' });
const FAN = item('i3', 'Fan 1', { parent_id: 'i1' });
const VC = { id: 'vc-1', tenant_id: 't', name: 'core-1', domain: null, master_asset_id: ASSET_ID };
const MEMBERS = [
  { asset_id: ASSET_ID, display_name: 'core-1', serial: 'FOC2432L0AB', vc_position: 1, vc_priority: 15, is_master: true },
  { asset_id: OTHER_ID, display_name: 'core-2', serial: 'FOC2432L0CD', vc_position: 2, vc_priority: 14, is_master: false },
];
const DEVICE_BAY = { ...life, id: 'db-1', asset_id: ASSET_ID, module_id: null, name: 'Blade 1', label: null, installed_asset_id: null, mark_connected: false, cable_id: null, cable_end: null };

const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });
type RouteMap = Record<string, () => unknown>;
const BASE: RouteMap = {
  '/dcim/assets/{id}/hardware': () => ({ data: { data: { asset_id: ASSET_ID, class_key: 'switch', is_hardware: true, device_type: { id: 'dt', name: 'C9300-48P', slug: 'c9300' }, manufacturer: { id: 'cisco', name: 'Cisco', slug: 'cisco' }, device_role: null, platform: null, serial: 'FOC2432L0AB', asset_tag: null, template_counts: {} } } }),
  '/dcim/assets/{id}/module-bays': () => page([]),
  '/dcim/assets/{id}/modules': () => page([]),
  '/dcim/assets/{id}/inventory-items': () => page([]),
  '/dcim/assets/{id}/interfaces': () => page([]),
  '/dcim/assets/{id}/device-bays': () => page([]),
  '/dcim/assets/{id}/virtual-chassis': () => ({ data: { data: { virtual_chassis: null, members: [] } } }),
  '/dcim/inventory-item-roles': () => page([{ id: 'psu', name: 'Power supply' }, { id: 'opt', name: 'Transceiver' }]),
  '/dcim/module-types': () => page([MT_NM, MT_PSU]),
};
function answer(routes: RouteMap) {
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
const MANAGE = ['dcim.read', 'dcim.manage'];
const text = () => document.body.textContent ?? '';
const byTest = (id: string) => document.body.querySelectorAll(`[data-testid="${id}"]`);
const byLabel = <T extends Element>(label: string) => document.body.querySelector<T>(`[aria-label="${label}"]`);
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

describe('<HardwareTab> states', () => {
  it('carries the Lifecycle card (DCIM gap 4), with Edit for a manager only', async () => {
    answer({});
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('hardware-lifecycle')).toHaveLength(1));
    await vi.waitFor(() => expect(byTest('eos-badge')[0]?.textContent).toBe('End of support not recorded'));
    expect(byTest('lifecycle-edit')).toHaveLength(1);
    act(() => root.unmount());
    root = createRoot(host);
    await mount(<HardwareTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('hardware-lifecycle')).toHaveLength(1));
    expect(byTest('lifecycle-edit')).toHaveLength(0);
  });

  it('default: bays grid with the installed module card, the item tree, the chassis members and device bays', async () => {
    answer({
      '/dcim/assets/{id}/module-bays': () => page([BAY_NM, BAY_PS2]),
      '/dcim/assets/{id}/modules': () => page([MODULE]),
      '/dcim/assets/{id}/interfaces': () => page([IFACE]),
      '/dcim/assets/{id}/inventory-items': () => page([PSU, SFP, FAN]),
      '/dcim/assets/{id}/virtual-chassis': () => ({ data: { data: { virtual_chassis: VC, members: MEMBERS } } }),
      '/dcim/assets/{id}/device-bays': () => page([DEVICE_BAY]),
    });
    await mount(<HardwareTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('module-bay')).toHaveLength(2));
    expect(byTest('module-card')).toHaveLength(1);
    await vi.waitFor(() => expect(byTest('module-card')[0].textContent).toContain('C9300-NM-8X'));
    expect(byTest('module-card')[0].textContent).toContain('1 interface');
    expect(text()).toContain('Cisco C9300-48P');
    await vi.waitFor(() => expect(byTest('inventory-item-row')).toHaveLength(3));
    // The fan sits under its PSU in the tree.
    const rows = [...byTest('inventory-item-row')].map((r) => r.textContent ?? '');
    expect(rows[0]).toContain('Switch 1 - Power Supply A');
    expect(rows[1]).toContain('Fan 1');
    expect(byTest('discovered-badge')).toHaveLength(2);
    await vi.waitFor(() => expect(rows.join('|') + text()).toContain('TenGigabitEthernet1/1/1'));
    expect(byTest('chassis-member')).toHaveLength(2);
    expect(byTest('master-badge')).toHaveLength(1);
    expect(byTest('device-bay-row')).toHaveLength(1);
  });

  it('empty: each section says nothing is declared or reported, not that the asset has none', async () => {
    answer({});
    await mount(<HardwareTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No module bays'));
    expect(text()).toContain('No inventory items');
    expect(text()).toContain('says nothing about whether it has any');
    expect(text()).toContain('Not in a virtual chassis');
    expect(text()).toContain('No device bays');
  });

  it('loading: skeletons while the requests are in flight', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<HardwareTab asset={ASSET as never} />, READ);
    expect(text()).toContain('Loading module bays');
    expect(text()).toContain('Loading inventory items');
  });

  it('error: the server reason and a retry', async () => {
    answer({ '/dcim/assets/{id}/inventory-items': () => ({ error: { error: { code: 'internal_error', message: 'database unavailable' } } }) });
    await mount(<HardwareTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(text()).toContain('database unavailable'));
  });

  it('read-only: dcim.read sees everything but no install, remove or add', async () => {
    answer({ '/dcim/assets/{id}/module-bays': () => page([BAY_NM, BAY_PS2]), '/dcim/assets/{id}/modules': () => page([MODULE]) });
    await mount(<HardwareTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('module-bay')).toHaveLength(2));
    expect(text()).not.toContain('Install module');
    expect(text()).not.toContain('Remove');
    expect(text()).not.toContain('Create virtual chassis');
  });

  it('without dcim.read: the permission explanation and no request', async () => {
    answer({});
    await mount(<HardwareTab asset={ASSET as never} />, []);
    expect(text()).toContain('You can\'t view hardware');
    expect(mocks.get).not.toHaveBeenCalled();
  });
});

describe('module install and removal', () => {
  it('success: installs a PSU module into bay PS2 with the chosen type and serial', async () => {
    answer({ '/dcim/assets/{id}/module-bays': () => page([BAY_NM, BAY_PS2]), '/dcim/assets/{id}/modules': () => page([MODULE]) });
    mocks.post.mockResolvedValue({ data: { data: { ...MODULE, id: 'mod-2', module_bay_id: 'bay-ps2', module_type_id: 'mt-psu' } } });
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('module-bay')).toHaveLength(2));
    await act(async () => { button('Install module in PS2').click(); });
    await vi.waitFor(() => expect(document.body.querySelector('select[aria-label="Module type"] option[value="mt-psu"]')).not.toBeNull());
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Module type')!, 'mt-psu'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Serial')!, 'DCB9'); });
    await act(async () => { button('Install').click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    const [path, init] = mocks.post.mock.calls[0] as [string, { params: { path: { id: string } }; body: Record<string, unknown> }];
    expect(path).toBe('/dcim/assets/{id}/modules');
    expect(init.params.path.id).toBe(ASSET_ID);
    expect(init.body).toEqual({ module_bay_id: 'bay-ps2', module_type_id: 'mt-psu', serial: 'DCB9' });
  });

  it('shows the server reason when an install is refused', async () => {
    answer({ '/dcim/assets/{id}/module-bays': () => page([BAY_PS2]) });
    mocks.post.mockResolvedValue({ error: { error: { code: 'invalid_request', message: 'module bay PS2 has no position' } } });
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('module-bay')).toHaveLength(1));
    await act(async () => { button('Install module in PS2').click(); });
    await vi.waitFor(() => expect(document.body.querySelector('select[aria-label="Module type"] option[value="mt-psu"]')).not.toBeNull());
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Module type')!, 'mt-psu'); });
    await act(async () => { button('Install').click(); });
    await vi.waitFor(() => expect(byTest('install-error')[0]?.textContent).toContain('has no position'));
  });

  it('removes a module after the warning about measured components', async () => {
    answer({ '/dcim/assets/{id}/module-bays': () => page([BAY_NM]), '/dcim/assets/{id}/modules': () => page([MODULE]) });
    mocks.del.mockResolvedValue({});
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('module-card')).toHaveLength(1));
    await act(async () => { button('Remove module from Network Module').click(); });
    expect(text()).toContain('unless something was measured on them');
    // The dialog's confirm (the card's own button carries the same text).
    const confirms = [...document.body.querySelectorAll('button')].filter((b) => b.textContent?.trim() === 'Remove' && !b.getAttribute('aria-label'));
    await act(async () => { confirms[confirms.length - 1].click(); });
    await vi.waitFor(() => expect(mocks.del).toHaveBeenCalledWith('/dcim/modules/{id}', { params: { path: { id: 'mod-1' } } }));
  });
});

// DCIM gap 8: a part on the asset goes to stock or out for RMA from its row.
//
// Mutation: drop the RemoveToStockModal / OpenRmaModal mount, or the
// canManage gate on the row buttons → red.
describe('spares actions on an inventory item', () => {
  const LOC = { id: 'loc-1', site_id: 's', name: 'Stores', path: 'DC1 / Stores' };
  const withLocations: RouteMap = {
    '/dcim/assets/{id}/inventory-items': () => page([PSU, item('i9', 'PSU B', { stock_state: 'rma' })]),
    '/dcim/locations': () => ({ data: { locations: [LOC] } }),
  };

  it('read-only: no To stock or RMA on a row', async () => {
    answer(withLocations);
    await mount(<HardwareTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('inventory-item-row')).toHaveLength(2));
    expect(text()).not.toContain('To stock');
    expect(byTest('rma-badge')).toHaveLength(1);
  });

  it('removes a part to a stock location with the request body', async () => {
    answer(withLocations);
    mocks.post.mockResolvedValue({ data: { data: { item: { ...PSU, asset_id: null, location_id: 'loc-1', stock_state: 'in_stock' } } } });
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('inventory-item-row')).toHaveLength(2));
    await act(async () => { button('Remove Switch 1 - Power Supply A to stock').click(); });
    await vi.waitFor(() => expect(document.body.querySelector('select[aria-label="Stock location"] option[value="loc-1"]')).not.toBeNull());
    expect(button('Remove to stock').disabled).toBe(true);
    await act(async () => { setValue(byLabel<HTMLSelectElement>('Stock location')!, 'loc-1'); });
    await act(async () => { button('Remove to stock').click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    expect(mocks.post.mock.calls[0]).toEqual(['/dcim/inventory-items/{id}/remove', { params: { path: { id: 'i1' } }, body: { location_id: 'loc-1' } }]);
  });

  it('opens an RMA (RMA only on an installed part) and shows a refusal', async () => {
    answer(withLocations);
    mocks.post.mockResolvedValue({ error: { error: { code: 'conflict', message: 'this item is already out for RMA' } } });
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('inventory-item-row')).toHaveLength(2));
    expect(byLabel('Open RMA for PSU B')).toBeNull();
    await act(async () => { button('Open RMA for Switch 1 - Power Supply A').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Vendor')!, 'Acme Networks'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Case number')!, 'RMA-77'); });
    await act(async () => { button('Open RMA').click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    expect(mocks.post.mock.calls[0]).toEqual(['/dcim/inventory-items/{id}/rma', { params: { path: { id: 'i1' } }, body: { vendor: 'Acme Networks', case_number: 'RMA-77' } }]);
    await vi.waitFor(() => expect(byTest('spare-error')[0]?.textContent).toContain('already out for RMA'));
  });
});

describe('virtual chassis and device bays', () => {
  it('adds a member with position and priority', async () => {
    answer({ '/dcim/assets/{id}/virtual-chassis': () => ({ data: { data: { virtual_chassis: VC, members: MEMBERS.slice(0, 1) } } }) });
    mocks.post.mockResolvedValue({ data: { data: MEMBERS } });
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('chassis-member')).toHaveLength(1));
    await act(async () => { setValue(byLabel<HTMLInputElement>('Member asset id')!, OTHER_ID); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Member position')!, '2'); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Member priority')!, '14'); });
    await act(async () => { button('Add member').click(); });
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    const [path, init] = mocks.post.mock.calls[0] as [string, { params: { path: { id: string } }; body: unknown }];
    expect(path).toBe('/dcim/virtual-chassis/{id}/members');
    expect(init.params.path.id).toBe('vc-1');
    expect(init.body).toEqual({ asset_id: OTHER_ID, vc_position: 2, vc_priority: 14 });
  });

  it('refuses a position outside 0-255 before asking the server', async () => {
    answer({ '/dcim/assets/{id}/virtual-chassis': () => ({ data: { data: { virtual_chassis: VC, members: MEMBERS } } }) });
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('chassis-member')).toHaveLength(2));
    await act(async () => { setValue(byLabel<HTMLInputElement>('Member asset id')!, OTHER_ID); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Member position')!, '300'); });
    expect(button('Add member').disabled).toBe(true);
    expect(text()).toContain('whole numbers from 0 to 255');
  });

  it('installs a child asset in a device bay', async () => {
    answer({ '/dcim/assets/{id}/device-bays': () => page([DEVICE_BAY]) });
    mocks.patch.mockResolvedValue({ data: { data: { ...DEVICE_BAY, installed_asset_id: OTHER_ID } } });
    await mount(<HardwareTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('device-bay-row')).toHaveLength(1));
    await act(async () => { button('Install a child in Blade 1').click(); });
    await act(async () => { setValue(byLabel<HTMLInputElement>('Child asset id')!, OTHER_ID); });
    await act(async () => { button('Install').click(); });
    await vi.waitFor(() => expect(mocks.patch).toHaveBeenCalledWith('/dcim/device-bays/{id}', { params: { path: { id: 'db-1' } }, body: { installed_asset_id: OTHER_ID } }));
  });
});

describe('itemTree', () => {
  it('nests children under their parent and keeps an orphan at the top', () => {
    const tree = itemTree([FAN, PSU, item('i9', 'Lost', { parent_id: 'missing' })]);
    expect(tree.map((n) => `${n.depth}:${n.item.name}`)).toEqual(['0:Lost', '0:Switch 1 - Power Supply A', '1:Fan 1']);
  });
});

describe('asset page wiring', () => {
  it('Hardware is in the tab registry, right after Ports', () => {
    const keys = ASSET_TABS.map((t) => t.key);
    expect(keys.indexOf('hardware')).toBe(keys.indexOf('ports') + 1);
    expect(ASSET_TABS.find((t) => t.key === 'hardware')?.placeholder).toBeUndefined();
  });

  it('the tab is registered on the real asset page and shows the asset\'s hardware', async () => {
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/assets/{id}/module-bays': () => page([BAY_NM]),
      '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [] } }),
    });
    await mount(null, MANAGE, `/inventory/assets/${ASSET_ID}/hardware`);
    await vi.waitFor(() => expect(byTest('hardware-tab')).toHaveLength(1));
    await vi.waitFor(() => expect(byTest('module-bay')).toHaveLength(1));
    expect([...document.body.querySelectorAll('[role="tab"]')].some((t) => t.textContent === 'Hardware' && t.getAttribute('aria-selected') === 'true')).toBe(true);
  });
});
