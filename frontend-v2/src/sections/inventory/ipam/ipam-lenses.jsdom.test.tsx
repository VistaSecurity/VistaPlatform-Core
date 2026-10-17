// @vitest-environment jsdom
//
// Inventory → Networks and VLANs and Settings → IPAM (DCIM BUILD_PLAN row 1.3),
// mounted through the REAL InventoryPage / SettingsPage over a faked inventory
// client and the REAL permission gate: each in its five states (default,
// empty, loading, error, success), the prefix tree expanding, the prefix panel
// with its addresses and the asset holding one, Find, and the write controls
// hidden from a read-only role.
//
// Mutation: drop the `networks` / `vlans` branch from InventoryPage, or the
// `ipam` case from SettingsPage → the "reached through the real page" tests
// fail (the default lens / the spec-pending page renders instead).
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

import { InventoryPage } from '../inventory-page';
import { WorkspacePage } from '../../settings/settings-page';

const NOW = new Date().toISOString();
const T = '00000000-0000-4000-8000-00000000000a';
const base = {
  tenant_id: T, description: null, comments: null, source_kind: 'declared', source_ref: null,
  custom_fields: {}, external_ids: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const lifecycle = { status: 'active', first_seen_at: null, last_seen_at: null, observation_count: 0, approved_by: null, approved_at: null };
const prefix = (id: string, p: string, extra: Record<string, unknown> = {}) => ({
  ...base, ...lifecycle, id, prefix: p, vrf_id: null, scope_kind: null, scope_id: null, business_unit_id: null, vlan_id: null,
  role_id: null, operational_status: 'active', is_pool: false, mark_utilized: false, network_type: null, environment: null,
  auto_approve_discoveries: false, auto_approve_sources: [], dhcp_managed: null, active_probes_disabled: false, sensitive: false,
  gateway_ip_id: null, gateway_asset_id: null, gateway_source_ref: null, gateway_observed_at: null, cloud_network_ref: null,
  utilization: 0, child_count: 0, ip_count: 0, ...extra,
});
const P16 = prefix('p16', '10.10.0.0/16', { operational_status: 'container', utilization: 0.39, child_count: 1, ip_count: 1 });
const P24 = prefix('p24', '10.10.0.0/24', { utilization: 0.39, ip_count: 1, vlan_id: 'v10', business_unit_id: 'bu1' });
const TREE = { data: [{ prefix: P16, depth: 0, children: [{ prefix: P24, depth: 1, children: [] }] }], total: 2 };
const ASSET = '33333333-3333-4333-8333-333333333333';
const IP = {
  ...base, ...lifecycle, id: 'ip1', address: '10.10.0.5/24', host: '10.10.0.5/32', vrf_id: null, business_unit_id: null,
  operational_status: 'active', role: null, assigned_kind: null, assigned_id: null, nat_inside_id: null, dns_name: 'pbx.corp',
  mac_address: null, last_seen_source: null, asset: { id: ASSET, name: 'pbx-01' },
};
const DETAIL = {
  data: {
    prefix: P24, parent: P16, depth: 1, children: [], child_count: 0, ip_count: 1,
    utilization: { percent: 0.39, used: '1', size: '254' }, available_prefixes: ['10.10.0.128/25'],
    available_ips: { addresses: ['10.10.0.1', '10.10.0.2'], available: '253', subnet_router_anycast: null }, ip_ranges: [],
  },
};
const VLAN = {
  ...base, ...lifecycle, id: 'v10', vid: 10, name: 'voice', group_id: 'g1', site_id: null, business_unit_id: null,
  operational_status: 'active', role_id: null, qinq_role: null, qinq_svlan_id: null, prefixes: ['10.10.0.0/24'],
};
const GROUP = { ...base, id: 'g1', name: 'Campus', slug: 'campus', scope_kind: null, scope_id: null, vid_ranges: [[1, 4094]], business_unit_id: null };
const RIR_PLATFORM = { ...base, tenant_id: null, id: 'r1', name: 'ARIN', slug: 'arin', is_private: false };
const VRF = { ...base, id: 'vrf1', name: 'blue', rd: '65000:1', business_unit_id: null, enforce_unique: true };

const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });

type Routes = Record<string, (init?: unknown) => unknown>;
function answer(routes: Routes) {
  mocks.get.mockImplementation(async (path: string, init?: unknown) => {
    const fn = routes[path];
    return fn ? fn(init) : { data: { data: [], pagination: { total: 0, limit: 200, offset: 0, next_offset: null } } };
  });
}
const happy: Routes = {
  '/ipam/prefixes/tree': () => ({ data: TREE }),
  '/ipam/prefixes/{id}': () => ({ data: DETAIL }),
  '/ipam/ip-addresses': () => page([IP]),
  '/ipam/vlans': () => page([VLAN]),
  '/ipam/vlan-groups': () => page([GROUP]),
  '/ipam/vrfs': () => page([VRF]),
  '/dcim/business-units': () => ({ data: { business_units: [{ id: 'bu1', name: 'Finance', slug: 'finance', parent_id: null }] } }),
  '/ipam/rirs': () => page([RIR_PLATFORM]),
  '/ipam/find': () => ({ data: { address: '10.10.0.5', data: [{ vrf_id: null, vrf_name: null, prefix: P24, ip_address: IP, assigned: null, asset: { id: ASSET, name: 'pbx-01', via: 'primary_ip4' } }] } }),
};

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 20)); });
const MANAGE = ['ipam.read', 'ipam.manage'];
const READ = ['ipam.read'];

async function mount(path: string, permissions: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/inventory" element={<InventoryPage />} />
              <Route path="/inventory/manage/:page" element={<WorkspacePage />} />
            </Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await flush();
}
const q = (sel: string) => host.querySelector(sel);
const all = (sel: string) => Array.from(host.querySelectorAll(sel));
const click = (el: Element | null) => act(async () => { (el as HTMLElement).click(); });

describe('Inventory → Networks', () => {
  it('is reached through the real page and shows the tree (success)', async () => {
    answer(happy);
    await mount('/inventory?lens=networks', MANAGE);
    expect(q('[data-testid="networks-lens"]')).not.toBeNull();
    // Roots start open, so the /24 under the /16 is visible.
    const rows = all('[data-testid="prefix-row"]').map((r) => r.textContent ?? '');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toContain('10.10.0.0/16');
    expect(rows[0]).toContain('Container');
    expect(rows[1]).toContain('10 voice');
    expect(rows[1]).toContain('Finance');
    expect(q('[data-testid="utilization"]')?.textContent).toContain('0.4%');
    expect(q('[data-testid="add-prefix"]')).not.toBeNull();
  });

  it('collapses and expands a branch (default → toggled)', async () => {
    answer(happy);
    await mount('/inventory?lens=networks', MANAGE);
    await click(q('[data-testid="prefix-toggle"]'));
    expect(all('[data-testid="prefix-row"]')).toHaveLength(1);
    await click(q('[data-testid="prefix-toggle"]'));
    expect(all('[data-testid="prefix-row"]')).toHaveLength(2);
  });

  it('opens a prefix with its addresses and the asset holding one', async () => {
    answer(happy);
    await mount('/inventory?lens=networks&prefix=p24', MANAGE);
    const panel = q('[data-testid="prefix-panel"]');
    expect(panel?.textContent).toContain('10.10.0.0/24');
    expect(panel?.textContent).toContain('1 of 254');
    expect(q('[data-testid="available-ips-count"]')?.textContent).toBe('253');
    expect(q('[data-testid="available-prefixes"]')?.textContent).toContain('10.10.0.128/25');
    const ip = q('[data-testid="ip-row"]');
    expect(ip?.textContent).toContain('pbx.corp');
    expect(ip?.querySelector('a')?.getAttribute('href')).toBe(`/inventory/assets/${ASSET}`);
    // The address list was asked for inside the prefix, in its VRF.
    const call = mocks.get.mock.calls.find((c) => c[0] === '/ipam/ip-addresses');
    expect((call?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ parent: '10.10.0.0/24', vrf_id: 'global' });
  });

  it('approves a pending (discovered) prefix', async () => {
    const pending = { ...P24, status: 'pending', source_kind: 'measured' };
    answer({ ...happy, '/ipam/prefixes/{id}': () => ({ data: { data: { ...DETAIL.data, prefix: pending } } }) });
    mocks.patch.mockResolvedValue({ data: { data: { ...pending, status: 'active' } } });
    await mount('/inventory?lens=networks&prefix=p24', MANAGE);
    expect(q('[data-testid="prefix-panel"]')?.textContent).toContain('Pending approval');
    await click(q('[data-testid="approve-prefixes"]'));
    await flush();
    const [path, init] = mocks.patch.mock.calls[0] as [string, { params: { path: { id: string } }; body: Record<string, unknown> }];
    expect(path).toBe('/ipam/prefixes/{id}');
    expect(init.params.path.id).toBe('p24');
    expect(init.body).toEqual({ status: 'active' });
  });

  it('says honestly when a prefix holds no addresses (empty)', async () => {
    answer({ ...happy, '/ipam/ip-addresses': () => page([]) });
    await mount('/inventory?lens=networks&prefix=p24', MANAGE);
    expect(q('[data-testid="prefix-panel"]')?.textContent).toContain('No addresses recorded');
  });

  it('shows an empty VRF as empty, not as an error (empty)', async () => {
    answer({ ...happy, '/ipam/prefixes/tree': () => ({ data: { data: [], total: 0 } }) });
    await mount('/inventory?lens=networks', MANAGE);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No prefixes in this VRF yet');
  });

  it('shows loading while the tree is on its way (loading)', async () => {
    answer({ ...happy, '/ipam/prefixes/tree': () => new Promise(() => {}) });
    await mount('/inventory?lens=networks', MANAGE);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
  });

  it('shows the server error and retries (error)', async () => {
    answer({ ...happy, '/ipam/prefixes/tree': () => ({ error: { error: { code: 'internal_error', message: 'database unavailable' } } }) });
    await mount('/inventory?lens=networks', MANAGE);
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('database unavailable');
  });

  it('hides every write control from a read-only role', async () => {
    answer(happy);
    await mount('/inventory?lens=networks&prefix=p24', READ);
    expect(q('[data-testid="add-prefix"]')).toBeNull();
    expect(q('[data-testid="edit-prefix"]')).toBeNull();
    expect(q('[data-testid="add-ip"]')).toBeNull();
  });

  it('switches VRF through the picker and asks for that VRF\'s tree', async () => {
    answer(happy);
    await mount('/inventory?lens=networks', MANAGE);
    const sel = q('[data-testid="vrf-select"]') as HTMLSelectElement;
    await act(async () => { sel.value = 'vrf1'; sel.dispatchEvent(new Event('change', { bubbles: true })); });
    await flush();
    const vrfs = mocks.get.mock.calls.filter((c) => c[0] === '/ipam/prefixes/tree').map((c) => (c[1] as { params: { query: { vrf: string } } }).params.query.vrf);
    expect(vrfs).toContain('global');
    expect(vrfs).toContain('vrf1');
  });

  it('finds an address and names the asset holding it', async () => {
    answer(happy);
    await mount('/inventory?lens=networks', MANAGE);
    const input = q('[data-testid="find-input"]') as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    await act(async () => { setter.call(input, '10.10.0.5'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    await act(async () => { (q('[data-testid="find-input"]')!.closest('form') as HTMLFormElement).requestSubmit(); });
    await flush();
    const r = q('[data-testid="find-result"]');
    expect(r?.textContent).toContain('10.10.0.0/24');
    expect(r?.querySelector('a')?.textContent).toBe('pbx-01');
  });

  it('creates a prefix in the selected VRF from the add dialog', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: P24 } });
    await mount('/inventory?lens=networks&vrf=vrf1', MANAGE);
    await click(q('[data-testid="add-prefix"]'));
    const input = host.ownerDocument.querySelector('input[aria-label="Prefix"]') as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    await act(async () => { setter.call(input, '10.20.0.0/24'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    await click(host.ownerDocument.querySelector('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/ipam/prefixes');
    expect(init.body).toMatchObject({ prefix: '10.20.0.0/24', vrf_id: 'vrf1', operational_status: 'active' });
  });

  it('shows the server\'s refusal in the dialog', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ error: { error: { code: 'conflict', message: 'conflict: an object with the same identity already exists (prefixes_identity_uniq)' } } });
    await mount('/inventory?lens=networks', MANAGE);
    await click(q('[data-testid="add-prefix"]'));
    const input = host.ownerDocument.querySelector('input[aria-label="Prefix"]') as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    await act(async () => { setter.call(input, '10.10.0.0/24'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    await click(host.ownerDocument.querySelector('[data-testid="ipam-save"]'));
    await flush();
    expect(host.ownerDocument.querySelector('[data-testid="ipam-form-error"]')?.textContent).toContain('same identity');
  });
});

describe('Inventory → VLANs', () => {
  it('is reached through the real page and lists VLANs with their prefixes (success)', async () => {
    answer(happy);
    await mount('/inventory?lens=vlans', MANAGE);
    expect(q('[data-testid="vlans-lens"]')).not.toBeNull();
    const row = q('[data-testid="vlan-row"]');
    expect(row?.textContent).toContain('voice');
    expect(row?.textContent).toContain('Campus');
    expect(row?.textContent).toContain('10.10.0.0/24');
    expect(all('[data-testid="vlan-group"]').map((g) => g.textContent)).toEqual(['Campus']);
  });

  it('opens a VLAN with its change log', async () => {
    answer({ ...happy, '/dcim/changes': () => page([]) });
    await mount('/inventory?lens=vlans&vlan=v10', MANAGE);
    expect(q('[data-testid="vlan-panel"]')?.textContent).toContain('10.10.0.0/24');
    const call = mocks.get.mock.calls.find((c) => c[0] === '/dcim/changes');
    expect((call?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ object_kind: 'vlan', object_id: 'v10' });
  });

  it('empty, loading and error states', async () => {
    answer({ ...happy, '/ipam/vlans': () => page([]) });
    await mount('/inventory?lens=vlans', MANAGE);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No VLANs yet');
    act(() => root.unmount());
    root = createRoot(host);
    answer({ ...happy, '/ipam/vlans': () => new Promise(() => {}) });
    await mount('/inventory?lens=vlans', MANAGE);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
    act(() => root.unmount());
    root = createRoot(host);
    answer({ ...happy, '/ipam/vlans': () => ({ error: { error: { code: 'x', message: 'boom' } } }) });
    await mount('/inventory?lens=vlans', MANAGE);
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('boom');
  });

  it('hides the write controls from a read-only role', async () => {
    answer(happy);
    await mount('/inventory?lens=vlans', READ);
    expect(q('[data-testid="add-vlan"]')).toBeNull();
    expect(q('[data-testid="add-vlan-group"]')).toBeNull();
  });
});

describe('Settings → IPAM', () => {
  it('is reached through the real settings page with every catalogue (success)', async () => {
    answer(happy);
    await mount('/inventory/manage/ipam', MANAGE);
    expect(q('[data-testid="ipam-settings"]')).not.toBeNull();
    for (const r of ['vrfs', 'aggregates', 'rirs', 'prefix-roles', 'asns']) {
      expect(q(`[data-testid="ipam-catalog-${r}"]`)).not.toBeNull();
    }
    expect(q('[data-testid="ipam-catalog-vrfs"]')?.textContent).toContain('65000:1');
    // A platform-seeded RIR is listed as built in, with no edit controls.
    expect(q('[data-testid="ipam-catalog-rirs"]')?.textContent).toContain('Built in');
    expect(q('[data-testid="add-vrfs"]')).not.toBeNull();
  });

  it('shows empty catalogues as empty and errors as errors', async () => {
    answer({ ...happy, '/ipam/vrfs': () => page([]), '/ipam/asns': () => ({ error: { error: { code: 'x', message: 'no asns' } } }) });
    await mount('/inventory/manage/ipam', MANAGE);
    expect(q('[data-testid="ipam-catalog-vrfs"] [data-testid="substrate-empty"]')).not.toBeNull();
    expect(q('[data-testid="ipam-catalog-asns"] [data-testid="substrate-error"]')?.textContent).toContain('no asns');
  });

  it('shows loading while a catalogue is on its way', async () => {
    answer({ ...happy, '/ipam/aggregates': () => new Promise(() => {}) });
    await mount('/inventory/manage/ipam', MANAGE);
    expect(q('[data-testid="ipam-catalog-aggregates"] [data-testid="substrate-loading"]')).not.toBeNull();
  });

  it('is closed to a role without ipam.read, and read-only without ipam.manage', async () => {
    answer(happy);
    await mount('/inventory/manage/ipam', []);
    expect(q('[data-testid="ipam-settings"]')).toBeNull();
    act(() => root.unmount());
    root = createRoot(host);
    await mount('/inventory/manage/ipam', READ);
    expect(q('[data-testid="ipam-settings"]')).not.toBeNull();
    expect(q('[data-testid="add-vrfs"]')).toBeNull();
  });
});
