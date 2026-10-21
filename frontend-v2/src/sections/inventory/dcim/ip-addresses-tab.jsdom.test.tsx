// @vitest-environment jsdom
//
// The asset page's IP Addresses tab (DCIM gap 2): default, both empty states,
// loading, error, the Primary / OOB badges, the set-as-primary / set-as-OOB
// requests (IPv4 -> primary_ip4_id, IPv6 -> primary_ip6_id), the permission
// gates, the row opening the address, and the tab's registration on the asset
// page (mounted through the REAL AssetPage route, so removing the tab from the
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
import { ASSET_TABS } from '../asset-tabs';
import { IpAddressesTab, roleFlags, sourceText } from './ip-addresses-tab';
import type { IpAddress } from '../ipam/ipam-queries';

const ASSET_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_ID = '22222222-2222-4222-8222-222222222222';
const IFACE_ID = '33333333-3333-4333-8333-333333333333';
const NOW = new Date().toISOString();
const ASSET = { id: ASSET_ID, hostname: 'sw-1.example.test', display_name: 'sw-1.example.test', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };

function ip(over: Partial<IpAddress> & { address: string }): IpAddress {
  return {
    id: 'ip-' + over.address, tenant_id: 't', host: null, identity_scope: null, address_assignment: null, device_confirmed_at: null,
    identity_confidence: null, vrf_id: null, business_unit_id: null, operational_status: 'active', role: null,
    assigned_kind: 'interface', assigned_id: IFACE_ID, nat_inside_id: null, dns_name: null, mac_address: null,
    last_seen_source: 'agent', external_ids: {}, status: 'active', first_seen_at: NOW, last_seen_at: NOW, observation_count: 1,
    approved_by: null, approved_at: null, description: null, comments: null, source_kind: 'measured', source_ref: null,
    custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null,
    asset: { id: ASSET_ID, name: 'sw-1', is_primary_ip4: false, is_primary_ip6: false, is_oob_ip: false },
    ...over,
  };
}

const V4 = ip({ address: '10.0.0.5/24', dns_name: 'sw-1.example.test', asset: { id: ASSET_ID, name: 'sw-1', is_primary_ip4: true, is_primary_ip6: false, is_oob_ip: false } });
const V6 = ip({ address: '2001:db8::5/64', source_kind: 'declared', last_seen_source: 'declared' });
const OOB = ip({ address: '192.0.2.9/24', assigned_kind: null, assigned_id: null, asset: { id: ASSET_ID, name: 'sw-1', is_primary_ip4: false, is_primary_ip6: false, is_oob_ip: true } });

const list = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 500, offset: 0, next_offset: null } } });
const iface = { id: IFACE_ID, asset_id: ASSET_ID, name: 'Vlan10' };

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

function answer(routes: Record<string, () => unknown>) {
  mocks.get.mockImplementation(async (path: string) => (routes[path] ? routes[path]() : { data: {} }));
}
const NORMAL = (ips: unknown[], ifaces: unknown[] = [iface]) => ({
  '/ipam/ip-addresses': () => list(ips),
  '/ipam/vrfs': () => list([]),
  '/dcim/assets/{id}/interfaces': () => list(ifaces),
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

const READ = ['ipam.read'];
const MANAGE = ['ipam.read', 'ipam.manage'];
const text = () => document.body.textContent ?? '';
const byTest = (id: string) => document.body.querySelectorAll(`[data-testid="${id}"]`);
const click = (el: Element) => act(async () => { (el as HTMLElement).click(); });

describe('<IpAddressesTab> states', () => {
  it('default: one row per address with VRF, interface link, role, status, DNS, source, and the Primary / OOB badges', async () => {
    answer(NORMAL([V4, V6, OOB]));
    await mount(<IpAddressesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('ip-address-row')).toHaveLength(3));
    expect(text()).toContain('10.0.0.5/24');
    expect(text()).toContain('sw-1.example.test');
    expect(text()).toContain('Global');
    expect(text()).toContain('Measured · agent');
    expect(text()).toContain('Declared');
    expect(byTest('primary-badge')).toHaveLength(1);
    expect(byTest('oob-badge')).toHaveLength(1);
    const link = byTest('ip-interface-link')[0] as HTMLAnchorElement;
    expect(link.textContent).toBe('Vlan10');
    expect(link.getAttribute('href')).toBe(`/inventory/assets/${ASSET_ID}/interfaces`);
    expect(mocks.get).toHaveBeenCalledWith('/ipam/ip-addresses', expect.objectContaining({ params: { query: { limit: 500, asset_id: ASSET_ID } } }));
  });

  it('empty with no interfaces: says the asset has not been interrogated, not that it has no addresses', async () => {
    answer(NORMAL([], []));
    await mount(<IpAddressesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No interfaces recorded'));
    expect(text()).toContain('says nothing about whether it has addresses');
    expect(byTest('ip-addresses-table')).toHaveLength(0);
  });

  it('empty with interfaces present: says no address is assigned', async () => {
    answer(NORMAL([], [iface]));
    await mount(<IpAddressesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No IP addresses'));
    expect(text()).toContain('no address is assigned');
    expect(text()).not.toContain('No interfaces recorded');
  });

  it('loading: a spinner label, no table', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<IpAddressesTab asset={ASSET as never} />, READ);
    expect(text()).toContain('Loading IP addresses');
    expect(byTest('ip-addresses-table')).toHaveLength(0);
  });

  it('error: the server reason and a retry, never an empty table', async () => {
    answer({ ...NORMAL([]), '/ipam/ip-addresses': () => ({ error: { error: { message: 'database is down' } } }) });
    await mount(<IpAddressesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(text()).toContain('database is down'));
    expect(byTest('ip-addresses-table')).toHaveLength(0);
  });
});

describe('<IpAddressesTab> actions', () => {
  it('Set as primary sends primary_ip4_id for IPv4 and primary_ip6_id for IPv6; Set as OOB sends oob_ip_id', async () => {
    mocks.patch.mockResolvedValue({ data: { data: {} } });
    answer(NORMAL([V6, OOB]));
    await mount(<IpAddressesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('ip-address-row')).toHaveLength(2));
    const rows = [...byTest('ip-address-row')];
    const v6row = rows.find((r) => r.textContent?.includes('2001:db8'))!;
    const v4row = rows.find((r) => r.textContent?.includes('192.0.2.9'))!;
    await click(v6row.querySelector('[data-testid="set-primary"]')!);
    expect(mocks.patch).toHaveBeenLastCalledWith('/dcim/assets/{id}/primary-ips', { params: { path: { id: ASSET_ID } }, body: { primary_ip6_id: V6.id } });
    await click(v4row.querySelector('[data-testid="set-primary"]')!);
    expect(mocks.patch).toHaveBeenLastCalledWith('/dcim/assets/{id}/primary-ips', { params: { path: { id: ASSET_ID } }, body: { primary_ip4_id: OOB.id } });
    await click(v6row.querySelector('[data-testid="set-oob"]')!);
    expect(mocks.patch).toHaveBeenLastCalledWith('/dcim/assets/{id}/primary-ips', { params: { path: { id: ASSET_ID } }, body: { oob_ip_id: V6.id } });
  });

  it('an address that is already primary / OOB offers to unset it, sending null', async () => {
    mocks.patch.mockResolvedValue({ data: { data: {} } });
    answer(NORMAL([V4, OOB]));
    await mount(<IpAddressesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('ip-address-row')).toHaveLength(2));
    const rows = [...byTest('ip-address-row')];
    await click(rows.find((r) => r.textContent?.includes('10.0.0.5'))!.querySelector('[data-testid="set-primary"]')!);
    expect(mocks.patch).toHaveBeenLastCalledWith('/dcim/assets/{id}/primary-ips', { params: { path: { id: ASSET_ID } }, body: { primary_ip4_id: null } });
    await click(rows.find((r) => r.textContent?.includes('192.0.2.9'))!.querySelector('[data-testid="set-oob"]')!);
    expect(mocks.patch).toHaveBeenLastCalledWith('/dcim/assets/{id}/primary-ips', { params: { path: { id: ASSET_ID } }, body: { oob_ip_id: null } });
  });

  it('a server refusal is shown, not swallowed', async () => {
    const toast = (await import('react-hot-toast')).default as unknown as { error: ReturnType<typeof vi.fn> };
    mocks.patch.mockResolvedValue({ error: { error: { message: 'primary_ip4_id takes an IPv4 address' } } });
    answer(NORMAL([V4]));
    await mount(<IpAddressesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('ip-address-row')).toHaveLength(1));
    await click(byTest('set-oob')[0]);
    await vi.waitFor(() => expect(toast.error).toHaveBeenCalledWith('primary_ip4_id takes an IPv4 address'));
  });

  it('ipam.read alone: rows and badges, but no write actions; an archived asset hides them too', async () => {
    answer(NORMAL([V4]));
    await mount(<IpAddressesTab asset={ASSET as never} />, READ);
    await vi.waitFor(() => expect(byTest('ip-address-row')).toHaveLength(1));
    expect(byTest('set-primary')).toHaveLength(0);
    expect(byTest('set-oob')).toHaveLength(0);
    act(() => root.unmount());
    root = createRoot(host);
    await mount(<IpAddressesTab asset={{ ...ASSET, asset_status: 'archived' } as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('ip-address-row')).toHaveLength(1));
    expect(byTest('set-primary')).toHaveLength(0);
  });

  it('no ipam.read: a lock notice and no request for addresses', async () => {
    answer(NORMAL([V4]));
    await mount(<IpAddressesTab asset={ASSET as never} />, ['dcim.read']);
    expect(text()).toContain("You can't view IP addresses");
    expect(mocks.get).not.toHaveBeenCalledWith('/ipam/ip-addresses', expect.anything());
  });

  it('a row opens the address drawer with its details and change record', async () => {
    answer({ ...NORMAL([V4]), '/dcim/changes': () => list([]) });
    await mount(<IpAddressesTab asset={ASSET as never} />, MANAGE);
    await vi.waitFor(() => expect(byTest('ip-address-row')).toHaveLength(1));
    await click(byTest('ip-address-row')[0]);
    await vi.waitFor(() => expect(byTest('ip-address-drawer')).toHaveLength(1));
    expect(byTest('ip-address-drawer')[0].textContent).toContain('Primary');
    expect(byTest('ip-address-drawer')[0].textContent).toContain('Changes');
  });
});

describe('role flags and source text', () => {
  it('flags only count for the asset that holds the address, and per family', () => {
    expect(roleFlags(V4, ASSET_ID)).toEqual({ primary: true, oob: false });
    expect(roleFlags(V4, OTHER_ID)).toEqual({ primary: false, oob: false });
    expect(roleFlags(ip({ address: '2001:db8::1/64', asset: { id: ASSET_ID, name: 'x', is_primary_ip4: true, is_primary_ip6: false, is_oob_ip: false } }), ASSET_ID).primary).toBe(false);
    expect(roleFlags(ip({ address: '10.0.0.1/24', asset: null }), ASSET_ID)).toEqual({ primary: false, oob: false });
  });
  it('source text names who saw it, except for a declared address', () => {
    expect(sourceText({ source_kind: 'measured', last_seen_source: 'arp' })).toBe('Measured · ARP');
    expect(sourceText({ source_kind: 'declared', last_seen_source: 'declared' })).toBe('Declared');
    expect(sourceText({ source_kind: 'imported', last_seen_source: null })).toBe('Imported');
  });
});

describe('registration on the asset page', () => {
  it('the tab sits between Interfaces and Ports and the REAL asset page renders it', async () => {
    const keys = ASSET_TABS.map((t) => t.key);
    expect(keys.indexOf('ip-addresses')).toBe(keys.indexOf('interfaces') + 1);
    expect(keys.indexOf('ports')).toBe(keys.indexOf('ip-addresses') + 1);
    answer({
      ...NORMAL([V4]),
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [] } }),
    });
    await mount(null, MANAGE, `/inventory/assets/${ASSET_ID}/ip-addresses`);
    await vi.waitFor(() => expect(byTest('ip-addresses-table')).toHaveLength(1));
    expect([...document.body.querySelectorAll('[role="tab"]')].some((t) => t.textContent === 'IP Addresses' && t.getAttribute('aria-selected') === 'true')).toBe(true);
  });
});
