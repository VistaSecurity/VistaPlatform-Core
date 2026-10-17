// @vitest-environment jsdom
//
// DCIM row 1.6: the tenant's networks are prefixes, so what Settings → Network
// Segments showed and edited — scan posture, DHCP posture, auto-approval, the
// gateway, the sensor that reaches the network, a claim on a learned range —
// lives on the prefix panel in Inventory → Networks. Driven through the REAL
// InventoryPage over a faked inventory client and the REAL permission gate.
//
// Mutations, each red: drop the Discovery section from PrefixPanel (gateway,
// FHRP and posture assertions); drop the `decode` application in
// IpamFormModal (the DHCP edit sends the string "false"); drop the claim's
// `source_kind: 'declared'` body (the claim test).
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

const NOW = new Date().toISOString();
const T = '00000000-0000-4000-8000-00000000000a';
const ROUTER = '00000000-0000-4000-8000-0000000000a1';
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

const detail = (p: ReturnType<typeof prefix>, extra: Record<string, unknown> = {}) => ({
  data: {
    prefix: p, parent: null, depth: 0, children: [], child_count: 0, ip_count: 0,
    utilization: { percent: 0, used: '0', size: '254' }, available_prefixes: [],
    available_ips: { addresses: [], available: '254', subnet_router_anycast: null }, ip_ranges: [],
    gateway: null, coverage: null, fhrp_groups: [], ...extra,
  },
});

const ROUTED = prefix('p1', '192.0.2.0/24', { network_type: 'private', environment: 'production', dhcp_managed: true, auto_approve_discoveries: true });
const LEARNED = prefix('p2', '198.51.100.0/24', { source_kind: 'measured', status: 'pending', network_type: 'public' });

function answer(p: ReturnType<typeof prefix>, extra: Record<string, unknown> = {}) {
  mocks.get.mockImplementation(async (path: string) => {
    if (path === '/ipam/prefixes/tree') return { data: { data: [{ prefix: p, depth: 0, children: [] }], total: 1 } };
    if (path === '/ipam/prefixes/{id}') return { data: detail(p, extra) };
    return { data: { data: [], pagination: { total: 0, limit: 200, offset: 0, next_offset: null } } };
  });
}

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

async function mount(path: string, permissions: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes><Route path="/inventory" element={<InventoryPage />} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await flush();
}
const q = (sel: string) => host.ownerDocument.querySelector(sel);
const click = (el: Element | null) => act(async () => { (el as HTMLElement).click(); });

describe('the prefix panel is the network (DCIM row 1.6)', () => {
  it('shows the gateway, the sensor that reaches it and the FHRP virtual address', async () => {
    answer(ROUTED, {
      gateway: { asset_id: ROUTER, display_name: 'edge-router', address: '192.0.2.1/24', observed_at: NOW },
      coverage: { sensor_id: '00000000-0000-4000-8000-0000000000d1', sensor_name: 'office-sensor' },
      fhrp_groups: [{ id: 'g1', protocol: 'vrrp3', group_id: 10, name: 'office', virtual_address: '192.0.2.254/24' }],
    });
    await mount('/inventory?lens=networks&prefix=p1', MANAGE);
    const gw = q('[data-testid="prefix-gateway"]');
    expect(gw?.textContent).toContain('edge-router');
    expect(gw?.querySelector('a')?.getAttribute('href')).toBe(`/inventory/assets/${ROUTER}`);
    expect(q('[data-testid="prefix-discovery"]')?.textContent).toContain('Sensor: office-sensor');
    expect(q('[data-testid="prefix-fhrp"]')?.textContent).toBe('VRRP 10 (192.0.2.254)');
    expect(q('[data-testid="prefix-dhcp"]')?.textContent).toBe('DHCP');
    expect(q('[data-testid="prefix-scan-posture"]')?.textContent).toContain('Declared');
    // A declared prefix has nothing to claim.
    expect(q('[data-testid="claim-prefix"]')).toBeNull();
  });

  it('says so when no gateway is recorded and no sensor reaches it', async () => {
    answer(ROUTED);
    await mount('/inventory?lens=networks&prefix=p1', MANAGE);
    expect(q('[data-testid="prefix-gateway"]')?.textContent).toBe('gateway not recorded');
    expect(q('[data-testid="prefix-discovery"] [data-testid="coverage-note"]')?.getAttribute('data-coverage')).toBe('none');
    expect(q('[data-testid="prefix-fhrp"]')).toBeNull();
  });

  it('edits the DHCP posture as a three-valued column (No → false, not the string)', async () => {
    answer(ROUTED);
    mocks.patch.mockResolvedValue({ data: { data: { ...ROUTED, dhcp_managed: false } } });
    await mount('/inventory?lens=networks&prefix=p1', MANAGE);
    await click(q('[data-testid="edit-prefix"]'));
    const select = q('select[aria-label="Addresses handed out by DHCP"]') as HTMLSelectElement;
    expect(select.value).toBe('true');
    await act(async () => { select.value = 'false'; select.dispatchEvent(new Event('change', { bubbles: true })); });
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [, init] = mocks.patch.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(init.body).toEqual({ dhcp_managed: false });
  });

  it('claims a learned prefix as the organization\'s: the source becomes declared', async () => {
    answer(LEARNED);
    mocks.patch.mockResolvedValue({ data: { data: { ...LEARNED, source_kind: 'declared' } } });
    await mount('/inventory?lens=networks&prefix=p2', MANAGE);
    expect(q('[data-testid="prefix-scan-posture"]')?.textContent).toContain('not treated as yours');
    await click(q('[data-testid="claim-prefix"]'));
    expect(q('[data-testid="claim-consequences"]')?.textContent).toContain("Do not claim a range you don't control");
    await click(q('[data-testid="claim-prefix-confirm"]'));
    await flush();
    const [, init] = mocks.patch.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(init.body).toEqual({ source_kind: 'declared' });
  });

  it('hides the claim from a read-only role', async () => {
    answer(LEARNED);
    await mount('/inventory?lens=networks&prefix=p2', ['ipam.read']);
    expect(q('[data-testid="claim-prefix"]')).toBeNull();
  });
});
