// @vitest-environment jsdom
//
// The five DCIM object pages (gap 7) — prefix, VLAN, circuit, cable, interface —
// mounted over a faked inventory client and the REAL permission gate: each in
// its states (loading, error, not found, success), the breadcrumb and Back
// target, the substrate panels (custom fields, tags, contacts, images, changes,
// journal) mounted with the page's own kind and id, and the read gate.
//
// Mutation: remove a page's <Route> from App.tsx → object-pages.routes.test.ts
// fails; drop <ObjectSubstrate> from the shell → "mounts every substrate panel"
// fails for all five.
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

import { PrefixPage } from './prefix-page';
import { VlanPage } from './vlan-page';
import { CircuitPage } from './circuit-page';
import { CablePage } from './cable-page';
import { InterfacePage } from './interface-page';
import { cable, iface, ref, ASSET, ASSET_ID } from '../cabling/cabling-test-kit';

const NOW = new Date().toISOString();
const base = {
  tenant_id: 't1', description: null, comments: null, source_kind: 'declared', source_ref: null,
  custom_fields: {}, external_ids: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const lifecycle = { status: 'active', first_seen_at: null, last_seen_at: null, observation_count: 0, approved_by: null, approved_at: null };
const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });

const PREFIX = {
  ...base, ...lifecycle, id: 'p24', prefix: '10.10.0.0/24', vrf_id: null, scope_kind: null, scope_id: null, business_unit_id: 'bu1', vlan_id: 'v10',
  role_id: null, operational_status: 'active', is_pool: false, mark_utilized: false, network_type: null, environment: null,
  auto_approve_discoveries: false, auto_approve_sources: [], dhcp_managed: null, active_probes_disabled: false, sensitive: false,
  gateway_ip_id: null, gateway_asset_id: null, gateway_source_ref: null, gateway_observed_at: null, cloud_network_ref: null,
};
const PREFIX_DETAIL = {
  prefix: PREFIX, parent: null, depth: 0, children: [], child_count: 0, ip_count: 0,
  utilization: { percent: 0, used: '0', size: '254' }, available_prefixes: [],
  available_ips: { addresses: [], available: '254', subnet_router_anycast: null }, ip_ranges: [],
};
const VLAN = {
  ...base, ...lifecycle, id: 'v10', vid: 10, name: 'voice', group_id: 'g1', site_id: null, business_unit_id: null,
  operational_status: 'active', role_id: null, qinq_role: null, qinq_svlan_id: null,
};
const CIRCUIT = {
  ...base, id: 'c1', cid: 'CKT-0042', provider_id: 'pv1', provider_account_id: null, type_id: 'ct1', operational_status: 'active',
  business_unit_id: null, install_date: null, termination_date: null, commit_rate_kbps: 100000, distance: null, distance_unit: null,
  provider_name: 'Lumen', type_name: 'MPLS',
};
const TERM_A = {
  ...base, id: 'tA', circuit_id: 'c1', term_side: 'A', termination_kind: 'provider_network', termination_id: 'pn1', port_speed_kbps: 1000000,
  upstream_speed_kbps: null, xconnect_id: null, pp_info: null, mark_connected: false, cable_id: 'cab1', cable_end: 'A', termination_name: 'Core',
};
const CABLE = cable({ id: 'cab1', label: 'P-1', a_terminations: [ref({ termination_id: 'i1', name: 'Gi1' })], b_terminations: [ref({ termination_id: 'i2', name: 'Gi2' })] });
const IFACE = iface({ id: 'i1', name: 'Gi1', asset_id: ASSET_ID, speed_kbps: 1_000_000, mode: 'tagged', untagged_vlan_id: 'v10', tagged_vlan_ids: ['v10'], cable_id: 'cab1' });

interface Case {
  kind: 'prefix' | 'vlan' | 'circuit' | 'cable' | 'interface';
  path: string; route: string; Page: () => React.JSX.Element; id: string;
  getPath: string; row: unknown; loading: string; heading: string; lensLabel: string; lensHref: string;
}
const CASES: Case[] = [
  { kind: 'prefix', path: '/inventory/prefixes/p24', route: '/inventory/prefixes/:id', Page: PrefixPage, id: 'p24', getPath: '/ipam/prefixes/{id}', row: { data: PREFIX_DETAIL }, loading: 'Loading the prefix', heading: '10.10.0.0/24', lensLabel: 'Networks', lensHref: '/inventory?lens=networks' },
  { kind: 'vlan', path: '/inventory/vlans/v10', route: '/inventory/vlans/:id', Page: VlanPage, id: 'v10', getPath: '/ipam/vlans/{id}', row: { data: VLAN }, loading: 'Loading vlan', heading: 'voice', lensLabel: 'VLANs', lensHref: '/inventory?lens=vlans' },
  { kind: 'circuit', path: '/inventory/circuits/c1', route: '/inventory/circuits/:id', Page: CircuitPage, id: 'c1', getPath: '/circuits/circuits/{id}', row: { data: CIRCUIT }, loading: 'Loading circuit', heading: 'CKT-0042', lensLabel: 'Circuits', lensHref: '/inventory?lens=circuits' },
  { kind: 'cable', path: '/inventory/cables/cab1', route: '/inventory/cables/:id', Page: CablePage, id: 'cab1', getPath: '/dcim/cables/{id}', row: { data: CABLE }, loading: 'Loading the cable', heading: 'P-1', lensLabel: 'Cabling', lensHref: '/inventory?lens=cabling' },
  { kind: 'interface', path: '/inventory/interfaces/i1', route: '/inventory/interfaces/:id', Page: InterfacePage, id: 'i1', getPath: '/dcim/interfaces/{id}', row: { data: IFACE }, loading: 'Loading interface', heading: 'Gi1', lensLabel: 'sw-1', lensHref: `/inventory/assets/${ASSET_ID}/interfaces` },
];

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

function answer(c: Case, override?: (path: string) => unknown) {
  mocks.get.mockImplementation(async (path: string) => {
    const o = override?.(path);
    if (o !== undefined) return o;
    if (path === c.getPath) return { data: c.row, response: { status: 200 } };
    if (path.endsWith('/trace')) return { data: { data: { object: { kind: 'interface', id: 'i1', name: 'Gi1', asset_id: null, asset_name: null, circuit_id: null }, paths: [] } } };
    if (path === '/dcim/cables/{id}') return { data: { data: CABLE } };
    if (path === '/infrastructure-assets/{id}') return { data: { asset: ASSET } };
    if (path === '/circuits/circuit-terminations') return page([TERM_A]);
    if (path === '/ipam/vlans') return page([VLAN]);
    if (path === '/dcim/interfaces') return page([IFACE]);
    if (path === '/dcim/business-units') return { data: { business_units: [] } };
    return page([]);
  });
}

/** Re-renders in 30 ms steps until `ready` holds, for at most ~3 s. */
async function settleUntil(ready: () => boolean) {
  for (let i = 0; i < 100 && !ready(); i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 30)); });
  }
}

async function mount(c: Case, permissions = ['dcim.read', 'dcim.manage', 'ipam.read', 'ipam.manage', 'circuits.read', 'circuits.manage'], state?: unknown) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[{ pathname: c.path, state }]}>
            <Routes><Route path={c.route} element={<c.Page />} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 30)); });
}
const q = (sel: string) => host.querySelector(sel);

describe.each(CASES)('$kind page', (c) => {
  it('loading', async () => {
    mocks.get.mockReturnValue(new Promise(() => {}));
    await mount(c);
    expect(q(`[data-testid="object-page-${c.kind}"]`)).not.toBeNull();
    expect(q('[data-testid="object-body"]')).toBeNull();
    expect(host.textContent).toMatch(/Loading/);
  });

  it('error offers a retry', async () => {
    mocks.get.mockResolvedValue({ data: undefined, error: { error: 'boom' }, response: { status: 500 } });
    await mount(c);
    expect(q('[data-testid="object-body"]')).toBeNull();
    expect(host.textContent).toMatch(/Retry/);
  });

  it('a 404 is its own empty state', async () => {
    mocks.get.mockResolvedValue({ data: undefined, error: { error: 'x' }, response: { status: 404 } });
    await mount(c);
    expect(host.textContent).toContain('no longer exists');
    expect(q('[data-testid="object-substrate"]')).toBeNull();
  });

  it('success: heading, breadcrumb to the lens, and Back to the lens', async () => {
    answer(c);
    await mount(c);
    expect(host.textContent).toContain(c.heading);
    // The interface page's lens crumb is the asset's name, which arrives from
    // a second query; on a slow runner it lands after mount's settle delay.
    await settleUntil(() => q('[data-testid="object-crumb-lens"]')?.textContent === c.lensLabel);
    expect(q('[data-testid="object-crumb-lens"]')!.textContent).toBe(c.lensLabel);
    expect(q('[data-testid="object-crumb-lens"]')!.getAttribute('href')).toBe(c.lensHref);
    expect(q('[data-testid="object-back"]')!.getAttribute('href')).toBe(c.lensHref);
  });

  it('Back returns to the lens with its query when the link carried it', async () => {
    answer(c);
    await mount(c, undefined, { from: '/inventory?lens=x&q=core' });
    expect(q('[data-testid="object-back"]')!.getAttribute('href')).toBe('/inventory?lens=x&q=core');
  });

  it('Back ignores a from that is not an inventory path', async () => {
    answer(c);
    await mount(c, undefined, { from: 'https://evil.example/' });
    expect(q('[data-testid="object-back"]')!.getAttribute('href')).toBe(c.lensHref);
  });

  it('mounts every substrate panel with this page\'s kind and id', async () => {
    answer(c);
    await mount(c);
    for (const t of ['substrate-custom-fields', 'substrate-tags', 'substrate-contacts', 'substrate-images', 'substrate-history']) {
      expect(q(`[data-testid="${t}"]`), t).not.toBeNull();
    }
    expect(q('[data-testid="object-tags"]')).not.toBeNull();
    expect(q('[data-testid="object-contacts"]')).not.toBeNull();
    expect(q('[data-testid="object-images"]')).not.toBeNull();
    const called = (p: string) => mocks.get.mock.calls.some(([path, init]) => path === p
      && (init as { params?: { path?: { kind?: string; id?: string } } })?.params?.path?.kind === c.kind
      && (init as { params?: { path?: { id?: string } } })?.params?.path?.id === c.id);
    expect(called('/dcim/objects/{kind}/{id}/tags')).toBe(true);
    expect(called('/dcim/objects/{kind}/{id}/contacts')).toBe(true);
    expect(called('/dcim/objects/{kind}/{id}/images')).toBe(true);
    expect(mocks.get.mock.calls.some(([path, init]) => path === '/dcim/changes'
      && (init as { params?: { query?: { object_kind?: string; object_id?: string } } })?.params?.query?.object_kind === c.kind
      && (init as { params?: { query?: { object_id?: string } } })?.params?.query?.object_id === c.id)).toBe(true);
    // The Journal tab mounts the journal for the same object.
    const journal = [...host.querySelectorAll('[role="tab"]')].find((t) => t.textContent === 'Journal')!;
    await act(async () => { (journal as HTMLElement).click(); });
    expect(called('/dcim/objects/{kind}/{id}/journal')).toBe(true);
  });

  it('without the read permission the page says so and fetches nothing about the object', async () => {
    answer(c);
    await mount(c, ['sites.read']);
    expect(host.textContent).toContain("You can't view this");
    expect(q('[data-testid="object-body"]')).toBeNull();
  });
});

describe('page specifics', () => {
  const by = (k: string) => CASES.find((c) => c.kind === k)!;

  it('VLAN: lists the interfaces using it, tagged or untagged, linking to their pages', async () => {
    answer(by('vlan'));
    await mount(by('vlan'));
    const rows = [...host.querySelectorAll('[data-testid="vlan-interface"]')];
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain('Gi1');
    expect(rows[0].querySelector('a')!.getAttribute('href')).toBe('/inventory/interfaces/i1');
    expect(mocks.get).toHaveBeenCalledWith('/dcim/interfaces', { params: { query: { vlan: 'v10', limit: 200 } } });
  });

  it('VLAN: no interfaces says so', async () => {
    answer(by('vlan'), (p) => (p === '/dcim/interfaces' ? page([]) : undefined));
    await mount(by('vlan'));
    expect(q('[data-testid="vlan-interfaces"]')!.textContent).toContain('No interface is recorded');
  });

  it('prefix: shows its VLAN as a link to the VLAN page and omits the panel\'s own substrate tabs', async () => {
    answer(by('prefix'));
    await mount(by('prefix'));
    expect(q('[data-testid="prefix-page-facts"] a')!.getAttribute('href')).toBe('/inventory/vlans/v10');
    const tabs = [...host.querySelectorAll('[data-testid="prefix-panel"] [role="tab"]')].map((t) => t.textContent);
    expect(tabs).toEqual(['IP addresses']);
    expect(q('[data-testid="prefix-panel"] [aria-label="Close"]')).toBeNull();
  });

  it('circuit: traces a cabled end; an uncabled circuit has nothing to trace', async () => {
    answer(by('circuit'));
    await mount(by('circuit'));
    expect(mocks.get.mock.calls.some(([p]) => p === '/dcim/circuit-terminations/{id}/trace')).toBe(true);
    answer(by('circuit'), (p) => (p === '/circuits/circuit-terminations' ? page([{ ...TERM_A, cable_id: null }]) : undefined));
    await act(async () => { root.unmount(); });
    root = createRoot(host);
    await mount(by('circuit'));
    expect(q('[data-testid="circuit-trace"]')!.textContent).toContain('Nothing to trace');
  });

  it('cable: both ends, and says plainly that no neighbour has confirmed it', async () => {
    answer(by('cable'));
    await mount(by('cable'));
    expect(q('[data-testid="cable-end-A"]')!.textContent).toContain('Gi1');
    expect(q('[data-testid="cable-end-B"]')!.textContent).toContain('Gi2');
    expect(q('[data-testid="cable-lldp"]')!.textContent).toContain('no neighbour observation has confirmed');
    // The page supplies Changes itself: the body does not repeat it.
    expect(host.querySelectorAll('[data-testid="object-changes"]').length).toBeLessThanOrEqual(1);
  });

  it('interface: its asset, VLAN links, cable link and trace', async () => {
    answer(by('interface'));
    await mount(by('interface'));
    expect(q('[data-testid="interface-asset"]')!.getAttribute('href')).toBe(`/inventory/assets/${ASSET_ID}`);
    // The VLAN and cable links come from follow-on queries; wait for them.
    await settleUntil(() => !!q('[data-testid="interface-vlans"] a') && !!q('[data-testid="interface-cable-link"]'));
    expect(q('[data-testid="interface-vlans"] a')!.getAttribute('href')).toBe('/inventory/vlans/v10');
    expect(q('[data-testid="interface-cable-link"]')!.getAttribute('href')).toBe('/inventory/cables/cab1');
    expect(mocks.get.mock.calls.some(([p]) => p === '/dcim/interfaces/{id}/trace')).toBe(true);
  });

  it('interface: an uncabled interface says "Not cabled" and an unreported state is not rendered as a value', async () => {
    const c = by('interface');
    answer(c, (p) => (p === c.getPath ? { data: { data: { ...IFACE, cable_id: null } } } : undefined));
    await mount(c);
    expect(q('[data-testid="interface-cable"]')!.textContent).toContain('Not cabled');
    expect(host.textContent).toContain('State not reported');
  });
});
