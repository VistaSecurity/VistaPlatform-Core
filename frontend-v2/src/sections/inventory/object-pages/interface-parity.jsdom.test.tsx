// @vitest-environment jsdom
//
// DCIM gap 10 on the interface: the interface page's virtual circuit (shown,
// added with the interface fixed, removed) and VLAN translation policy, and
// the asset's Interfaces drawer's policy picker — over a faked inventory
// client and the REAL permission gate.
//
// Mutation: drop <VirtualCircuitSection> from InterfacePage → every
// virtual-circuit test fails; drop `vlan_translation_policy_id` from bodyOf →
// the drawer test's body lacks the policy.
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

import { InterfacePage } from './interface-page';
import { InterfacesTab } from '../dcim/interfaces-tab';
import { iface, ASSET, ASSET_ID } from '../cabling/cabling-test-kit';

const NOW = new Date().toISOString();
const base = {
  tenant_id: 't1', description: null, comments: null, source_kind: 'declared', source_ref: null,
  custom_fields: {}, external_ids: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const POLICY = { ...base, id: 'vp1', name: 'customer-a', rules: [], interface_count: 1 };
const IFACE = iface({ id: 'i1', name: 'xe-0/0/1', asset_id: ASSET_ID, vlan_translation_policy_id: 'vp1' });
const VC = { ...base, id: 'vc1', cid: 'VC-0007', provider_network_id: 'pn1', provider_account_id: null, type_id: 'vt1', operational_status: 'active', business_unit_id: null };
const TERM = { ...base, id: 'vct1', virtual_circuit_id: 'vc1', role: 'spoke', interface_id: 'i1', virtual_circuit_cid: 'VC-0007', interface_name: 'xe-0/0/1', asset_id: ASSET_ID, asset_name: 'sw-1' };
const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); document.body.innerHTML = ''; });

function answer(over: Record<string, () => unknown> = {}) {
  mocks.get.mockImplementation(async (path: string) => {
    if (over[path]) return over[path]();
    if (path === '/dcim/interfaces/{id}') return { data: { data: IFACE }, response: { status: 200 } };
    if (path === '/infrastructure-assets/{id}') return { data: { asset: ASSET } };
    if (path.endsWith('/trace')) return { data: { data: { object: { kind: 'interface', id: 'i1', name: 'xe-0/0/1', asset_id: null, asset_name: null, circuit_id: null }, paths: [] } } };
    if (path === '/ipam/vlan-translation-policies') return page([POLICY]);
    if (path === '/circuits/virtual-circuit-terminations') return page([TERM]);
    if (path === '/circuits/virtual-circuits') return page([VC]);
    if (path === '/dcim/assets/{id}/interfaces') return page([IFACE]);
    if (path === '/dcim/business-units') return { data: { business_units: [] } };
    return page([]);
  });
}
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 30)); });
async function settleUntil(ready: () => boolean) {
  for (let i = 0; i < 100 && !ready(); i++) await flush();
}
const ALL = ['dcim.read', 'dcim.manage', 'ipam.read', 'ipam.manage', 'circuits.read', 'circuits.manage'];

async function mount(ui: React.ReactNode, path: string, route: string, permissions = ALL) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes><Route path={route} element={ui} /></Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
  await flush();
}
const mountPage = (permissions = ALL) => mount(<InterfacePage />, '/inventory/interfaces/i1', '/inventory/interfaces/:id', permissions);
const q = (sel: string) => document.querySelector(sel);
const click = (el: Element | null) => act(async () => { (el as HTMLElement).click(); });
const setSelect = async (label: string, value: string) => {
  const sel = document.querySelector(`select[aria-label="${label}"]`) as HTMLSelectElement;
  await act(async () => { sel.value = value; sel.dispatchEvent(new Event('change', { bubbles: true })); });
};

describe('the interface page (DCIM gap 10)', () => {
  it('shows its virtual circuit and VLAN translation policy, each linked to its view (success)', async () => {
    answer();
    await mountPage();
    await settleUntil(() => !!q('[data-testid="interface-virtual-circuit-link"]') && !!q('[data-testid="interface-translation-policy"]'));
    expect(q('[data-testid="interface-virtual-circuit"]')?.textContent).toContain('Spoke');
    expect(q('[data-testid="interface-virtual-circuit-link"]')?.getAttribute('href')).toBe('/inventory?lens=circuits&view=virtual&vc=vc1');
    expect(q('[data-testid="interface-translation-policy"]')?.textContent).toBe('customer-a');
    expect(q('[data-testid="interface-translation-policy"]')?.getAttribute('href')).toBe('/inventory?lens=vlans&view=translation&policy=vp1');
    const call = mocks.get.mock.calls.find((c) => c[0] === '/circuits/virtual-circuit-terminations');
    expect((call?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ interface_id: 'i1' });
  });

  it('removes the interface from its virtual circuit', async () => {
    answer();
    mocks.del.mockResolvedValue({});
    await mountPage();
    await settleUntil(() => !!q('[data-testid="interface-virtual-circuit-remove"]'));
    await click(q('[data-testid="interface-virtual-circuit-remove"]'));
    await flush();
    expect(mocks.del).toHaveBeenCalledWith('/circuits/virtual-circuit-terminations/{id}', { params: { path: { id: 'vct1' } } });
  });

  it('with none, says so (empty) and adds the interface to a virtual circuit with itself fixed', async () => {
    answer({ '/circuits/virtual-circuit-terminations': () => page([]) });
    mocks.post.mockResolvedValue({ data: { data: TERM } });
    await mountPage();
    await settleUntil(() => !!q('[data-testid="interface-virtual-circuit-add"]'));
    expect(q('[data-testid="interface-virtual-circuit"]')?.textContent).toContain('terminates no virtual circuit');
    await click(q('[data-testid="interface-virtual-circuit-add"]'));
    await settleUntil(() => !!document.querySelector('select[aria-label="Virtual circuit"] option[value="vc1"]'));
    await setSelect('Virtual circuit', 'vc1');
    await setSelect('Role', 'hub');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/circuits/virtual-circuit-terminations');
    expect(init.body).toEqual({ interface_id: 'i1', virtual_circuit_id: 'vc1', role: 'hub' });
  });

  it('loading and error of the virtual circuit read', async () => {
    answer({ '/circuits/virtual-circuit-terminations': () => new Promise(() => {}) });
    await mountPage();
    await settleUntil(() => !!q('[data-testid="interface-virtual-circuit"]'));
    expect(q('[data-testid="interface-virtual-circuit"] [data-testid="substrate-loading"]')).not.toBeNull();
    act(() => root.unmount());
    root = createRoot(host);
    answer({ '/circuits/virtual-circuit-terminations': () => ({ error: { error: { code: 'x', message: 'terminations down' } } }) });
    await mountPage();
    await settleUntil(() => !!q('[data-testid="interface-virtual-circuit"] [data-testid="substrate-error"]'));
    expect(q('[data-testid="interface-virtual-circuit"]')?.textContent).toContain('terminations down');
  });

  it('without circuits.read it explains the permission, fetches nothing, and offers no add', async () => {
    answer({ '/circuits/virtual-circuit-terminations': () => page([]) });
    await mountPage(['dcim.read', 'ipam.read']);
    await settleUntil(() => !!q('[data-testid="interface-virtual-circuit"]'));
    expect(q('[data-testid="interface-virtual-circuit"]')?.textContent).toContain('circuits read permission');
    expect(mocks.get.mock.calls.some((c) => c[0] === '/circuits/virtual-circuit-terminations')).toBe(false);
    expect(q('[data-testid="interface-virtual-circuit-add"]')).toBeNull();
  });
});

describe('the Interfaces drawer\'s VLAN translation policy picker', () => {
  it('lists the tenant\'s policies and sends the one chosen', async () => {
    answer();
    mocks.patch.mockResolvedValue({ data: { data: IFACE } });
    await mount(<InterfacesTab asset={ASSET as never} />, '/', '/');
    await settleUntil(() => document.querySelectorAll('[data-testid="interface-row"]').length === 1);
    const open = [...document.querySelectorAll('button')].find((b) => b.getAttribute('aria-label') === 'Open xe-0/0/1') as HTMLButtonElement;
    await click(open);
    await settleUntil(() => document.querySelector('select[aria-label="VLAN translation policy"]') !== null);
    const sel = document.querySelector('select[aria-label="VLAN translation policy"]') as HTMLSelectElement;
    expect([...sel.options].map((o) => o.textContent)).toEqual(['None', 'customer-a']);
    expect(sel.value).toBe('vp1');
    await setSelect('VLAN translation policy', '');
    const save = [...document.querySelectorAll('[data-testid="interface-drawer"] button')].find((b) => b.textContent === 'Save') as HTMLButtonElement;
    await click(save);
    await flush();
    const [, init] = mocks.patch.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(init.body).toMatchObject({ vlan_translation_policy_id: null });
  });
});
