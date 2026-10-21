// @vitest-environment jsdom
//
// Inventory → Circuits → Virtual circuits (DCIM gap 10), mounted through the
// REAL InventoryPage and WorkspacePage over a faked inventory client and the
// REAL permission gate: the view reached by its toggle in the Circuits lens
// (not a lens of its own), its five states, the add dialog's body, the drawer
// with its interface terminations and their removal, the Circuit Providers
// page's Virtual Circuit Types section, and the write controls hidden from a
// read-only role.
//
// Mutation: drop the `virtual ? <VirtualCircuitsView />` branch from
// CircuitsLens → "is a view of the Circuits lens" fails (the physical table
// renders); drop <CatalogSection c={VC_TYPES} /> → the Circuit Providers
// test fails.
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
import { INVENTORY_LENSES } from '../lenses';

const NOW = new Date().toISOString();
const T = '00000000-0000-4000-8000-00000000000a';
const base = {
  tenant_id: T, description: null, comments: null, source_kind: 'declared', source_ref: null,
  custom_fields: {}, external_ids: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const PROVIDER = { ...base, id: 'pv1', name: 'Overlay Co', slug: 'overlay-co', asns: [] };
const NETWORK = { ...base, id: 'pn1', provider_id: 'pv1', name: 'Overlay core', service_id: null };
const VC_TYPE = { ...base, id: 'vt1', name: 'SD-WAN', slug: 'sd-wan', color: '00aa00' };
const VC = {
  ...base, id: 'vc1', cid: 'VC-0007', provider_network_id: 'pn1', provider_account_id: null, type_id: 'vt1',
  operational_status: 'planned', business_unit_id: null,
  provider_network_name: 'Overlay core', provider_id: 'pv1', provider_name: 'Overlay Co', type_name: 'SD-WAN',
  terminations: [{ id: 'vct1', role: 'hub', interface_id: 'if1', interface_name: 'wan0', asset_id: 'a1', asset_name: 'edge-1' }],
};
const TERM = {
  ...base, id: 'vct1', virtual_circuit_id: 'vc1', role: 'hub', interface_id: 'if1',
  virtual_circuit_cid: 'VC-0007', interface_name: 'wan0', asset_id: 'a1', asset_name: 'edge-1',
};

const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });
type Routes = Record<string, (init?: unknown) => unknown>;
function answer(routes: Routes) {
  mocks.get.mockImplementation(async (path: string, init?: unknown) => {
    const fn = routes[path];
    return fn ? fn(init) : page([]);
  });
}
const happy: Routes = {
  '/circuits/virtual-circuits': () => page([VC]),
  '/circuits/providers': () => page([PROVIDER]),
  '/circuits/provider-networks': () => page([NETWORK]),
  '/circuits/virtual-circuit-types': () => page([VC_TYPE]),
  '/circuits/virtual-circuit-terminations': () => page([TERM]),
};

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); document.body.innerHTML = ''; });

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 20)); });
const MANAGE = ['circuits.read', 'circuits.manage'];
const READ = ['circuits.read'];

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
async function remount(path: string, permissions: string[]) {
  act(() => root.unmount());
  root = createRoot(host);
  await mount(path, permissions);
}
const q = (sel: string) => document.querySelector(sel);
const click = (el: Element | null) => act(async () => { (el as HTMLElement).click(); });
const setInput = async (label: string, value: string) => {
  const input = document.querySelector(`input[aria-label="${label}"]`) as HTMLInputElement;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  await act(async () => { setter.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true })); });
};
const setSelect = async (label: string, value: string) => {
  const sel = document.querySelector(`select[aria-label="${label}"]`) as HTMLSelectElement;
  await act(async () => { sel.value = value; sel.dispatchEvent(new Event('change', { bubbles: true })); });
};

describe('Inventory → Circuits → Virtual circuits', () => {
  it('is a view of the Circuits lens, reached by its toggle (default)', async () => {
    expect(INVENTORY_LENSES.some((l) => String(l.key) === 'virtual-circuits')).toBe(false);
    answer(happy);
    await mount('/inventory?lens=circuits', MANAGE);
    expect(q('[data-testid="physical-circuits-view"]')).not.toBeNull();
    await click(q('[data-testid="circuits-view-virtual"]'));
    await flush();
    expect(q('[data-testid="virtual-circuits-view"]')).not.toBeNull();
    expect(q('[data-testid="physical-circuits-view"]')).toBeNull();
    const row = q('[data-testid="virtual-circuit-row"]')?.textContent ?? '';
    expect(row).toContain('VC-0007');
    expect(row).toContain('Overlay Co');
    expect(row).toContain('Overlay core');
    expect(row).toContain('SD-WAN');
    expect(row).toContain('Planned');
    expect(row).toContain('Hub on edge-1 wan0');
    expect(q('[data-testid="add-virtual-circuit"]')).not.toBeNull();
  });

  it('empty, loading and error states', async () => {
    answer({ ...happy, '/circuits/virtual-circuits': () => page([]) });
    await mount('/inventory?lens=circuits&view=virtual', MANAGE);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No virtual circuits yet');
    answer({ ...happy, '/circuits/virtual-circuits': () => new Promise(() => {}) });
    await remount('/inventory?lens=circuits&view=virtual', MANAGE);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
    answer({ ...happy, '/circuits/virtual-circuits': () => ({ error: { error: { code: 'x', message: 'virtual circuits unavailable' } } }) });
    await remount('/inventory?lens=circuits&view=virtual', MANAGE);
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('virtual circuits unavailable');
  });

  it('creates a virtual circuit on a provider network (success)', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: VC } });
    await mount('/inventory?lens=circuits&view=virtual', MANAGE);
    await click(q('[data-testid="add-virtual-circuit"]'));
    await setInput('Circuit ID', 'VC-0099');
    await setSelect('Provider Network', 'pn1');
    await setSelect('Virtual Circuit Type', 'vt1');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/circuits/virtual-circuits');
    expect(init.body).toMatchObject({ cid: 'VC-0099', provider_network_id: 'pn1', type_id: 'vt1', operational_status: 'active' });
  });

  it('opens a virtual circuit with its terminations, and removes one', async () => {
    answer({ ...happy, '/dcim/changes': () => page([]) });
    mocks.del.mockResolvedValue({});
    await mount('/inventory?lens=circuits&view=virtual&vc=vc1', MANAGE);
    expect(q('[data-testid="virtual-circuit-drawer"]')?.textContent).toContain('VC-0007');
    const terms = mocks.get.mock.calls.find((c) => c[0] === '/circuits/virtual-circuit-terminations');
    expect((terms?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ virtual_circuit_id: 'vc1' });
    const t = q('[data-testid="virtual-circuit-termination"]');
    expect(t?.textContent).toContain('Hub');
    expect(t?.querySelector('a')?.getAttribute('href')).toBe('/inventory/interfaces/if1');
    await click(q('[data-testid="virtual-circuit-termination-remove"]'));
    await flush();
    expect(mocks.del).toHaveBeenCalledWith('/circuits/virtual-circuit-terminations/{id}', { params: { path: { id: 'vct1' } } });
    const changes = mocks.get.mock.calls.find((c) => c[0] === '/dcim/changes');
    expect((changes?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ object_kind: 'virtual_circuit', object_id: 'vc1' });
  });

  it('hides every write control from a read-only role', async () => {
    answer(happy);
    await mount('/inventory?lens=circuits&view=virtual&vc=vc1', READ);
    expect(q('[data-testid="virtual-circuits-view"]')).not.toBeNull();
    expect(q('[data-testid="add-virtual-circuit"]')).toBeNull();
    expect(q('[data-testid="virtual-circuit-edit"]')).toBeNull();
    expect(q('[data-testid="virtual-circuit-termination-remove"]')).toBeNull();
  });
});

describe('Circuit Providers → Virtual Circuit Types', () => {
  it('lists the tenant\'s virtual circuit types and adds one', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: VC_TYPE } });
    await mount('/inventory/manage/circuit-providers', MANAGE);
    expect(q('[data-testid="circuit-catalog-virtual-circuit-types"]')?.textContent).toContain('SD-WAN');
    await click(q('[data-testid="add-virtual-circuit-types"]'));
    await setInput('Name', 'MPLS L3VPN');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/circuits/virtual-circuit-types');
    expect(init.body).toMatchObject({ name: 'MPLS L3VPN' });
  });

  it('empty and error', async () => {
    answer({ ...happy, '/circuits/virtual-circuit-types': () => page([]) });
    await mount('/inventory/manage/circuit-providers', MANAGE);
    expect(q('[data-testid="circuit-catalog-virtual-circuit-types"] [data-testid="substrate-empty"]')).not.toBeNull();
    answer({ ...happy, '/circuits/virtual-circuit-types': () => ({ error: { error: { code: 'x', message: 'no types' } } }) });
    await remount('/inventory/manage/circuit-providers', MANAGE);
    expect(q('[data-testid="circuit-catalog-virtual-circuit-types"] [data-testid="substrate-error"]')?.textContent).toContain('no types');
  });
});
