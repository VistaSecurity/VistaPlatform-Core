// @vitest-environment jsdom
//
// Inventory → Circuits and Settings → Circuit Providers (DCIM BUILD_PLAN row
// 4.1), mounted through the REAL InventoryPage / SettingsPage over a faked
// inventory client and the REAL permission gate: the lens registered and
// reachable, each surface in its five states (default, empty, loading, error,
// success), the circuit drawer with its A/Z terminations editor, and the write
// controls hidden from a read-only role.
//
// Mutation: drop the `circuits` entry from lenses.ts, or the `circuits` branch
// from InventoryPage → "is registered and reached through the real page" fails
// (the default lens renders instead); drop the `circuit-providers` case from
// SettingsPage → the settings test fails (the spec-pending page renders).
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
import { INVENTORY_LENSES, findLens } from '../lenses';
import { parseAsns } from '../../settings/pages-circuit-providers';
import { rateText } from './circuits-queries';

const NOW = new Date().toISOString();
const T = '00000000-0000-4000-8000-00000000000a';
const base = {
  tenant_id: T, description: null, comments: null, source_kind: 'declared', source_ref: null,
  custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const PROVIDER = { ...base, external_ids: {}, id: 'pv1', name: 'Lumen', slug: 'lumen', asns: [3356] };
const NETWORK = { ...base, external_ids: {}, id: 'pn1', provider_id: 'pv1', name: 'Lumen MPLS core', service_id: 'SVC-9' };
const TYPE_MPLS = { ...base, tenant_id: null, id: 'ct1', name: 'MPLS', slug: 'mpls', color: '9c27b0' };
const CIRCUIT = {
  ...base, external_ids: {}, id: 'c1', cid: 'CKT-0042', provider_id: 'pv1', provider_account_id: null, type_id: 'ct1',
  operational_status: 'active', business_unit_id: null, install_date: '2026-01-10', termination_date: null,
  commit_rate_kbps: 100000, distance: null, distance_unit: null,
  provider_name: 'Lumen', type_name: 'MPLS',
  terminations: [
    { id: 'tA', term_side: 'A', termination_kind: null, termination_id: null, termination_name: null, port_speed_kbps: 1000000 },
    { id: 'tZ', term_side: 'Z', termination_kind: 'provider_network', termination_id: 'pn1', termination_name: 'Lumen MPLS core', port_speed_kbps: 1000000 },
  ],
};
const TERM_Z = {
  ...base, id: 'tZ', circuit_id: 'c1', term_side: 'Z', termination_kind: 'provider_network', termination_id: 'pn1',
  port_speed_kbps: 1000000, upstream_speed_kbps: null, xconnect_id: 'XC-7', pp_info: null, mark_connected: false,
  cable_id: null, cable_end: null, termination_name: 'Lumen MPLS core',
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
  '/circuits/circuits': () => page([CIRCUIT]),
  '/circuits/providers': () => page([PROVIDER]),
  '/circuits/provider-networks': () => page([NETWORK]),
  '/circuits/circuit-types': () => page([TYPE_MPLS]),
  '/circuits/circuit-terminations': () => page([TERM_Z]),
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

describe('Inventory → Circuits', () => {
  it('is registered in the Assets group and reached through the real page (default)', async () => {
    const lens = INVENTORY_LENSES.find((l) => l.key === 'circuits');
    expect(lens).toMatchObject({ group: 'assets', live: true, anchor: 'circuit' });
    expect(findLens('circuits').key).toBe('circuits');
    answer(happy);
    await mount('/inventory?lens=circuits', MANAGE);
    expect(q('[data-testid="circuits-lens"]')).not.toBeNull();
    const row = q('[data-testid="circuit-row"]')?.textContent ?? '';
    expect(row).toContain('CKT-0042');
    expect(row).toContain('Lumen');
    expect(row).toContain('MPLS');
    expect(row).toContain('Active');
    expect(row).toContain('Not connected'); // A end
    expect(row).toContain('Lumen MPLS core'); // Z end
    expect(row).toContain('100 Mbps');
    expect(q('[data-testid="add-circuit"]')).not.toBeNull();
  });

  it('empty, loading and error states', async () => {
    answer({ ...happy, '/circuits/circuits': () => page([]) });
    await mount('/inventory?lens=circuits', MANAGE);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No circuits yet');
    answer({ ...happy, '/circuits/circuits': () => new Promise(() => {}) });
    await remount('/inventory?lens=circuits', MANAGE);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
    answer({ ...happy, '/circuits/circuits': () => ({ error: { error: { code: 'x', message: 'circuits unavailable' } } }) });
    await remount('/inventory?lens=circuits', MANAGE);
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('circuits unavailable');
  });

  it('opens a circuit with both ends and its change log', async () => {
    answer({ ...happy, '/dcim/changes': () => page([]) });
    await mount('/inventory?lens=circuits&circuit=c1', MANAGE);
    const drawer = q('[data-testid="circuit-drawer"]');
    expect(drawer?.textContent).toContain('CKT-0042');
    expect(q('[data-testid="termination-A"]')?.textContent).toContain('Not set');
    expect(q('[data-testid="termination-Z"]')?.textContent).toContain('Lumen MPLS core');
    expect(q('[data-testid="termination-Z"]')?.textContent).toContain('XC-7');
    const terms = mocks.get.mock.calls.find((c) => c[0] === '/circuits/circuit-terminations');
    expect((terms?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ circuit_id: 'c1' });
    const changes = mocks.get.mock.calls.find((c) => c[0] === '/dcim/changes');
    expect((changes?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ object_kind: 'circuit', object_id: 'c1' });
  });

  it('sets the A end onto a provider network (success)', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: { ...TERM_Z, id: 'tA', term_side: 'A' } } });
    await mount('/inventory?lens=circuits&circuit=c1', MANAGE);
    await click(q('[data-testid="termination-edit-A"]'));
    await setSelect('Lands on', 'pn1');
    await setInput('Port speed (kbps)', '10000000');
    await click(q('[data-testid="termination-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/circuits/circuit-terminations');
    expect(init.body).toMatchObject({ circuit_id: 'c1', term_side: 'A', termination_kind: 'provider_network', termination_id: 'pn1', port_speed_kbps: 10000000 });
    expect(q('[data-testid="termination-save"]')).toBeNull(); // the dialog closed
  });

  it('creates a circuit from the add dialog', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: CIRCUIT } });
    await mount('/inventory?lens=circuits', MANAGE);
    await click(q('[data-testid="add-circuit"]'));
    await setInput('Circuit ID', 'CKT-0099');
    await setSelect('Circuit Provider', 'pv1');
    await setSelect('Circuit Type', 'ct1');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/circuits/circuits');
    expect(init.body).toMatchObject({ cid: 'CKT-0099', provider_id: 'pv1', type_id: 'ct1', operational_status: 'active' });
  });

  it('adds the circuit to a circuit group', async () => {
    answer({ ...happy, '/circuits/circuit-groups': () => page([{ ...base, id: 'g1', name: 'HQ pair', slug: 'hq-pair' }]) });
    mocks.post.mockResolvedValue({ data: { data: { id: 'ga1', tenant_id: T, group_id: 'g1', circuit_id: 'c1', priority: 'primary', created_at: NOW, updated_at: NOW, created_by: null } } });
    await mount('/inventory?lens=circuits&circuit=c1', MANAGE);
    expect(q('[data-testid="circuit-groups"]')?.textContent).toContain('In no circuit group');
    await click(q('[data-testid="add-circuit-group"]'));
    await setSelect('Circuit Group', 'g1');
    await setSelect('Priority', 'primary');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/circuits/circuit-group-assignments');
    expect(init.body).toEqual({ circuit_id: 'c1', group_id: 'g1', priority: 'primary' });
  });

  it('hides every write control from a read-only role', async () => {
    answer(happy);
    await mount('/inventory?lens=circuits&circuit=c1', READ);
    expect(q('[data-testid="circuits-lens"]')).not.toBeNull();
    expect(q('[data-testid="add-circuit"]')).toBeNull();
    expect(q('[data-testid="circuit-edit"]')).toBeNull();
    expect(q('[data-testid="termination-edit-A"]')).toBeNull();
    expect(q('[data-testid="add-circuit-group"]')).toBeNull();
  });

  it('says rates as people do and never turns unknown into zero', () => {
    expect(rateText(100000)).toBe('100 Mbps');
    expect(rateText(10_000_000)).toBe('10 Gbps');
    expect(rateText(1500)).toBe('1.5 Mbps');
    expect(rateText(null)).toBe('—');
  });
});

describe('Settings → Circuit Providers', () => {
  it('is reached through the real settings page with every catalogue (success)', async () => {
    answer(happy);
    await mount('/inventory/manage/circuit-providers', MANAGE);
    expect(q('[data-testid="circuit-providers-settings"]')).not.toBeNull();
    for (const r of ['providers', 'provider-accounts', 'provider-networks', 'circuit-types', 'circuit-groups']) {
      expect(q(`[data-testid="circuit-catalog-${r}"]`)).not.toBeNull();
    }
    expect(q('[data-testid="circuit-catalog-providers"]')?.textContent).toContain('AS3356');
    expect(q('[data-testid="circuit-catalog-provider-networks"]')?.textContent).toContain('SVC-9');
    // A platform-seeded circuit type is listed as built in, with no controls.
    expect(q('[data-testid="circuit-catalog-circuit-types"]')?.textContent).toContain('Built in');
    expect(q('[data-testid="add-providers"]')).not.toBeNull();
  });

  it('shows empty catalogues as empty, errors as errors, and loading', async () => {
    answer({ ...happy, '/circuits/circuit-groups': () => page([]), '/circuits/provider-accounts': () => ({ error: { error: { code: 'x', message: 'no accounts' } } }) });
    await mount('/inventory/manage/circuit-providers', MANAGE);
    expect(q('[data-testid="circuit-catalog-circuit-groups"] [data-testid="substrate-empty"]')).not.toBeNull();
    expect(q('[data-testid="circuit-catalog-provider-accounts"] [data-testid="substrate-error"]')?.textContent).toContain('no accounts');
    answer({ ...happy, '/circuits/provider-networks': () => new Promise(() => {}) });
    await remount('/inventory/manage/circuit-providers', MANAGE);
    expect(q('[data-testid="circuit-catalog-provider-networks"] [data-testid="substrate-loading"]')).not.toBeNull();
  });

  it('creates a provider with its AS numbers', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: PROVIDER } });
    await mount('/inventory/manage/circuit-providers', MANAGE);
    await click(q('[data-testid="add-providers"]'));
    await setInput('Name', 'Zayo Group');
    await setInput('AS numbers', 'AS6461, 174');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/circuits/providers');
    expect(init.body).toMatchObject({ name: 'Zayo Group', asns: [6461, 174] });
    expect(parseAsns('')).toEqual([]);
  });

  it('is closed to a role without circuits.read, and read-only without circuits.manage', async () => {
    answer(happy);
    await mount('/inventory/manage/circuit-providers', []);
    expect(q('[data-testid="circuit-providers-settings"]')).toBeNull();
    await remount('/inventory/manage/circuit-providers', READ);
    expect(q('[data-testid="circuit-providers-settings"]')).not.toBeNull();
    expect(q('[data-testid="add-providers"]')).toBeNull();
  });
});
