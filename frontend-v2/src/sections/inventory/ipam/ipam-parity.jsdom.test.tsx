// @vitest-environment jsdom
//
// DCIM gap 10's IPAM surfaces, mounted through the REAL InventoryPage and
// WorkspacePage over a faked inventory client and the REAL permission gate:
//   - Inventory → VLANs → Translation policies: a view of the VLANs lens
//     reached by its toggle, its five states, a policy opened onto its rules,
//     the add-policy and add-rule bodies, the read-only role;
//   - Infrastructure → IPAM workspace → ASN ranges, beside ASNs: the list with
//     how many numbers are in use and free, the free numbers on request, the
//     add body, empty / error / loading.
//
// Mutation: drop the `if (translation)` branch from VlansLens → "is a view of
// the VLANs lens" fails; drop <CatalogSection c={ASN_RANGES} /> → the ASN
// ranges tests fail; drop the useAvailableAsns call in FreeAsns → the free
// list never renders.
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
const POLICY = {
  ...base, id: 'vp1', name: 'customer-a', description: 'C-VLAN rewrite',
  rules: [{ id: 'vr1', local_vid: 100, remote_vid: 2100, description: null }], interface_count: 2,
};
const RULE = { ...base, id: 'vr1', policy_id: 'vp1', local_vid: 100, remote_vid: 2100 };
const RIR = { ...base, tenant_id: null, id: 'r1', name: 'RFC 6996', slug: 'rfc-6996', is_private: true };
const RANGE = {
  ...base, id: 'ar1', name: 'Private 16-bit', slug: 'private-16', rir_id: 'r1', start: 64512, end: 65534, business_unit_id: null,
  asn_count: 1, available_count: 1022,
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
  '/ipam/vlan-translation-policies': () => page([POLICY]),
  '/ipam/vlan-translation-rules': () => page([RULE]),
  '/ipam/rirs': () => page([RIR]),
  '/ipam/asn-ranges': () => page([RANGE]),
  '/ipam/asn-ranges/{id}/available-asns': () => ({ data: { data: { range_id: 'ar1', start: 64512, end: 65534, size: 1023, used: 1, available: 1022, asns: [64513, 64514] } } }),
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

describe('Inventory → VLANs → Translation policies', () => {
  it('is a view of the VLANs lens, reached by its toggle (default)', async () => {
    answer(happy);
    await mount('/inventory?lens=vlans', MANAGE);
    expect(q('[data-testid="vlans-lens"]')).not.toBeNull();
    await click(q('[data-testid="vlans-view-translation"]'));
    await flush();
    expect(q('[data-testid="vlan-translation-view"]')).not.toBeNull();
    const row = q('[data-testid="vlan-translation-policy-row"]')?.textContent ?? '';
    expect(row).toContain('customer-a');
    expect(row).toContain('100→2100');
    expect(row).toContain('2 interfaces');
    expect(q('[data-testid="add-vlan-translation-policy"]')).not.toBeNull();
  });

  it('empty, loading and error states', async () => {
    answer({ ...happy, '/ipam/vlan-translation-policies': () => page([]) });
    await mount('/inventory?lens=vlans&view=translation', MANAGE);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No VLAN translation policies yet');
    answer({ ...happy, '/ipam/vlan-translation-policies': () => new Promise(() => {}) });
    await remount('/inventory?lens=vlans&view=translation', MANAGE);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
    answer({ ...happy, '/ipam/vlan-translation-policies': () => ({ error: { error: { code: 'x', message: 'policies unavailable' } } }) });
    await remount('/inventory?lens=vlans&view=translation', MANAGE);
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('policies unavailable');
  });

  it('opens a policy onto its rules and adds one (success)', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: RULE } });
    await mount('/inventory?lens=vlans&view=translation&policy=vp1', MANAGE);
    expect(q('[data-testid="vlan-translation-rule"]')?.textContent).toContain('2100');
    const rules = mocks.get.mock.calls.find((c) => c[0] === '/ipam/vlan-translation-rules');
    expect((rules?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ policy_id: 'vp1' });
    await click(q('[data-testid="add-vlan-translation-rule"]'));
    await setInput('Local VLAN ID', '200');
    await setInput('Remote VLAN ID', '2200');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/ipam/vlan-translation-rules');
    expect(init.body).toEqual({ policy_id: 'vp1', local_vid: 200, remote_vid: 2200, description: null });
  });

  it('adds a policy', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: { ...POLICY, id: 'vp2', name: 'customer-b' } } });
    await mount('/inventory?lens=vlans&view=translation', MANAGE);
    await click(q('[data-testid="add-vlan-translation-policy"]'));
    await setInput('Name', 'customer-b');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/ipam/vlan-translation-policies');
    expect(init.body).toMatchObject({ name: 'customer-b' });
  });

  it('hides every write control from a read-only role', async () => {
    answer(happy);
    await mount('/inventory?lens=vlans&view=translation&policy=vp1', READ);
    expect(q('[data-testid="vlan-translation-view"]')).not.toBeNull();
    expect(q('[data-testid="add-vlan-translation-policy"]')).toBeNull();
    expect(q('[data-testid="add-vlan-translation-rule"]')).toBeNull();
  });
});

describe('IPAM workspace → ASN ranges', () => {
  it('lists a range with what is in use and free, and shows the free numbers on request', async () => {
    answer(happy);
    await mount('/inventory/manage/ipam', MANAGE);
    const section = q('[data-testid="ipam-catalog-asn-ranges"]');
    expect(section?.textContent).toContain('Private 16-bit');
    expect(section?.textContent).toContain('AS64512–AS65534');
    expect(section?.textContent).toContain('RFC 6996');
    expect(q('[data-testid="asn-range-free"]')?.textContent).toContain('1 in use');
    expect(q('[data-testid="asn-range-free"]')?.textContent).toContain('1,022 free');
    expect(mocks.get.mock.calls.some((c) => c[0] === '/ipam/asn-ranges/{id}/available-asns')).toBe(false);
    await click(q('[data-testid="asn-range-show-free"]'));
    await flush();
    expect(q('[data-testid="asn-range-free-list"]')?.textContent).toBe('AS64513, AS64514, …');
    const call = mocks.get.mock.calls.find((c) => c[0] === '/ipam/asn-ranges/{id}/available-asns');
    expect((call?.[1] as { params: { path: Record<string, unknown> } }).params.path).toEqual({ id: 'ar1' });
  });

  it('adds a range', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: RANGE } });
    await mount('/inventory/manage/ipam', MANAGE);
    await click(q('[data-testid="add-asn-ranges"]'));
    await setInput('Name', 'Private 32-bit');
    await setSelect('RIR', 'r1');
    await setInput('First ASN', '4200000000');
    await setInput('Last ASN', '4200000999');
    await click(q('[data-testid="ipam-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/ipam/asn-ranges');
    expect(init.body).toMatchObject({ name: 'Private 32-bit', rir_id: 'r1', start: 4200000000, end: 4200000999 });
  });

  it('empty, error and loading', async () => {
    answer({ ...happy, '/ipam/asn-ranges': () => page([]) });
    await mount('/inventory/manage/ipam', MANAGE);
    expect(q('[data-testid="ipam-catalog-asn-ranges"] [data-testid="substrate-empty"]')).not.toBeNull();
    answer({ ...happy, '/ipam/asn-ranges': () => ({ error: { error: { code: 'x', message: 'no ranges' } } }) });
    await remount('/inventory/manage/ipam', MANAGE);
    expect(q('[data-testid="ipam-catalog-asn-ranges"] [data-testid="substrate-error"]')?.textContent).toContain('no ranges');
    answer({ ...happy, '/ipam/asn-ranges': () => new Promise(() => {}) });
    await remount('/inventory/manage/ipam', MANAGE);
    expect(q('[data-testid="ipam-catalog-asn-ranges"] [data-testid="substrate-loading"]')).not.toBeNull();
  });
});
