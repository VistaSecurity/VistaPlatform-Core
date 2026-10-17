// @vitest-environment jsdom
//
// Virtualisation in the tenant UI (DCIM BUILD_PLAN row 4.2), mounted through
// the REAL InventoryPage, the REAL cluster page route, the REAL SettingsPage
// and the asset page's card, over a faked inventory client and the REAL
// permission gate: each in its five states (default, empty, loading, error,
// success), the writes they send, and the write controls hidden from a
// read-only role.
//
// Mutation: drop the `clusters` entry from lenses.ts, or the `clusters` branch
// from InventoryPage → "is reached through the real page" fails (the default
// lens renders instead); drop the `cluster-types` case from SettingsPage →
// the settings test fails; drop the /inventory/clusters/:id route from App.tsx
// → routing.contract.test.tsx fails.
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
import { ClusterPage } from './cluster-page';
import { VirtualizationCard } from './virtualization-card';
import { mbText, resourceTotals } from './virt-queries';

const NOW = new Date().toISOString();
const T = '00000000-0000-4000-8000-00000000000a';
const base = {
  tenant_id: T, description: null, comments: null, source_kind: 'declared', source_ref: null,
  custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const KVM = { ...base, tenant_id: null, id: 'ct-kvm', name: 'KVM', slug: 'kvm' };
const OWN_TYPE = { ...base, id: 'ct-own', name: 'Lab rig', slug: 'lab-rig' };
const GROUP = { ...base, id: 'g1', name: 'DC East', slug: 'dc-east', external_ids: {} };
const CLUSTER = {
  ...base, id: 'c1', name: 'pve-prod', type_id: 'ct-kvm', group_id: 'g1', operational_status: 'active', scope_kind: null, scope_id: null,
  business_unit_id: null, external_ids: {}, status: 'active', first_seen_at: null, last_seen_at: null, observation_count: 0,
  approved_by: null, approved_at: null, type: { id: 'ct-kvm', name: 'KVM', slug: 'kvm' }, group: { id: 'g1', name: 'DC East', slug: 'dc-east' },
  host_count: 2, vm_count: 3,
};
const MIRROR = { ...CLUSTER, id: 'c2', name: '123456789012/us-east-1', type_id: 'ct-aws', group_id: null, group: null,
  type: { id: 'ct-aws', name: 'AWS', slug: 'aws' }, external_ids: { cloud: '123456789012:us-east-1' }, status: 'pending', host_count: 0, vm_count: 4 };
const HOST = { asset_id: '11111111-1111-4111-8111-111111111111', display_name: 'pve-01', hostname: 'pve-01', class_key: 'hypervisor', asset_status: 'monitoring', source_kind: 'measured' };
const VM1 = { asset_id: '22222222-2222-4222-8222-222222222222', display_name: 'web-01', hostname: null, class_key: 'virtual_machine', asset_status: 'monitoring', vcpus: 2, memory_mb: 4096, disk_mb: 40960, virtual_disk_count: 1 };
const VM2 = { ...VM1, asset_id: '33333333-3333-4333-8333-333333333333', display_name: 'db-01', vcpus: 4, memory_mb: 8192, disk_mb: null };

const page = (rows: unknown[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });
type RouteMap = Record<string, (init?: unknown) => unknown>;
function answer(routes: RouteMap) {
  mocks.get.mockImplementation(async (path: string, init?: unknown) => {
    const fn = routes[path];
    return fn ? fn(init) : page([]);
  });
}
const happy: RouteMap = {
  '/virtualization/clusters': () => page([CLUSTER, MIRROR]),
  '/virtualization/cluster-types': () => page([KVM, OWN_TYPE]),
  '/virtualization/cluster-groups': () => page([GROUP]),
  '/virtualization/clusters/{id}': (init) => ({ data: { data: (init as { params: { path: { id: string } } }).params.path.id === 'c2' ? MIRROR : CLUSTER } }),
  '/virtualization/clusters/{id}/hosts': () => ({ data: { data: [HOST] } }),
  '/virtualization/clusters/{id}/vms': () => ({ data: { data: [VM1, VM2] } }),
  '/infrastructure-assets': () => ({ data: { assets: [{ id: 'hv2', display_name: 'pve-02', hostname: 'pve-02' }], pagination: { total: 1, page: 1, page_size: 50 } } }),
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
const MANAGE = ['virtualization.read', 'virtualization.manage'];
const READ = ['virtualization.read'];

async function mount(path: string, permissions: string[], card?: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/inventory" element={<InventoryPage />} />
              <Route path="/inventory/clusters/:id" element={<ClusterPage />} />
              <Route path="/inventory/manage/:page" element={<WorkspacePage />} />
              <Route path="/card" element={<div style={{ display: 'grid' }}><VirtualizationCard assetId={card ?? ''} /></div>} />
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

describe('Inventory → Clusters', () => {
  it('is reached through the real page and lists clusters with type, group, hosts, VMs and status (success)', async () => {
    answer(happy);
    await mount('/inventory?lens=clusters', MANAGE);
    expect(q('[data-testid="clusters-lens"]')).not.toBeNull();
    const rows = all('[data-testid="cluster-row"]').map((r) => r.textContent ?? '');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toContain('pve-prod');
    expect(rows[0]).toContain('KVM');
    expect(rows[0]).toContain('DC East');
    expect(rows[0]).toContain('Active');
    expect(rows[1]).toContain('AWS');
    expect(rows[1]).toContain('Pending approval');
    expect(q('[data-testid="cluster-row"] a')?.getAttribute('href')).toBe('/inventory/clusters/c1');
    expect(q('[data-testid="add-cluster"]')).not.toBeNull();
  });

  it('filters by type through the server (default → filtered)', async () => {
    answer(happy);
    await mount('/inventory?lens=clusters&type=ct-kvm', MANAGE);
    const call = mocks.get.mock.calls.find((c) => c[0] === '/virtualization/clusters');
    expect((call?.[1] as { params: { query: Record<string, unknown> } }).params.query).toMatchObject({ type_id: 'ct-kvm' });
  });

  it('shows no clusters as empty, not as an error (empty)', async () => {
    answer({ ...happy, '/virtualization/clusters': () => page([]) });
    await mount('/inventory?lens=clusters', MANAGE);
    expect(q('[data-testid="substrate-empty"]')?.textContent).toContain('No clusters yet');
  });

  it('shows loading (loading)', async () => {
    answer({ ...happy, '/virtualization/clusters': () => new Promise(() => {}) });
    await mount('/inventory?lens=clusters', MANAGE);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
  });

  it('shows the server error (error)', async () => {
    answer({ ...happy, '/virtualization/clusters': () => ({ error: { error: { message: 'boom' } } }) });
    await mount('/inventory?lens=clusters', MANAGE);
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('boom');
  });

  it('creates a cluster with the chosen type', async () => {
    answer(happy);
    mocks.post.mockResolvedValue({ data: { data: { ...CLUSTER, id: 'c9' } } });
    await mount('/inventory?lens=clusters', MANAGE);
    await click(q('[data-testid="add-cluster"]'));
    const set = (label: string, v: string) => act(async () => {
      const el = document.querySelector(`[aria-label="${label}"]`) as HTMLInputElement | HTMLSelectElement;
      const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, v);
      el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
    });
    await set('Name', 'esx-lab');
    await set('Cluster type', 'ct-kvm');
    await click(document.querySelector('[data-testid="virt-save"]'));
    await flush();
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/virtualization/clusters');
    expect(init.body).toMatchObject({ name: 'esx-lab', type_id: 'ct-kvm', operational_status: 'active' });
  });

  it('hides the write controls from a read-only role', async () => {
    answer(happy);
    await mount('/inventory?lens=clusters', READ);
    expect(q('[data-testid="clusters-lens"]')).not.toBeNull();
    expect(q('[data-testid="add-cluster"]')).toBeNull();
  });
});

describe('the cluster page', () => {
  it('shows the cluster, its resources, hosts and VMs (success)', async () => {
    answer(happy);
    await mount('/inventory/clusters/c1', MANAGE);
    expect(q('[data-testid="cluster-name"]')?.textContent).toBe('pve-prod');
    expect(all('[data-testid="host-row"]')).toHaveLength(1);
    expect(q('[data-testid="host-row"] a')?.getAttribute('href')).toBe(`/inventory/assets/${HOST.asset_id}`);
    const vms = all('[data-testid="vm-row"]').map((r) => r.textContent ?? '');
    expect(vms).toHaveLength(2);
    expect(vms[0]).toContain('web-01');
    expect(vms[0]).toContain('4 GB');
    expect(vms[1]).toContain('—'); // db-01 reports no disk: a dash, never 0
    const tiles = all('[data-testid="resource-tile"]').map((t) => t.textContent ?? '');
    expect(tiles[0]).toContain('2');
    expect(tiles[1]).toContain('6');
    expect(tiles[2]).toContain('12 GB');
    expect(tiles[3]).toContain('1 of 2 VMs report it');
  });

  it('says a cloud mirror is one, and offers approval of a pending cluster', async () => {
    answer(happy);
    mocks.patch.mockResolvedValue({ data: { data: { ...MIRROR, status: 'active' } } });
    await mount('/inventory/clusters/c2', MANAGE);
    expect(q('[data-testid="cloud-mirror"]')?.textContent).toContain('123456789012:us-east-1');
    await click(q('[data-testid="approve-cluster"]'));
    await flush();
    const [path, init] = mocks.patch.mock.calls[0] as [string, { params: { path: { id: string } }; body: unknown }];
    expect(path).toBe('/virtualization/clusters/{id}');
    expect(init.params.path.id).toBe('c2');
    expect(init.body).toEqual({ status: 'active' });
  });

  it('removes a host', async () => {
    answer(happy);
    mocks.del.mockResolvedValue({});
    await mount('/inventory/clusters/c1', MANAGE);
    await click(q('[data-testid="remove-host"]'));
    await flush();
    const [path, init] = mocks.del.mock.calls[0] as [string, { params: { path: Record<string, string> } }];
    expect(path).toBe('/virtualization/clusters/{id}/hosts/{asset_id}');
    expect(init.params.path).toEqual({ id: 'c1', asset_id: HOST.asset_id });
  });

  it('says so when a cluster has no hosts and no VMs (empty)', async () => {
    answer({ ...happy, '/virtualization/clusters/{id}/hosts': () => ({ data: { data: [] } }), '/virtualization/clusters/{id}/vms': () => ({ data: { data: [] } }) });
    await mount('/inventory/clusters/c1', READ);
    const empties = all('[data-testid="substrate-empty"]').map((e) => e.textContent ?? '');
    expect(empties.some((e) => e.includes('No hosts recorded'))).toBe(true);
    expect(empties.some((e) => e.includes('No virtual machines recorded'))).toBe(true);
    expect(q('[data-testid="add-host"]')).toBeNull();
    expect(q('[data-testid="edit-cluster"]')).toBeNull();
  });

  it('shows loading and error (loading, error)', async () => {
    answer({ ...happy, '/virtualization/clusters/{id}': () => new Promise(() => {}) });
    await mount('/inventory/clusters/c1', MANAGE);
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
    act(() => root.unmount());
    root = createRoot(host);
    answer({ ...happy, '/virtualization/clusters/{id}': () => ({ error: { error: { message: 'No such object for this organisation.' } } }) });
    await mount('/inventory/clusters/c1', MANAGE);
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('No such object');
  });
});

describe('Settings → Cluster Types & Groups', () => {
  it('lists built-in types read-only and the tenant’s own editable', async () => {
    answer(happy);
    await mount('/inventory/manage/cluster-types', MANAGE);
    expect(q('[data-testid="virtualization-settings"]')).not.toBeNull();
    const types = q('[data-testid="virt-catalog-cluster-types"]')?.textContent ?? '';
    expect(types).toContain('KVM');
    expect(types).toContain('Built in');
    expect(types).toContain('Lab rig');
    expect(q('[data-testid="virt-catalog-cluster-groups"]')?.textContent).toContain('DC East');
    expect(q('[data-testid="add-cluster-groups"]')).not.toBeNull();
  });

  it('shows empty and error states', async () => {
    answer({ ...happy, '/virtualization/cluster-groups': () => page([]), '/virtualization/cluster-types': () => ({ error: { error: { message: 'nope' } } }) });
    await mount('/inventory/manage/cluster-types', READ);
    expect(q('[data-testid="virt-catalog-cluster-groups"] [data-testid="substrate-empty"]')).not.toBeNull();
    expect(q('[data-testid="virt-catalog-cluster-types"] [data-testid="substrate-error"]')?.textContent).toContain('nope');
    expect(q('[data-testid="add-cluster-groups"]')).toBeNull();
  });
});

describe('the asset page’s virtualisation card', () => {
  const VM_CARD = {
    asset_id: VM1.asset_id, class_key: 'virtual_machine', class_path: 'virtual.virtual_machine', is_vm: true, is_host: false,
    cluster: { id: 'c1', name: 'pve-prod', type_name: 'KVM', type_slug: 'kvm' }, vcpus: 2, memory_mb: 4096, disk_mb: null,
    virtual_disks: [{ ...base, id: 'd1', asset_id: VM1.asset_id, name: 'disk0', size_mb: 40960, external_ids: {} }], host_cluster: null, hosted_vms: [],
  };
  const HOST_CARD = { ...VM_CARD, asset_id: HOST.asset_id, class_key: 'hypervisor', class_path: 'virtual.hypervisor', is_vm: false, is_host: true,
    cluster: null, vcpus: null, memory_mb: null, virtual_disks: [], host_cluster: VM_CARD.cluster, hosted_vms: [VM1] };
  const card = (data: unknown) => ({ ...happy, '/virtualization/assets/{id}/virtualization': () => data });

  it('shows a VM’s cluster, resources and virtual disks, and saves an edit (success)', async () => {
    answer(card({ data: { data: VM_CARD } }));
    mocks.patch.mockResolvedValue({ data: { data: VM_CARD } });
    await mount('/card', MANAGE, VM1.asset_id);
    const vm = q('[data-testid="vm-card"]')?.textContent ?? '';
    expect(vm).toContain('pve-prod');
    expect(vm).toContain('4 GB');
    expect(vm).toContain('disk0');
    expect(q('[data-testid="card-cluster-link"]')?.getAttribute('href')).toBe('/inventory/clusters/c1');
    await click(q('[data-testid="edit-vm"]'));
    await click(document.querySelector('[data-testid="vm-save"]'));
    await flush();
    const [path, init] = mocks.patch.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/virtualization/assets/{id}/virtualization');
    expect(init.body).toEqual({ cluster_id: 'c1', vcpus: 2, memory_mb: 4096, disk_mb: null });
  });

  it('shows a hypervisor’s cluster and hosted VMs', async () => {
    answer(card({ data: { data: HOST_CARD } }));
    await mount('/card', READ, HOST.asset_id);
    expect(q('[data-testid="hypervisor-card"]')?.textContent).toContain('pve-prod');
    expect(all('[data-testid="hosted-vm"]')).toHaveLength(1);
    expect(q('[data-testid="edit-vm"]')).toBeNull();
  });

  it('renders nothing for an asset no card applies to (empty), loading and error', async () => {
    answer(card({ data: { data: { ...VM_CARD, is_vm: false, is_host: false } } }));
    await mount('/card', READ, 'x');
    expect(q('[data-testid="vm-card"]')).toBeNull();
    expect(q('[data-testid="hypervisor-card"]')).toBeNull();
    act(() => root.unmount());
    root = createRoot(host);
    answer(card(new Promise(() => {})));
    await mount('/card', READ, 'x');
    expect(q('[data-testid="substrate-loading"]')).not.toBeNull();
    act(() => root.unmount());
    root = createRoot(host);
    answer(card({ error: { error: { message: 'down' } } }));
    await mount('/card', READ, 'x');
    expect(q('[data-testid="substrate-error"]')?.textContent).toContain('down');
  });

  it('is not shown to a role without virtualization.read (default)', async () => {
    answer(card({ data: { data: VM_CARD } }));
    await mount('/card', ['assets.read'], VM1.asset_id);
    expect(q('[data-testid="vm-card"]')).toBeNull();
    expect(mocks.get.mock.calls.some((c) => c[0] === '/virtualization/assets/{id}/virtualization')).toBe(false);
  });
});

describe('resource arithmetic', () => {
  it('sums only what VMs report, and says MB/GB/TB', () => {
    const t = resourceTotals([VM1, VM2] as never);
    expect(t.disk).toEqual({ total: 40960, known: 1 });
    expect(mbText(null)).toBe('—');
    expect(mbText(512)).toBe('512 MB');
    expect(mbText(1536)).toBe('1.5 GB');
    expect(mbText(1024 * 1024)).toBe('1 TB');
  });
});
