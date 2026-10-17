// Query hooks for virtualisation (asset-inventory ADR-0010 D8; DCIM BUILD_PLAN
// row 4.2): the Inventory → Clusters lens, the cluster page, the asset page's
// VM / hypervisor card and Settings → Cluster Types & Groups. Every path is in
// the inventory-service spec (`/virtualization/...`) and goes through the
// generated client.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { ipamError } from '../ipam/ipam-queries';

type S = components['schemas'];
export type ClusterType = S['ClusterType'];
export type ClusterGroup = S['ClusterGroup'];
export type Cluster = S['Cluster'];
export type VirtualDisk = S['VirtualDisk'];
export type ClusterMember = S['ClusterMember'];
export type AssetVirtualization = S['AssetVirtualization'];

/** Row type per object route. */
export interface VirtRows {
  'cluster-types': ClusterType;
  'cluster-groups': ClusterGroup;
  clusters: Cluster;
  'virtual-disks': VirtualDisk;
}
export type VirtRoute = keyof VirtRows;

// openapi-fetch types each literal path; the generic hooks pick the path at run
// time from a closed union, so they see the client through this narrower view.
interface LooseClient {
  GET(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  POST(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  PATCH(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
  DELETE(path: string, init?: unknown): Promise<{ data?: unknown; error?: unknown }>;
}
const inv = () => clients.inventory as unknown as LooseClient;

export const virtKeys = {
  all: ['virtualization'] as const,
  list: (route: VirtRoute, query: Record<string, string | number>) => ['virtualization', 'list', route, query] as const,
  one: (route: VirtRoute, id: string) => ['virtualization', 'one', route, id] as const,
  hosts: (id: string) => ['virtualization', 'hosts', id] as const,
  vms: (id: string) => ['virtualization', 'vms', id] as const,
  asset: (id: string) => ['virtualization', 'asset', id] as const,
};

export interface VirtPage<T> { rows: T[]; total: number }

/** One page of a virtualisation object list. */
export function useVirtList<R extends VirtRoute>(route: R, query: Record<string, string | number> = {}, opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: virtKeys.list(route, query),
    enabled: opts.enabled ?? true,
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }): Promise<VirtPage<VirtRows[R]>> => {
      const { data, error } = await inv().GET(`/virtualization/${route}`, { signal, params: { query: { limit: 200, ...query } } });
      if (error || !data) throw new Error(ipamError(error, `Failed to load ${route.replace('-', ' ')}`));
      const env = data as { data?: VirtRows[R][]; pagination?: { total?: number } };
      const rows = env.data ?? [];
      return { rows, total: env.pagination?.total ?? rows.length };
    },
  });
}

/** One cluster. */
export function useCluster(id: string | undefined) {
  return useQuery({
    queryKey: virtKeys.one('clusters', id ?? ''),
    enabled: !!id,
    queryFn: async ({ signal }): Promise<Cluster> => {
      const { data, error } = await clients.inventory.GET('/virtualization/clusters/{id}', { signal, params: { path: { id: id! } } });
      if (error || !data) throw new Error(ipamError(error, 'Failed to load the cluster'));
      return data.data;
    },
  });
}

/** A cluster's hosts. */
export function useClusterHosts(id: string | undefined) {
  return useQuery({
    queryKey: virtKeys.hosts(id ?? ''),
    enabled: !!id,
    queryFn: async ({ signal }): Promise<ClusterMember[]> => {
      const { data, error } = await clients.inventory.GET('/virtualization/clusters/{id}/hosts', { signal, params: { path: { id: id! } } });
      if (error || !data) throw new Error(ipamError(error, 'Failed to load the hosts'));
      return data.data ?? [];
    },
  });
}

/** A cluster's virtual machines. */
export function useClusterVms(id: string | undefined) {
  return useQuery({
    queryKey: virtKeys.vms(id ?? ''),
    enabled: !!id,
    queryFn: async ({ signal }): Promise<ClusterMember[]> => {
      const { data, error } = await clients.inventory.GET('/virtualization/clusters/{id}/vms', { signal, params: { path: { id: id! } } });
      if (error || !data) throw new Error(ipamError(error, 'Failed to load the virtual machines'));
      return data.data ?? [];
    },
  });
}

/** An asset's VM / hypervisor card. */
export function useAssetVirtualization(assetId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: virtKeys.asset(assetId ?? ''),
    enabled: !!assetId && enabled,
    queryFn: async ({ signal }): Promise<AssetVirtualization> => {
      const { data, error } = await clients.inventory.GET('/virtualization/assets/{id}/virtualization', { signal, params: { path: { id: assetId! } } });
      if (error || !data) throw new Error(ipamError(error, 'Failed to load the virtualisation details'));
      return data.data;
    },
  });
}

/** Create, edit or delete a virtualisation object; every virtualisation read is refetched. */
export function useVirtWrite<R extends VirtRoute>(route: R) {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: virtKeys.all });
  const create = useMutation({
    mutationFn: async (body: Record<string, unknown>): Promise<VirtRows[R]> => {
      const { data, error } = await inv().POST(`/virtualization/${route}`, { body });
      if (error || !data) throw new Error(ipamError(error, 'Could not create it'));
      return (data as { data: VirtRows[R] }).data;
    },
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Record<string, unknown> }): Promise<VirtRows[R]> => {
      const { data, error } = await inv().PATCH(`/virtualization/${route}/{id}`, { params: { path: { id } }, body });
      if (error || !data) throw new Error(ipamError(error, 'Could not save it'));
      return (data as { data: VirtRows[R] }).data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await inv().DELETE(`/virtualization/${route}/{id}`, { params: { path: { id } } });
      if (error) throw new Error(ipamError(error, 'Could not delete it'));
    },
    onSuccess: done,
  });
  return { create, update, remove };
}

/** Add or remove a cluster host. */
export function useClusterHostWrite(clusterId: string) {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: virtKeys.all });
  const add = useMutation({
    mutationFn: async (assetId: string) => {
      const { error } = await clients.inventory.POST('/virtualization/clusters/{id}/hosts', { params: { path: { id: clusterId } }, body: { asset_id: assetId } });
      if (error) throw new Error(ipamError(error, 'Could not add the host'));
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (assetId: string) => {
      const { error } = await clients.inventory.DELETE('/virtualization/clusters/{id}/hosts/{asset_id}', { params: { path: { id: clusterId, asset_id: assetId } } });
      if (error) throw new Error(ipamError(error, 'Could not remove the host'));
    },
    onSuccess: done,
  });
  return { add, remove };
}

/** Set a VM's cluster and resources. */
export function useUpdateAssetVirtualization(assetId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { cluster_id?: string | null; vcpus?: number | null; memory_mb?: number | null; disk_mb?: number | null }) => {
      const { data, error } = await clients.inventory.PATCH('/virtualization/assets/{id}/virtualization', { params: { path: { id: assetId } }, body });
      if (error || !data) throw new Error(ipamError(error, 'Could not save it'));
      return data.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: virtKeys.all }),
  });
}

export const CLUSTER_STATUS_LABEL: Record<Cluster['operational_status'], string> = {
  planned: 'Planned', staging: 'Staging', active: 'Active', decommissioning: 'Decommissioning', offline: 'Offline',
};

/** Memory or disk in MB as words; unknown is a dash, never 0. */
export function mbText(mb: number | null | undefined): string {
  if (mb == null) return '—';
  if (mb >= 1024 * 1024) return `${(mb / (1024 * 1024)).toFixed(mb % (1024 * 1024) === 0 ? 0 : 1)} TB`;
  if (mb >= 1024) return `${(mb / 1024).toFixed(mb % 1024 === 0 ? 0 : 1)} GB`;
  return `${mb} MB`;
}

/** vCPUs as text; unknown is a dash. */
export function cpuText(v: number | null | undefined): string {
  return v == null ? '—' : String(v);
}

/** The cluster page's resources summary: sums over the VMs that state each
 *  value, with how many did, so an unreported VM is not counted as zero. */
export function resourceTotals(vms: ClusterMember[]) {
  const sum = (k: 'vcpus' | 'memory_mb' | 'disk_mb') => {
    let total = 0;
    let known = 0;
    for (const v of vms) {
      const n = v[k];
      if (typeof n === 'number') { total += n; known += 1; }
    }
    return { total, known };
  };
  return { vcpus: sum('vcpus'), memory: sum('memory_mb'), disk: sum('disk_mb') };
}

/** An asset's name for a member row: display name, else hostname, else a short id. */
export function memberName(m: { display_name?: string | null; hostname?: string | null; asset_id: string }): string {
  if (m.display_name) return m.display_name;
  if (m.hostname) return m.hostname;
  return m.asset_id.slice(0, 8);
}

export const clusterHref = (id: string) => `/inventory/clusters/${id}`;
