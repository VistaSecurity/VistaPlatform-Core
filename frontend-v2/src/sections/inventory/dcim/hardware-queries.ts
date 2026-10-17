// Query hooks for an asset's hardware (DCIM BUILD_PLAN row 2.4; asset-inventory
// ADR-0010 D4): its module bays and the modules in them, its inventory items,
// the virtual chassis it is a member of, and the module-type catalogue the
// Install module dialog searches. Device bays are row 3.1's component kind
// (component-queries.ts).
//
// HARDWARE_PATHS `satisfies` the generated client's path keys, so a path that
// leaves the spec fails typecheck.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components, inventoryPaths } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { portKeys } from './component-queries';
import { substrateError } from './substrate-queries';

export type ModuleBay = components['schemas']['ModuleBay'];
export type Module = components['schemas']['Module'];
export type InventoryItem = components['schemas']['InventoryItem'];
export type InventoryItemRole = components['schemas']['InventoryItemRole'];
export type VirtualChassis = components['schemas']['VirtualChassis'];
export type VirtualChassisMember = components['schemas']['VirtualChassisMember'];
export type AssetVirtualChassis = components['schemas']['AssetVirtualChassis'];
export type ModuleType = components['schemas']['ModuleType'];
export type Manufacturer = components['schemas']['Manufacturer'];

export const HARDWARE_PATHS = [
  '/dcim/assets/{id}/module-bays', '/dcim/assets/{id}/modules', '/dcim/assets/{id}/inventory-items',
  '/dcim/assets/{id}/virtual-chassis', '/dcim/modules/{id}', '/dcim/inventory-item-roles', '/dcim/virtual-chassis',
  '/dcim/virtual-chassis/{id}/members', '/dcim/virtual-chassis/{id}/members/{asset_id}', '/dcim/module-types',
  '/dcim/module-types/{id}', '/dcim/manufacturers',
] as const satisfies readonly (keyof inventoryPaths)[];

interface Reply { data?: unknown; error?: unknown }
interface Loose {
  GET: (path: string, init?: object) => Promise<Reply>;
  POST: (path: string, init?: object) => Promise<Reply>;
  PATCH: (path: string, init?: object) => Promise<Reply>;
  DELETE: (path: string, init?: object) => Promise<Reply>;
}
const api = (): Loose => clients.inventory as unknown as Loose;

export const HARDWARE_PAGE_SIZE = 1000;

export const hardwareKeys = {
  asset: (assetId: string) => ['dcim-hardware-objects', assetId] as const,
  list: (assetId: string, kind: string) => ['dcim-hardware-objects', assetId, kind] as const,
  chassis: (assetId: string) => ['dcim-hardware-objects', assetId, 'virtual-chassis'] as const,
  roles: ['dcim-inventory-item-roles'] as const,
  moduleTypes: (q: string) => ['dcim-module-types', q] as const,
  allModuleTypes: ['dcim-module-types'] as const,
  manufacturers: ['dcim-manufacturers'] as const,
};

export class HardwareWriteError extends Error {}

async function listOf<T>(path: string, assetId: string, what: string): Promise<T[]> {
  const { data, error } = await api().GET(path, { params: { path: { id: assetId }, query: { limit: HARDWARE_PAGE_SIZE } } });
  const env = data as { data?: T[] } | undefined;
  if (error || !env) throw new Error(substrateError(error, `Failed to load ${what}`));
  return env.data ?? [];
}

export function useAssetModuleBays(assetId: string | undefined) {
  return useQuery({
    queryKey: hardwareKeys.list(assetId ?? '', 'module-bays'),
    enabled: !!assetId,
    queryFn: () => listOf<ModuleBay>('/dcim/assets/{id}/module-bays', assetId!, 'module bays'),
  });
}

export function useAssetModules(assetId: string | undefined) {
  return useQuery({
    queryKey: hardwareKeys.list(assetId ?? '', 'modules'),
    enabled: !!assetId,
    queryFn: () => listOf<Module>('/dcim/assets/{id}/modules', assetId!, 'modules'),
  });
}

export function useAssetInventoryItems(assetId: string | undefined) {
  return useQuery({
    queryKey: hardwareKeys.list(assetId ?? '', 'inventory-items'),
    enabled: !!assetId,
    queryFn: () => listOf<InventoryItem>('/dcim/assets/{id}/inventory-items', assetId!, 'inventory items'),
  });
}

export function useInventoryItemRoles() {
  return useQuery({
    queryKey: hardwareKeys.roles,
    queryFn: async (): Promise<InventoryItemRole[]> => {
      const { data, error } = await api().GET('/dcim/inventory-item-roles', { params: { query: { limit: HARDWARE_PAGE_SIZE } } });
      const env = data as { data?: InventoryItemRole[] } | undefined;
      if (error || !env) throw new Error(substrateError(error, 'Failed to load inventory item roles'));
      return env.data ?? [];
    },
    staleTime: 5 * 60_000,
  });
}

export function useAssetVirtualChassis(assetId: string | undefined) {
  return useQuery({
    queryKey: hardwareKeys.chassis(assetId ?? ''),
    enabled: !!assetId,
    queryFn: async (): Promise<AssetVirtualChassis> => {
      const { data, error } = await api().GET('/dcim/assets/{id}/virtual-chassis', { params: { path: { id: assetId! } } });
      const env = data as { data?: AssetVirtualChassis } | undefined;
      if (error || !env?.data) throw new Error(substrateError(error, 'Failed to load the virtual chassis'));
      return env.data;
    },
  });
}

export function useModuleTypes(q: string, enabled = true) {
  return useQuery({
    queryKey: hardwareKeys.moduleTypes(q),
    enabled,
    queryFn: async (): Promise<ModuleType[]> => {
      const query: Record<string, unknown> = { limit: 200 };
      if (q.trim()) query.q = q.trim();
      const { data, error } = await api().GET('/dcim/module-types', { params: { query } });
      const env = data as { data?: ModuleType[] } | undefined;
      if (error || !env) throw new Error(substrateError(error, 'Failed to load module types'));
      return env.data ?? [];
    },
  });
}

export function useManufacturers(enabled = true) {
  return useQuery({
    queryKey: hardwareKeys.manufacturers,
    enabled,
    queryFn: async (): Promise<Manufacturer[]> => {
      const { data, error } = await api().GET('/dcim/manufacturers', { params: { query: { limit: 1000 } } });
      const env = data as { data?: Manufacturer[] } | undefined;
      if (error || !env) throw new Error(substrateError(error, 'Failed to load manufacturers'));
      return env.data ?? [];
    },
    staleTime: 5 * 60_000,
  });
}

/** A write on the Hardware tab can change ports, interfaces and bays alike. */
function useInvalidateAsset(assetId: string) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: hardwareKeys.asset(assetId) });
    void qc.invalidateQueries({ queryKey: portKeys.asset(assetId) });
    void qc.invalidateQueries({ queryKey: ['dcim-interfaces', assetId] });
  };
}

export interface InstallModuleInput { module_bay_id: string; module_type_id: string; serial?: string | null }

export function useInstallModule(assetId: string) {
  const invalidate = useInvalidateAsset(assetId);
  return useMutation({
    mutationFn: async (body: InstallModuleInput): Promise<Module> => {
      const { data, error } = await api().POST('/dcim/assets/{id}/modules', { params: { path: { id: assetId } }, body });
      const env = data as { data?: Module } | undefined;
      if (error || !env?.data) throw new HardwareWriteError(substrateError(error, 'Failed to install the module'));
      return env.data;
    },
    onSuccess: () => {
      toast.success('Module installed');
      invalidate();
    },
  });
}

export function useRemoveModule(assetId: string) {
  const invalidate = useInvalidateAsset(assetId);
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await api().DELETE('/dcim/modules/{id}', { params: { path: { id } } });
      if (error) throw new HardwareWriteError(substrateError(error, 'Failed to remove the module'));
    },
    onSuccess: () => {
      toast.success('Module removed');
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to remove the module'),
  });
}

export function useCreateVirtualChassis(assetId: string) {
  const invalidate = useInvalidateAsset(assetId);
  return useMutation({
    mutationFn: async (body: { name: string; domain?: string | null; master_asset_id: string }): Promise<VirtualChassis> => {
      const { data, error } = await api().POST('/dcim/virtual-chassis', { body });
      const env = data as { data?: VirtualChassis } | undefined;
      if (error || !env?.data) throw new HardwareWriteError(substrateError(error, 'Failed to create the virtual chassis'));
      return env.data;
    },
    onSuccess: () => {
      toast.success('Virtual chassis created');
      invalidate();
    },
  });
}

export function useAddChassisMember(assetId: string) {
  const invalidate = useInvalidateAsset(assetId);
  return useMutation({
    mutationFn: async ({ vc, ...body }: { vc: string; asset_id: string; vc_position: number | null; vc_priority: number | null }) => {
      const { data, error } = await api().POST('/dcim/virtual-chassis/{id}/members', { params: { path: { id: vc } }, body });
      const env = data as { data?: VirtualChassisMember[] } | undefined;
      if (error || !env?.data) throw new HardwareWriteError(substrateError(error, 'Failed to add the member'));
      return env.data;
    },
    onSuccess: () => {
      toast.success('Member added');
      invalidate();
    },
  });
}

export function useRemoveChassisMember(assetId: string) {
  const invalidate = useInvalidateAsset(assetId);
  return useMutation({
    mutationFn: async ({ vc, member }: { vc: string; member: string }) => {
      const { error } = await api().DELETE('/dcim/virtual-chassis/{id}/members/{asset_id}', { params: { path: { id: vc, asset_id: member } } });
      if (error) throw new HardwareWriteError(substrateError(error, 'Failed to remove the member'));
    },
    onSuccess: () => {
      toast.success('Member removed');
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to remove the member'),
  });
}

/** Inventory items as a tree: roots in natural name order, each with its children. */
export interface ItemNode { item: InventoryItem; depth: number }
export function itemTree(items: readonly InventoryItem[]): ItemNode[] {
  const byParent = new Map<string | null, InventoryItem[]>();
  const ids = new Set(items.map((i) => i.id));
  for (const i of items) {
    const p = i.parent_id && ids.has(i.parent_id) ? i.parent_id : null;
    byParent.set(p, [...(byParent.get(p) ?? []), i]);
  }
  const out: ItemNode[] = [];
  const walk = (parent: string | null, depth: number) => {
    const kids = [...(byParent.get(parent) ?? [])].sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
    for (const k of kids) {
      out.push({ item: k, depth });
      if (depth < 16) walk(k.id, depth + 1);
    }
  };
  walk(null, 0);
  return out;
}

/** Module types created by the tenant can be edited; the platform's are read-only. */
export const isPlatformRow = (r: { tenant_id: string | null }) => r.tenant_id == null;

export function useCreateModuleType() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { manufacturer_id: string; model: string; part_number?: string | null; description?: string | null }): Promise<ModuleType> => {
      const { data, error } = await api().POST('/dcim/module-types', { body });
      const env = data as { data?: ModuleType } | undefined;
      if (error || !env?.data) throw new HardwareWriteError(substrateError(error, 'Failed to create the module type'));
      return env.data;
    },
    onSuccess: (r) => {
      toast.success(`Created ${r.model}`);
      void qc.invalidateQueries({ queryKey: hardwareKeys.allModuleTypes });
    },
  });
}

export function useDeleteModuleType() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (r: ModuleType) => {
      const { error } = await api().DELETE('/dcim/module-types/{id}', { params: { path: { id: r.id } } });
      if (error) throw new HardwareWriteError(substrateError(error, 'Failed to delete the module type'));
      return r;
    },
    onSuccess: (r) => {
      toast.success(`Deleted ${r.model}`);
      void qc.invalidateQueries({ queryKey: hardwareKeys.allModuleTypes });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete the module type'),
  });
}
