// Query hooks for an asset's interfaces (DCIM BUILD_PLAN row 1.2;
// asset-inventory ADR-0010 D3). Every path is in the inventory-service spec and
// goes through the generated client.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError, substrateKeys } from './substrate-queries';

export type Interface = components['schemas']['Interface'];
export type InterfaceCreate = components['schemas']['InterfaceCreate'];
export type InterfacePatch = components['schemas']['InterfacePatch'];

/** The tab lists an asset's interfaces on one page; a chassis has hundreds. */
export const INTERFACES_PAGE_SIZE = 1000;

export const interfaceKeys = {
  asset: (assetId: string, q: string) => ['dcim-interfaces', assetId, q] as const,
  assetAll: (assetId: string) => ['dcim-interfaces', assetId] as const,
};

/** The field a 422 names, so the drawer can mark it. */
export function interfaceErrorField(error: unknown): string | undefined {
  if (error && typeof error === 'object') {
    const inner = (error as { error?: unknown }).error;
    if (inner && typeof inner === 'object') {
      const f = (inner as { field?: unknown }).field;
      if (typeof f === 'string') return f;
    }
  }
  return undefined;
}

export class InterfaceWriteError extends Error {
  constructor(message: string, readonly field?: string) {
    super(message);
  }
}

export interface InterfacePage { rows: Interface[]; total: number }

export function useAssetInterfaces(assetId: string | undefined, q = '', enabled = true) {
  return useQuery({
    queryKey: interfaceKeys.asset(assetId ?? '', q),
    enabled: !!assetId && enabled,
    queryFn: async (): Promise<InterfacePage> => {
      const query: { limit: number; q?: string } = { limit: INTERFACES_PAGE_SIZE };
      if (q.trim()) query.q = q.trim();
      const { data, error } = await clients.inventory.GET('/dcim/assets/{id}/interfaces', {
        params: { path: { id: assetId! }, query },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load interfaces'));
      return { rows: data.data ?? [], total: data.pagination?.total ?? (data.data ?? []).length };
    },
  });
}

function useInvalidate(assetId: string) {
  const qc = useQueryClient();
  return (id?: string) => {
    void qc.invalidateQueries({ queryKey: interfaceKeys.assetAll(assetId) });
    if (id) void qc.invalidateQueries({ queryKey: substrateKeys.changes('interface', id) });
  };
}

export function useCreateInterface(assetId: string) {
  const invalidate = useInvalidate(assetId);
  return useMutation({
    mutationFn: async (body: InterfaceCreate): Promise<Interface> => {
      const { data, error } = await clients.inventory.POST('/dcim/interfaces', { body });
      if (error || !data) throw new InterfaceWriteError(substrateError(error, 'Failed to add the interface'), interfaceErrorField(error));
      return data.data;
    },
    onSuccess: (i) => {
      toast.success(`Added ${i.name}`);
      invalidate(i.id);
    },
  });
}

export function usePatchInterface(assetId: string) {
  const invalidate = useInvalidate(assetId);
  return useMutation({
    mutationFn: async ({ id, patch }: { id: string; patch: InterfacePatch }): Promise<Interface> => {
      const { data, error } = await clients.inventory.PATCH('/dcim/interfaces/{id}', {
        params: { path: { id } },
        body: patch,
      });
      if (error || !data) throw new InterfaceWriteError(substrateError(error, 'Failed to save the interface'), interfaceErrorField(error));
      return data.data;
    },
    onSuccess: (i) => {
      toast.success(`Saved ${i.name}`);
      invalidate(i.id);
    },
  });
}

export function useDeleteInterface(assetId: string) {
  const invalidate = useInvalidate(assetId);
  return useMutation({
    mutationFn: async (i: Interface): Promise<Interface> => {
      const { error } = await clients.inventory.DELETE('/dcim/interfaces/{id}', { params: { path: { id: i.id } } });
      if (error) throw new InterfaceWriteError(substrateError(error, 'Failed to delete the interface'));
      return i;
    },
    onSuccess: (i) => {
      toast.success(`Deleted ${i.name}`);
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete the interface'),
  });
}

export type Vlan = components['schemas']['Vlan'];

/** The tenant's VLANs for the drawer's picker (row 1.3's `/ipam/vlans`).
 *  Needs ipam.read; without it, or when the request fails, the drawer falls
 *  back to typed VLAN ids. */
export function useVlanChoices(enabled: boolean) {
  return useQuery({
    queryKey: ['dcim-interface-vlan-choices'] as const,
    enabled,
    staleTime: 60_000,
    queryFn: async (): Promise<Vlan[]> => {
      const { data, error } = await clients.inventory.GET('/ipam/vlans', { params: { query: { limit: 1000 } } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load VLANs'));
      return (data.data ?? []).filter((v) => v.status !== 'rejected');
    },
  });
}

/** "110 · voice". */
export function vlanLabel(v: Pick<Vlan, 'vid' | 'name'>): string {
  return `${v.vid} · ${v.name}`;
}
