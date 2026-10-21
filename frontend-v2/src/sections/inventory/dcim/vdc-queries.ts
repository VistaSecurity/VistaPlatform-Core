// Query hooks for an asset's virtual device contexts (DCIM gap 1; NetBox
// dcim/virtual-device-context): the logical partitions of a device — a Nexus
// VDC, a Palo Alto vsys, a Fortinet VDOM, an F5 route domain — that own
// interfaces and addresses. An interface's membership is written through the
// interface's own PATCH (virtual_device_context_ids, interface-queries.ts).
//
// VDC_PATHS `satisfies` the generated client's path keys, so a path that
// leaves the spec fails typecheck.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components, inventoryPaths } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { interfaceKeys } from './interface-queries';
import { substrateError, substrateKeys } from './substrate-queries';

export type VirtualDeviceContext = components['schemas']['VirtualDeviceContext'];
export type VirtualDeviceContextInput = components['schemas']['VirtualDeviceContextUpdateInput'];

export const VDC_PATHS = [
  '/dcim/assets/{id}/virtual-device-contexts', '/dcim/virtual-device-contexts/{id}',
] as const satisfies readonly (keyof inventoryPaths)[];

/** NetBox 4.3's VirtualDeviceContextStatusChoices, in its order. */
export const VDC_STATUSES = ['active', 'planned', 'offline'] as const;
export type VdcStatus = (typeof VDC_STATUSES)[number];
export const VDC_STATUS_LABEL: Record<VdcStatus, string> = { active: 'Active', planned: 'Planned', offline: 'Offline' };

interface Reply { data?: unknown; error?: unknown }
interface Loose {
  GET: (path: string, init?: object) => Promise<Reply>;
  POST: (path: string, init?: object) => Promise<Reply>;
  PATCH: (path: string, init?: object) => Promise<Reply>;
  DELETE: (path: string, init?: object) => Promise<Reply>;
}
const api = (): Loose => clients.inventory as unknown as Loose;

export const vdcKeys = {
  asset: (assetId: string) => ['dcim-virtual-device-contexts', assetId] as const,
};

export class VdcWriteError extends Error {}

/** One asset's contexts, by identifier then name (the server's order). */
export function useAssetVirtualDeviceContexts(assetId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: vdcKeys.asset(assetId ?? ''),
    enabled: !!assetId && enabled,
    queryFn: async (): Promise<VirtualDeviceContext[]> => {
      const { data, error } = await api().GET('/dcim/assets/{id}/virtual-device-contexts', {
        params: { path: { id: assetId! }, query: { limit: 1000 } },
      });
      const env = data as { data?: VirtualDeviceContext[] } | undefined;
      if (error || !env) throw new Error(substrateError(error, 'Failed to load virtual device contexts'));
      return (env.data ?? []).filter((c) => c.status !== 'rejected');
    },
  });
}

function useInvalidate(assetId: string) {
  const qc = useQueryClient();
  return (id?: string) => {
    void qc.invalidateQueries({ queryKey: vdcKeys.asset(assetId) });
    // A context's delete (and a rename) changes what its interfaces show.
    void qc.invalidateQueries({ queryKey: interfaceKeys.assetAll(assetId) });
    if (id) void qc.invalidateQueries({ queryKey: substrateKeys.changes('virtual_device_context', id) });
  };
}

export function useCreateVirtualDeviceContext(assetId: string) {
  const invalidate = useInvalidate(assetId);
  return useMutation({
    mutationFn: async (body: VirtualDeviceContextInput): Promise<VirtualDeviceContext> => {
      const { data, error } = await api().POST('/dcim/assets/{id}/virtual-device-contexts', { params: { path: { id: assetId } }, body });
      const env = data as { data?: VirtualDeviceContext } | undefined;
      if (error || !env?.data) throw new VdcWriteError(substrateError(error, 'Failed to add the virtual device context'));
      return env.data;
    },
    onSuccess: (c) => {
      toast.success(`Added ${c.name}`);
      invalidate(c.id);
    },
  });
}

export function useUpdateVirtualDeviceContext(assetId: string) {
  const invalidate = useInvalidate(assetId);
  return useMutation({
    mutationFn: async ({ id, patch }: { id: string; patch: VirtualDeviceContextInput }): Promise<VirtualDeviceContext> => {
      const { data, error } = await api().PATCH('/dcim/virtual-device-contexts/{id}', { params: { path: { id } }, body: patch });
      const env = data as { data?: VirtualDeviceContext } | undefined;
      if (error || !env?.data) throw new VdcWriteError(substrateError(error, 'Failed to save the virtual device context'));
      return env.data;
    },
    onSuccess: (c) => {
      toast.success(`Saved ${c.name}`);
      invalidate(c.id);
    },
  });
}

export function useDeleteVirtualDeviceContext(assetId: string) {
  const invalidate = useInvalidate(assetId);
  return useMutation({
    mutationFn: async (c: VirtualDeviceContext): Promise<VirtualDeviceContext> => {
      const { error } = await api().DELETE('/dcim/virtual-device-contexts/{id}', { params: { path: { id: c.id } } });
      if (error) throw new VdcWriteError(substrateError(error, 'Failed to delete the virtual device context'));
      return c;
    },
    onSuccess: (c) => {
      toast.success(`Deleted ${c.name}`);
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete the virtual device context'),
  });
}
