// Query hooks for config contexts (DCIM BUILD_PLAN row 5.3): the Settings list
// and editor, and the asset page's rendered config. Every path is in the
// inventory-service spec and goes through the generated client.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError, useTags } from './substrate-queries';
import { useBusinessUnits } from '../../settings/business-units-queries';

type S = components['schemas'];
export type ConfigContext = S['ConfigContext'];
export type ConfigContextInput = S['ConfigContextCreateInput'];
export type RenderedConfigContext = S['RenderedConfigContext'];

/** The assignment dimensions the server matches today, with their labels. */
export const CONFIG_CONTEXT_DIMENSIONS = [
  { key: 'locations', label: 'Locations' },
  { key: 'device_types', label: 'Device types' },
  { key: 'device_roles', label: 'Device roles' },
  { key: 'platforms', label: 'Platforms' },
  { key: 'business_units', label: 'Business units' },
  { key: 'tags', label: 'Tags' },
] as const;
export type ConfigContextDimension = (typeof CONFIG_CONTEXT_DIMENSIONS)[number]['key'];

export const configContextKeys = {
  list: () => ['dcim-config-contexts'] as const,
  asset: (id: string) => ['dcim-asset-config-context', id] as const,
};

export function useConfigContexts(enabled = true) {
  return useQuery({
    queryKey: configContextKeys.list(),
    enabled,
    queryFn: async (): Promise<ConfigContext[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/config-contexts', { params: { query: { limit: 1000 } } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load config contexts'));
      return data.data ?? [];
    },
  });
}

/** The asset's merged config and the contexts that produced it. */
export function useAssetConfigContext(assetId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: configContextKeys.asset(assetId ?? ''),
    enabled: !!assetId && enabled,
    queryFn: async (): Promise<RenderedConfigContext> => {
      const { data, error } = await clients.inventory.GET('/dcim/assets/{id}/config-context', { params: { path: { id: assetId! } } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to render the config context'));
      return data.data;
    },
  });
}

export function useConfigContextWrite() {
  const qc = useQueryClient();
  const invalidate = () => Promise.all([
    qc.invalidateQueries({ queryKey: configContextKeys.list() }),
    qc.invalidateQueries({ queryKey: ['dcim-asset-config-context'] }),
  ]);
  const create = useMutation({
    mutationFn: async (body: ConfigContextInput): Promise<ConfigContext> => {
      const { data, error } = await clients.inventory.POST('/dcim/config-contexts', { body });
      if (error || !data) throw new Error(substrateError(error, 'Failed to create the config context'));
      return data.data;
    },
    onSuccess: () => toast.success('Config context created'),
    onSettled: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Partial<ConfigContextInput> }): Promise<ConfigContext> => {
      const { data, error } = await clients.inventory.PATCH('/dcim/config-contexts/{id}', { params: { path: { id } }, body });
      if (error || !data) throw new Error(substrateError(error, 'Failed to save the config context'));
      return data.data;
    },
    onSuccess: () => toast.success('Config context saved'),
    onSettled: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await clients.inventory.DELETE('/dcim/config-contexts/{id}', { params: { path: { id } } });
      if (error) throw new Error(substrateError(error, 'Failed to delete the config context'));
    },
    onSuccess: () => toast.success('Config context deleted'),
    onSettled: invalidate,
  });
  return { create, update, remove };
}

export interface DimensionOption { id: string; label: string }

/** The pickable values of one assignment dimension. */
export function useDimensionOptions(dim: ConfigContextDimension, enabled = true) {
  const bus = useBusinessUnits(enabled && dim === 'business_units');
  const tags = useTags(enabled && dim === 'tags');
  const catalogue = useQuery({
    queryKey: ['dcim-config-context-options', dim],
    enabled: enabled && dim !== 'business_units' && dim !== 'tags',
    queryFn: async (): Promise<DimensionOption[]> => {
      const q = { params: { query: { limit: 1000 } } };
      if (dim === 'locations') {
        // Row 2.1 moved locations under /dcim/locations (site-scoped tree).
        const { data, error } = await clients.inventory.GET('/dcim/locations', { params: { query: {} } });
        if (error || !data) throw new Error('Failed to load locations');
        return (data.locations ?? []).map((l) => ({ id: l.id, label: l.name }));
      }
      if (dim === 'device_types') {
        const { data, error } = await clients.inventory.GET('/dcim/device-types', q);
        if (error || !data) throw new Error('Failed to load device types');
        return (data.data ?? []).map((d) => ({ id: d.id, label: d.model }));
      }
      if (dim === 'device_roles') {
        const { data, error } = await clients.inventory.GET('/dcim/device-roles', q);
        if (error || !data) throw new Error('Failed to load device roles');
        return (data.data ?? []).map((d) => ({ id: d.id, label: d.name }));
      }
      const { data, error } = await clients.inventory.GET('/dcim/platforms', q);
      if (error || !data) throw new Error('Failed to load platforms');
      return (data.data ?? []).map((d) => ({ id: d.id, label: d.name }));
    },
  });
  if (dim === 'business_units') {
    return { options: (bus.data ?? []).map((b) => ({ id: b.id, label: b.name })), isLoading: bus.isLoading, isError: bus.isError };
  }
  if (dim === 'tags') {
    return { options: (tags.data ?? []).map((t) => ({ id: t.id, label: t.name })), isLoading: tags.isLoading, isError: tags.isError };
  }
  return { options: catalogue.data ?? [], isLoading: catalogue.isLoading, isError: catalogue.isError };
}
