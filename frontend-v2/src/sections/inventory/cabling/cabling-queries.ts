// Query hooks for the Cabling surfaces (DCIM BUILD_PLAN row 3.4; asset-
// inventory ADR-0010 D6/D10): the tenant-wide cable list behind Inventory →
// Cabling, one cable, editing a cable, a port's trace and the per-interface
// crypto posture behind the faceplate's overlay. Every path is in the
// inventory-service spec and goes through the generated client.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components, inventoryPaths } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError, substrateKeys } from '../dcim/substrate-queries';
import { cableKeys, CableWriteError, type Cable, type CableCreateInput } from '../dcim/cable-queries';

export type CableUpdateInput = components['schemas']['CableUpdateInput'];
export type CablePaths = components['schemas']['CablePaths'];
export type CablePath = components['schemas']['CablePath'];
export type CablePathNode = components['schemas']['CablePathNode'];
export type CablePathStep = components['schemas']['CablePathStep'];
export type AssetInterfacePosture = components['schemas']['AssetInterfacePosture'];
export type InterfacePosture = components['schemas']['InterfacePosture'];

/** The lens's server-side filters (GET /dcim/cables). */
export interface CableFilters {
  site_id?: string;
  rack_id?: string;
  asset_id?: string;
  type?: string;
  operational_status?: string;
  status?: string;
  termination_kind?: string;
  q?: string;
}

export const CABLE_LIST_PAGE = 200;

type CableQuery = NonNullable<inventoryPaths['/dcim/cables']['get']['parameters']['query']>;

export const cablingKeys = {
  list: (f: CableFilters, offset: number) => ['dcim-cables', 'list', f, offset] as const,
  one: (id: string) => ['dcim-cables', 'one', id] as const,
  trace: (route: TraceRoute, id: string) => ['dcim-trace', route, id] as const,
  posture: (assetId: string) => ['dcim-interface-posture', assetId] as const,
};

export interface CablePage { rows: Cable[]; total: number }

export function useCableList(filters: CableFilters, offset = 0) {
  return useQuery({
    queryKey: cablingKeys.list(filters, offset),
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }): Promise<CablePage> => {
      const query: CableQuery = { limit: CABLE_LIST_PAGE, offset };
      for (const [k, v] of Object.entries(filters) as [keyof CableFilters, string | undefined][]) if (v) (query as Record<string, unknown>)[k] = v;
      const { data, error } = await clients.inventory.GET('/dcim/cables', { signal, params: { query } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load cables'));
      return { rows: data.data ?? [], total: data.pagination?.total ?? (data.data ?? []).length };
    },
  });
}

export function useCable(id: string | null) {
  return useQuery({
    queryKey: cablingKeys.one(id ?? ''),
    enabled: !!id,
    queryFn: async (): Promise<Cable> => {
      const { data, error } = await clients.inventory.GET('/dcim/cables/{id}', { params: { path: { id: id! } } });
      if (error || !data?.data) throw new Error(substrateError(error, 'Failed to load the cable'));
      return data.data;
    },
  });
}

/** Every cable view reads the same rows: one write refreshes all of them. */
function useInvalidateCabling() {
  const qc = useQueryClient();
  return (id?: string) => {
    void qc.invalidateQueries({ queryKey: cableKeys.all });
    void qc.invalidateQueries({ queryKey: ['dcim-ports'] });
    void qc.invalidateQueries({ queryKey: ['dcim-interfaces'] });
    void qc.invalidateQueries({ queryKey: ['dcim-trace'] });
    if (id) void qc.invalidateQueries({ queryKey: substrateKeys.changes('cable', id) });
  };
}

export function useUpdateCable() {
  const invalidate = useInvalidateCabling();
  return useMutation({
    mutationFn: async ({ id, patch }: { id: string; patch: CableUpdateInput }): Promise<Cable> => {
      const { data, error } = await clients.inventory.PATCH('/dcim/cables/{id}', { params: { path: { id } }, body: patch });
      if (error || !data?.data) throw new CableWriteError(substrateError(error, 'Failed to save the cable'));
      return data.data;
    },
    onSuccess: (c) => {
      toast.success('Cable saved');
      invalidate(c.id);
    },
  });
}

/** A bare create (no toast, no invalidation per call): the bulk editor applies
 *  many in a row and refreshes once at the end. */
export async function createCable(body: CableCreateInput): Promise<Cable> {
  const { data, error } = await clients.inventory.POST('/dcim/cables', { body });
  if (error || !data?.data) throw new CableWriteError(substrateError(error, 'Failed to connect the cable'));
  return data.data;
}

export function useRefreshCabling() {
  return useInvalidateCabling();
}

/** The six trace routes, by termination kind. */
export const TRACE_ROUTES = {
  interface: 'interfaces',
  front_port: 'front-ports',
  rear_port: 'rear-ports',
  console_port: 'console-ports',
  console_server_port: 'console-server-ports',
  circuit_termination: 'circuit-terminations',
} as const;
export type TraceKind = keyof typeof TRACE_ROUTES;
export type TraceRoute = (typeof TRACE_ROUTES)[TraceKind];

export const isTraceKind = (k: string): k is TraceKind => k in TRACE_ROUTES;

export function useTrace(kind: TraceKind | null, id: string | null) {
  const route = kind ? TRACE_ROUTES[kind] : 'interfaces';
  return useQuery({
    queryKey: cablingKeys.trace(route, id ?? ''),
    enabled: !!kind && !!id,
    queryFn: async (): Promise<CablePaths> => {
      const path = `/dcim/${route}/{id}/trace` as '/dcim/interfaces/{id}/trace';
      const { data, error } = await clients.inventory.GET(path, { params: { path: { id: id! } } });
      if (error || !data?.data) throw new Error(substrateError(error, 'Failed to trace the cable path'));
      return data.data;
    },
  });
}

/** Per-interface crypto posture for the faceplate overlay. */
export function useInterfacePosture(assetId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: cablingKeys.posture(assetId ?? ''),
    enabled: !!assetId && enabled,
    staleTime: 60_000,
    queryFn: async (): Promise<AssetInterfacePosture> => {
      const { data, error } = await clients.inventory.GET('/dcim/assets/{id}/interface-posture', { params: { path: { id: assetId! } } });
      if (error || !data?.data) throw new Error(substrateError(error, 'Failed to load the crypto posture'));
      return data.data;
    },
  });
}
