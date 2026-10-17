// Query hooks for cables (DCIM BUILD_PLAN row 3.2; asset-inventory ADR-0010
// D6): the cables on one asset's components, connect and disconnect. Every
// path is in the inventory-service spec and goes through the generated client.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError } from './substrate-queries';

export type Cable = components['schemas']['Cable'];
export type CableCreateInput = components['schemas']['CableCreateInput'];
export type CableTerminationRef = components['schemas']['CableTerminationRef'];
export type CableTerminationKind = components['schemas']['CableTerminationKind'];

/** One asset has at most a few hundred cabled ports; one page holds them. */
export const CABLES_PAGE_SIZE = 1000;

export const cableKeys = {
  all: ['dcim-cables'] as const,
  asset: (assetId: string) => ['dcim-cables', assetId] as const,
};

/** What a cabled port shows: the cable and the other end's terminations. */
export interface CableEnd {
  cable: Cable;
  far: CableTerminationRef[];
}

/** termination_id → its cable and far end, for one asset's cables. */
export type CableIndex = Map<string, CableEnd>;

export function indexCables(cables: Cable[]): CableIndex {
  const out: CableIndex = new Map();
  for (const c of cables) {
    for (const t of c.a_terminations) out.set(t.termination_id, { cable: c, far: c.b_terminations });
    for (const t of c.b_terminations) out.set(t.termination_id, { cable: c, far: c.a_terminations });
  }
  return out;
}

export function useAssetCables(assetId: string | undefined) {
  return useQuery({
    queryKey: cableKeys.asset(assetId ?? ''),
    enabled: !!assetId,
    queryFn: async (): Promise<CableIndex> => {
      const { data, error } = await clients.inventory.GET('/dcim/cables', {
        params: { query: { asset_id: assetId!, limit: CABLES_PAGE_SIZE } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load cables'));
      return indexCables(data.data ?? []);
    },
  });
}

/** A port's own row carries cable_id: every list that shows one must refresh. */
function useInvalidateCabling() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: cableKeys.all });
    void qc.invalidateQueries({ queryKey: ['dcim-ports'] });
    void qc.invalidateQueries({ queryKey: ['dcim-interfaces'] });
  };
}

export class CableWriteError extends Error {}

export function useConnectCable() {
  const invalidate = useInvalidateCabling();
  return useMutation({
    mutationFn: async (body: CableCreateInput): Promise<Cable> => {
      const { data, error } = await clients.inventory.POST('/dcim/cables', { body });
      if (error || !data?.data) throw new CableWriteError(substrateError(error, 'Failed to connect the cable'));
      return data.data;
    },
    onSuccess: () => {
      toast.success('Cable connected');
      invalidate();
    },
  });
}

export function useDisconnectCable() {
  const invalidate = useInvalidateCabling();
  return useMutation({
    mutationFn: async (cableId: string): Promise<void> => {
      const { error } = await clients.inventory.DELETE('/dcim/cables/{id}', { params: { path: { id: cableId } } });
      if (error) throw new CableWriteError(substrateError(error, 'Failed to disconnect the cable'));
    },
    onSuccess: () => {
      toast.success('Cable disconnected');
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to disconnect the cable'),
  });
}

/** "asset:port" for a far end, the way the Cable column reads it. */
export function farEndText(far: CableTerminationRef[]): string {
  if (far.length === 0) return 'nothing (dangling)';
  const first = far[0];
  const where = first.asset_name ?? (first.termination_kind === 'circuit_termination' ? 'circuit' : 'unknown asset');
  const more = far.length > 1 ? ` +${far.length - 1}` : '';
  return `${where}:${first.name ?? '?'}${more}`;
}

/** Proposed cables (DCIM row 3.3): LLDP / CDP neighbours between two known
 *  interfaces, measured and pending, waiting in Discovery → Approvals. */
export const PROPOSED_CABLES_PAGE_SIZE = 100;

export function useProposedCables() {
  return useQuery({
    queryKey: [...cableKeys.all, 'proposed'] as const,
    queryFn: async (): Promise<{ rows: Cable[]; total: number }> => {
      const { data, error } = await clients.inventory.GET('/dcim/cables', {
        params: { query: { status: 'pending', limit: PROPOSED_CABLES_PAGE_SIZE } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load proposed cables'));
      return { rows: data.data ?? [], total: data.pagination?.total ?? (data.data ?? []).length };
    },
  });
}

/** Approve (→ active, paths recomputed) or reject (→ rejected) a proposal. */
export function useDecideCable() {
  const invalidate = useInvalidateCabling();
  return useMutation({
    mutationFn: async ({ id, approve }: { id: string; approve: boolean }): Promise<Cable> => {
      const path = approve ? '/dcim/cables/{id}/approve' : '/dcim/cables/{id}/reject';
      const { data, error } = await clients.inventory.POST(path, { params: { path: { id } } });
      if (error || !data?.data) throw new CableWriteError(substrateError(error, `Failed to ${approve ? 'approve' : 'reject'} the cable`));
      return data.data;
    },
    onSuccess: (_c, v) => {
      toast.success(v.approve ? 'Cable approved' : 'Cable rejected');
      invalidate();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Request failed'),
  });
}

/** "asset:port" for one end of a cable. */
export function endText(end: CableTerminationRef[]): string {
  return farEndText(end);
}

/** The protocol that proposed a measured cable, as the label carries it. */
export function proposedBy(c: Cable): string {
  const l = (c.label ?? '').toLowerCase();
  return l === 'cdp' ? 'CDP' : l === 'lldp' ? 'LLDP' : 'a neighbour table';
}
