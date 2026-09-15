// Typed query hooks for the relationship surface (ADR-0003, workstream 2.8).
//
// Everything goes through the generated inventory-service client, like the rest
// of this UI. Every path below exists in the schema.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { clients } from '../../lib/clients';
import { errorMessage } from './asset-queries';
import type { Impact, Neighbourhood, Relationship, RelationshipType } from './relationships';
import type { TopologyPayload } from './topology-model';

export const RELATIONSHIPS_PAGE_SIZE = 100;
export const RELATIONSHIP_PROPOSALS_PAGE_SIZE = 50;

/** One page of an asset's edges, plus how many there are altogether. */
export interface RelationshipPage {
  relationships: Relationship[];
  /** Every edge on this asset — NOT the length of `relationships`. */
  total: number;
  limit: number;
  offset: number;
}

export function readRelationshipPage(data: {
  relationships?: Relationship[];
  total?: number;
  limit?: number;
  offset?: number;
} | undefined): RelationshipPage {
  const relationships = data?.relationships ?? [];
  return {
    relationships,
    // The fallback is for an envelope missing the field entirely; a real 0 is
    // still 0, because `??` does not treat it as missing.
    total: data?.total ?? relationships.length,
    limit: data?.limit ?? RELATIONSHIPS_PAGE_SIZE,
    offset: data?.offset ?? 0,
  };
}

/**
 * One asset's relationships, both directions.
 *
 * `rejected` edges are excluded by the server unless asked for by name, so this
 * is what a person can act on rather than everything the table has ever held.
 */
export function useAssetRelationships(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['asset-relationships', id],
    enabled: !!id && enabled,
    queryFn: async (): Promise<RelationshipPage> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/relationships', {
        params: { path: { id: id! }, query: { direction: 'both', limit: RELATIONSHIPS_PAGE_SIZE } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load relationships');
      return readRelationshipPage(data);
    },
  });
}

/**
 * The neighbourhood graph.
 *
 * THE SEAM FOR THE MAP (workstream 2.9). Nothing here renders a graph — the tab
 * uses the node and edge counts — but the hook returns the whole payload,
 * `truncated` and the caps included, so `@xyflow/react` can be dropped on top
 * of this exact data without a second endpoint or a second cache key.
 */
export function useAssetNeighbourhood(
  id: string | undefined,
  opts: { depth?: number; includePending?: boolean; enabled?: boolean } = {},
) {
  const depth = opts.depth ?? 2;
  const includePending = opts.includePending ?? false;
  return useQuery({
    queryKey: ['asset-neighbourhood', id, depth, includePending],
    enabled: !!id && (opts.enabled ?? true),
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<Neighbourhood> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/neighbourhood', {
        params: {
          path: { id: id! },
          query: { depth, ...(includePending ? { include_pending: true } : {}) },
        },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load the neighbourhood');
      return data.neighbourhood;
    },
  });
}

/** The impact closure — "what depends on this", or what this rests on. */
export function useAssetImpact(
  id: string | undefined,
  direction: 'downstream' | 'upstream' = 'downstream',
  enabled = true,
) {
  return useQuery({
    queryKey: ['asset-impact', id, direction],
    enabled: !!id && enabled,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<Impact> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/impact', {
        params: { path: { id: id! }, query: { direction } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load impact');
      return data.impact;
    },
  });
}

/** Invalidate everything an edge change can move: the asset's own list, any
 *  neighbourhood or impact it appears in, and the proposal queue. */
function invalidateRelationships(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: ['asset-relationships'] });
  void qc.invalidateQueries({ queryKey: ['asset-neighbourhood'] });
  void qc.invalidateQueries({ queryKey: ['asset-impact'] });
  void qc.invalidateQueries({ queryKey: ['discovery', 'relationship-proposals'] });
}

/** Declare an edge from this asset. */
export function useCreateRelationship(assetId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: {
      type: RelationshipType;
      peerAssetId: string;
      direction: 'out' | 'in';
    }): Promise<Relationship> => {
      const { data, error } = await clients.inventory.POST('/infrastructure-assets/{id}/relationships', {
        params: { path: { id: assetId! } },
        body: {
          type: input.type,
          peer_asset_id: input.peerAssetId,
          direction: input.direction,
        },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to add the relationship');
      return data.relationship;
    },
    onSuccess: (e) => toast.success(
      e.status === 'pending'
        // A declared edge against an unapproved asset is pending, and saying so
        // is the difference between "it did not work" and "it is waiting".
        ? 'Relationship added — pending until the other asset is approved'
        : 'Relationship added',
    ),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to add the relationship'),
    onSettled: () => invalidateRelationships(qc),
  });
}

/** Delete a DECLARED edge. The server answers 409 for anything else, and the
 *  message it sends is what the toast shows — it says why. */
export function useDeleteRelationship(assetId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (edgeId: string) => {
      const { error } = await clients.inventory.DELETE('/infrastructure-assets/{id}/relationships/{edgeId}', {
        params: { path: { id: assetId!, edgeId } },
      });
      if (error) throw new Error(errorMessage(error) ?? 'Failed to remove the relationship');
    },
    onSuccess: () => toast.success('Relationship removed'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to remove the relationship'),
    onSettled: () => invalidateRelationships(qc),
  });
}

// ------------------------------------------------------- proposals (queue) --

/** One page of relationship proposals, plus the tenant's whole count. */
export interface RelationshipProposalPage {
  proposals: Relationship[];
  /** Every pending proposal in the tenant — NOT the page length. */
  total: number;
  limit: number;
  offset: number;
}

export function readRelationshipProposalPage(data: {
  relationship_proposals?: Relationship[];
  total?: number;
  limit?: number;
  offset?: number;
} | undefined): RelationshipProposalPage {
  const proposals = data?.relationship_proposals ?? [];
  return {
    proposals,
    total: data?.total ?? proposals.length,
    limit: data?.limit ?? RELATIONSHIP_PROPOSALS_PAGE_SIZE,
    offset: data?.offset ?? 0,
  };
}

/**
 * The pending relationship proposals.
 *
 * These are the edges nothing will ever promote on its own: both ends are
 * already approved, so no asset decision will resolve them. Most are `inferred`
 * — the platform's own guess, which ADR-0003 D3 says a person has to sign off.
 */
export function useRelationshipProposals(enabled = true, offset = 0) {
  return useQuery({
    queryKey: ['discovery', 'relationship-proposals', offset],
    enabled,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<RelationshipProposalPage> => {
      const { data, error } = await clients.inventory.GET('/approvals/relationships', {
        params: { query: { status: 'pending', limit: RELATIONSHIP_PROPOSALS_PAGE_SIZE, offset } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load relationship proposals');
      return readRelationshipProposalPage(data);
    },
  });
}

/** Accept or reject one proposal. */
export function useDecideRelationshipProposal() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: { id: string; action: 'accept' | 'reject' }) => {
      const path = input.action === 'accept'
        ? '/approvals/relationships/{edgeId}/accept' as const
        : '/approvals/relationships/{edgeId}/reject' as const;
      const { error } = await clients.inventory.POST(path, {
        params: { path: { edgeId: input.id } },
      });
      if (error) throw new Error(errorMessage(error) ?? `Failed to ${input.action} the relationship`);
      return input;
    },
    onSuccess: (r) => toast.success(r.action === 'accept' ? 'Relationship accepted' : 'Relationship rejected'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to decide the relationship'),
    onSettled: () => invalidateRelationships(qc),
  });
}

/**
 * The tenant-wide topology (ADR-0006 D4 second half, workstream 3.8).
 *
 * One call, no paging: a hierarchy is not a list, and paging one is how a
 * client comes to render half a tree without knowing it. The server bounds the
 * answer and REPORTS the bound (`truncated`, `total_nodes`, `total_edges`), so
 * a large estate is told rather than shown less.
 *
 * Cached for a minute. The tree moves when assets are discovered or
 * re-segmented, neither of which is a second-by-second event.
 */
export function useAssetTopology(enabled = true) {
  return useQuery({
    queryKey: ['inventory', 'topology'],
    enabled,
    queryFn: async (): Promise<TopologyPayload> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/topology', {});
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load the topology');
      return data.topology;
    },
    staleTime: 60_000,
  });
}
