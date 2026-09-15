// Class proposals — the fourth row kind on the Approvals queue (ADR-0006 D6,
// workstream 2.10b).
//
// A class proposal is raised when the curated classification rules argue a class
// for an asset that already has a different one, or when two rules contradict
// each other. It is NOT how a newly discovered asset gets a class: that asset is
// created with the rule-derived class already on it and waits in this same queue
// as an asset, so approving it approves the class too.
//
// Read and write live here rather than beside the relationship queries because
// this section is the only consumer, and keeping it self-contained is what lets
// the Approvals page grow a row kind without four files moving at once.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { QueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { clients } from '../../lib/clients';
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type ClassProposal = inventoryComponents['schemas']['ClassProposal'];
export type ClassOption = inventoryComponents['schemas']['ClassOption'];
export type ClassificationRuleRef = inventoryComponents['schemas']['ClassificationRuleRef'];
/** One feature contribution behind a class the learned classifier proposed
 *  (workstream 4.2). The score IS the sum of these, so the list is the model's
 *  arithmetic rather than a guess at its reasoning. */
export type ClassModelReason = inventoryComponents['schemas']['ClassModelReason'];

/** The server's page size. Stated here so the UI's "of N" line and the server
 *  agree about what a page is. */
export const CLASS_PROPOSALS_PAGE_SIZE = 50;

/** One page of class proposals, plus the tenant's whole count. */
export interface ClassProposalPage {
  proposals: ClassProposal[];
  /** Every pending proposal in the tenant — NOT the page length. */
  total: number;
  limit: number;
  offset: number;
}

export function readClassProposalPage(data: {
  class_proposals?: ClassProposal[];
  total?: number;
  limit?: number;
  offset?: number;
} | undefined): ClassProposalPage {
  const proposals = data?.class_proposals ?? [];
  return {
    proposals,
    // `total` and not `proposals.length`: the array stops at the page size, and
    // reading the length as the count is how the merge queue once told a tenant
    // with 132 proposals that it had 50.
    total: data?.total ?? proposals.length,
    limit: data?.limit ?? CLASS_PROPOSALS_PAGE_SIZE,
    offset: data?.offset ?? 0,
  };
}

function errorMessage(error: unknown): string | undefined {
  if (error && typeof error === 'object') {
    const e = error as { message?: string; error?: string };
    return e.message ?? e.error;
  }
  return undefined;
}

/** The pending class proposals. */
export function useClassProposals(enabled = true, offset = 0) {
  return useQuery({
    queryKey: ['discovery', 'class-proposals', offset],
    enabled,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<ClassProposalPage> => {
      const { data, error } = await clients.inventory.GET('/approvals/classes', {
        params: { query: { status: 'pending', limit: CLASS_PROPOSALS_PAGE_SIZE, offset } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load class proposals');
      return readClassProposalPage(data);
    },
  });
}

function invalidateClassProposals(qc: QueryClient) {
  void qc.invalidateQueries({ queryKey: ['discovery', 'class-proposals'] });
  // Accepting one changes the asset's class, so anything showing a class is
  // stale — the pending list, the inventory, the asset page.
  void qc.invalidateQueries({ queryKey: ['discovery', 'pending-assets'] });
  void qc.invalidateQueries({ queryKey: ['inventory'] });
}

/**
 * Accept or reject one proposal.
 *
 * `classKey` is required only for a proposal that offers a CHOICE — the rules
 * conflicted, so there is no single class to take and the server refuses to pick
 * one. For an ordinary proposal it is omitted and the server takes the class the
 * rules argued.
 */
export function useDecideClassProposal() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: { id: string; action: 'accept' | 'reject'; classKey?: string }) => {
      if (input.action === 'accept') {
        const { error } = await clients.inventory.POST('/approvals/classes/{id}/accept', {
          params: { path: { id: input.id } },
          body: input.classKey ? { class_key: input.classKey } : {},
        });
        if (error) throw new Error(errorMessage(error) ?? 'Failed to accept the class');
      } else {
        const { error } = await clients.inventory.POST('/approvals/classes/{id}/reject', {
          params: { path: { id: input.id } },
        });
        if (error) throw new Error(errorMessage(error) ?? 'Failed to reject the class');
      }
      return input;
    },
    onSuccess: (r) => toast.success(r.action === 'accept' ? 'Class applied' : 'Class proposal rejected'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to decide the class'),
    onSettled: () => invalidateClassProposals(qc),
  });
}
