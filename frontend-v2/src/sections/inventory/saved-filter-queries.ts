// Saved Filters (DCIM BUILD_PLAN row 5.4): the list and the writes behind the
// Filters menu on a lens and Settings -> Saved Filters. Every path is in the
// inventory-service spec and goes through the generated client.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import { clients } from '../../lib/clients';
import { errorMessage } from '../../lib/api-result';

export type SavedFilter = inventoryComponents['schemas']['SavedFilter'];
export type SavedFilterInput = inventoryComponents['schemas']['SavedFilterInput'];

/** The kinds a filter can be saved for: those with a query catalogue. The
 *  server is the authority and refuses any other; this is the picker's list. */
export const SAVED_FILTER_KINDS: readonly ObjectKind[] = ['asset', 'endpoint', 'interface'];

export const SAVED_FILTERS_KEY = ['dcim-saved-filters'] as const;

export interface SavedFilterList { filters: SavedFilter[]; canShare: boolean }

/** The filters the caller can use, shared first; `kind` narrows to one kind. */
export function useSavedFilters(kind?: ObjectKind, enabled = true) {
  return useQuery({
    queryKey: [...SAVED_FILTERS_KEY, kind ?? 'all'],
    enabled,
    queryFn: async (): Promise<SavedFilterList> => {
      const { data, error } = await clients.inventory.GET('/dcim/saved-filters', {
        params: { query: kind ? { kind } : {} },
      });
      if (error || !data) throw new Error(filterError(error, 'Failed to load saved filters'));
      return { filters: data.data ?? [], canShare: data.can_share === true };
    },
  });
}

/** The server's reason, with the first query diagnostic when the query was
 *  what it refused: "The query is not valid for this kind. unknown field x". */
export function filterError(error: unknown, fallback: string): string {
  const inner = (error as { error?: { message?: unknown; details?: { message?: unknown }[] } } | null)?.error;
  if (inner && typeof inner === 'object') {
    const msg = typeof inner.message === 'string' ? inner.message.trim() : '';
    const first = inner.details?.[0]?.message;
    if (msg) return typeof first === 'string' && first ? `${msg} ${first}` : msg;
  }
  return errorMessage(error) ?? fallback;
}

function useInvalidate() {
  const qc = useQueryClient();
  return () => { void qc.invalidateQueries({ queryKey: SAVED_FILTERS_KEY }); };
}

export function useSaveFilter() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: async (body: SavedFilterInput): Promise<SavedFilter> => {
      const { data, error } = await clients.inventory.POST('/dcim/saved-filters', { body });
      if (error || !data) throw new Error(filterError(error, 'Failed to save the filter'));
      return data.data;
    },
    onSuccess: (f) => toast.success(`Saved filter “${f.name}”`),
    onSettled: invalidate,
  });
}

export function useUpdateFilter() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: SavedFilterInput }): Promise<SavedFilter> => {
      const { data, error } = await clients.inventory.PUT('/dcim/saved-filters/{id}', { params: { path: { id } }, body });
      if (error || !data) throw new Error(filterError(error, 'Failed to save the filter'));
      return data.data;
    },
    onSuccess: (f) => toast.success(`Updated “${f.name}”`),
    onSettled: invalidate,
  });
}

export function useDeleteFilter() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.inventory.DELETE('/dcim/saved-filters/{id}', { params: { path: { id } } });
      if (error) throw new Error(filterError(error, 'Failed to delete the filter'));
    },
    onSuccess: () => toast.success('Filter deleted'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete the filter'),
    onSettled: invalidate,
  });
}

/** What the Filters menu should show. A failed read is not "no filters yet". */
export function savedFiltersMenuState(
  q: { isLoading: boolean; isError: boolean },
  count: number,
): 'loading' | 'failed' | 'empty' | 'list' {
  if (q.isError) return 'failed';
  if (q.isLoading) return 'loading';
  return count === 0 ? 'empty' : 'list';
}
