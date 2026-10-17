// Query hooks for the DCIM object substrate (asset-inventory ADR-0010 D5; DCIM
// BUILD_PLAN row 0.3): the change record, journal and tags of any object, by
// object kind and id. Every path below is in the inventory-service spec and
// goes through the generated client.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { errorMessage } from '../../../lib/api-result';

export type ObjectChange = components['schemas']['ObjectChange'];
export type ObjectChangeDetail = components['schemas']['ObjectChangeDetail'];
export type JournalEntry = components['schemas']['JournalEntry'];
export type JournalKind = JournalEntry['kind'];
export type Tag = components['schemas']['Tag'];

export const CHANGES_PAGE_SIZE = 25;
export const JOURNAL_PAGE_SIZE = 25;

/** The server's reason: the ADR-0002 envelope's `error.message`, else the
 *  legacy `{error: "…"}` shape the auth middleware still writes. */
export function substrateError(error: unknown, fallback: string): string {
  if (error && typeof error === 'object') {
    const inner = (error as { error?: unknown }).error;
    if (inner && typeof inner === 'object') {
      const m = (inner as { message?: unknown }).message;
      if (typeof m === 'string' && m.trim()) return m.trim();
    }
  }
  return errorMessage(error) ?? fallback;
}

export const substrateKeys = {
  changes: (kind: ObjectKind, id: string) => ['dcim-changes', kind, id] as const,
  changeLog: (f: ChangeLogFilters) => ['dcim-change-log', f] as const,
  change: (id: string) => ['dcim-change', id] as const,
  journal: (kind: ObjectKind, id: string) => ['dcim-journal', kind, id] as const,
  objectTags: (kind: ObjectKind, id: string) => ['dcim-object-tags', kind, id] as const,
  tags: () => ['dcim-tags'] as const,
};

export interface Page<T> { rows: T[]; total: number }

/** One object's change record, newest first. */
export function useObjectChanges(kind: ObjectKind, id: string | undefined, enabled = true, includeRelated = false) {
  return useQuery({
    queryKey: [...substrateKeys.changes(kind, id ?? ''), includeRelated],
    enabled: !!id && enabled,
    queryFn: async (): Promise<Page<ObjectChange>> => {
      const { data, error } = await clients.inventory.GET('/dcim/changes', {
        params: { query: { object_kind: kind, object_id: id!, limit: CHANGES_PAGE_SIZE, ...(includeRelated ? { include_related: true } : {}) } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load changes'));
      return { rows: data.data ?? [], total: data.pagination?.total ?? (data.data ?? []).length };
    },
  });
}

/** The Inventory → Changes lens's filters; every field is optional. */
export interface ChangeLogFilters {
  object_kind?: ObjectKind;
  q?: string;
  user_name?: string;
  source?: string;
  action?: ObjectChange['action'];
  /** RFC 3339. */
  since?: string;
  until?: string;
  limit: number;
  offset: number;
}

/** The tenant's change log, filtered, newest first (Inventory → Changes). */
export function useChangeLog(filters: ChangeLogFilters) {
  return useQuery({
    queryKey: substrateKeys.changeLog(filters),
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<Page<ObjectChange>> => {
      const query = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined && v !== '')) as ChangeLogFilters;
      const { data, error } = await clients.inventory.GET('/dcim/changes', { params: { query } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load the change log'));
      return { rows: data.data ?? [], total: data.pagination?.total ?? (data.data ?? []).length };
    },
  });
}

/** One change with its field-level diff. */
export function useChangeDetail(id: string | undefined) {
  return useQuery({
    queryKey: substrateKeys.change(id ?? ''),
    enabled: !!id,
    queryFn: async (): Promise<ObjectChangeDetail> => {
      const { data, error } = await clients.inventory.GET('/dcim/changes/{id}', { params: { path: { id: id! } } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load the change'));
      return data.data;
    },
  });
}

/** One object's journal, newest first. */
export function useObjectJournal(kind: ObjectKind, id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: substrateKeys.journal(kind, id ?? ''),
    enabled: !!id && enabled,
    queryFn: async (): Promise<Page<JournalEntry>> => {
      const { data, error } = await clients.inventory.GET('/dcim/objects/{kind}/{id}/journal', {
        params: { path: { kind, id: id! }, query: { limit: JOURNAL_PAGE_SIZE } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load the journal'));
      return { rows: data.data ?? [], total: data.pagination?.total ?? (data.data ?? []).length };
    },
  });
}

export function useAddJournalEntry(kind: ObjectKind, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: { kind: JournalKind; comments: string }): Promise<JournalEntry> => {
      const { data, error } = await clients.inventory.POST('/dcim/objects/{kind}/{id}/journal', {
        params: { path: { kind, id } },
        body: input,
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to add the journal entry'));
      return data.data;
    },
    onSuccess: () => toast.success('Journal entry added'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to add the journal entry'),
    onSettled: () => Promise.all([
      qc.invalidateQueries({ queryKey: substrateKeys.journal(kind, id) }),
      qc.invalidateQueries({ queryKey: substrateKeys.changes(kind, id) }),
    ]),
  });
}

/** The tags on one object. */
export function useObjectTags(kind: ObjectKind, id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: substrateKeys.objectTags(kind, id ?? ''),
    enabled: !!id && enabled,
    queryFn: async (): Promise<Tag[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/objects/{kind}/{id}/tags', {
        params: { path: { kind, id: id! } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load tags'));
      return data.data ?? [];
    },
  });
}

/** The organisation's tag vocabulary. */
export function useTags(enabled = true) {
  return useQuery({
    queryKey: substrateKeys.tags(),
    enabled,
    queryFn: async (): Promise<Tag[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/tags', {});
      if (error || !data) throw new Error(substrateError(error, 'Failed to load tags'));
      return data.data ?? [];
    },
  });
}

/** Replaces an object's tags with exactly `tagIds`. */
export function useSetObjectTags(kind: ObjectKind, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (tagIds: string[]): Promise<Tag[]> => {
      const { data, error } = await clients.inventory.PUT('/dcim/objects/{kind}/{id}/tags', {
        params: { path: { kind, id } },
        body: { tag_ids: tagIds },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to save tags'));
      return data.data ?? [];
    },
    onSuccess: (tags) => {
      qc.setQueryData(substrateKeys.objectTags(kind, id), tags);
      toast.success('Tags saved');
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to save tags'),
    onSettled: () => qc.invalidateQueries({ queryKey: substrateKeys.changes(kind, id) }),
  });
}

export function useCreateTag() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (name: string): Promise<Tag> => {
      const { data, error } = await clients.inventory.POST('/dcim/tags', { body: { name } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to create the tag'));
      return data.data;
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to create the tag'),
    onSettled: () => qc.invalidateQueries({ queryKey: substrateKeys.tags() }),
  });
}
