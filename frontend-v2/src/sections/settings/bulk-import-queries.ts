// Bulk CSV import and export (DCIM BUILD_PLAN row 2.7): the kinds list, the
// dry-run/apply mutation, the template download and the export download.
import { useMutation, useQuery } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type BulkKind = inventoryComponents['schemas']['BulkImportKind'];
export type BulkColumn = inventoryComponents['schemas']['BulkImportColumn'];
export type BulkPlan = inventoryComponents['schemas']['BulkImportPlan'];
export type BulkRow = inventoryComponents['schemas']['BulkImportRow'];

export const BULK_KINDS_KEY = ['settings', 'bulk-import', 'kinds'] as const;

/** The reason in a `{error: {message}}` body, else `fallback`. */
export function bulkError(error: unknown, fallback: string): string {
  if (error && typeof error === 'object') {
    const inner = (error as { error?: unknown }).error;
    if (inner && typeof inner === 'object') {
      const m = (inner as { message?: unknown }).message;
      if (typeof m === 'string' && m.trim()) return m.trim();
    }
    const m = (error as { message?: unknown }).message;
    if (typeof m === 'string' && m.trim()) return m.trim();
  }
  return fallback;
}

/** Importable kinds, in dependency order. */
export function useBulkKinds() {
  return useQuery({
    queryKey: BULK_KINDS_KEY,
    queryFn: async (): Promise<BulkKind[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/import/kinds', {});
      if (error || !data) throw new Error(bulkError(error, 'Failed to load the importable kinds'));
      return data.data;
    },
  });
}

/** Plan (dryRun) or apply a CSV for one kind. */
export function useBulkRun() {
  return useMutation({
    mutationFn: async ({ kind, file, apply }: { kind: string; file: File; apply: boolean }): Promise<BulkPlan> => {
      const text = await file.text();
      const { data, error } = await clients.inventory.POST('/dcim/import', {
        params: { query: { kind, mode: apply ? 'apply' : 'dry_run' } },
        body: text,
        bodySerializer: (b) => b as string,
        headers: { 'Content-Type': 'text/csv' },
      });
      if (error || !data) throw new Error(bulkError(error, apply ? 'The import failed' : 'The file could not be checked'));
      return data.data;
    },
  });
}

/** Save `blob` as `filename` through a transient link. */
export function saveBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export async function downloadTemplate(kind: string): Promise<void> {
  const { data, response, error } = await clients.inventory.GET('/dcim/import/template', {
    params: { query: { kind } }, parseAs: 'blob',
  });
  if (!response.ok || !data) throw new Error(bulkError(error, 'The template could not be downloaded'));
  saveBlob(`${kind}-template.csv`, data);
}

export interface ExportFilters {
  query?: string;
  vrf_id?: string;
  group_id?: string;
  business_unit_id?: string;
  status?: string;
  scope?: string;
}

/** An export template to render the rows through instead of CSV (row 5.5). */
export interface ExportViaTemplate { id: string; file_extension: string }

/** Download a kind's rows as CSV (or through an export template), honouring the page's current filters. */
export async function downloadExport(kind: string, filters: ExportFilters = {}, template?: ExportViaTemplate): Promise<void> {
  const blank = (v: string | undefined) => (v === undefined || v === '' ? undefined : v);
  const { data, response, error } = await clients.inventory.GET('/dcim/export', {
    params: {
      query: {
        kind, format: template ? 'template' : 'csv', template_id: template?.id, query: blank(filters.query), vrf_id: blank(filters.vrf_id), group_id: blank(filters.group_id),
        business_unit_id: blank(filters.business_unit_id), status: blank(filters.status), scope: blank(filters.scope),
      },
    },
    parseAs: 'blob',
  });
  if (!response.ok || !data) throw new Error(bulkError(error, 'The export failed'));
  const stamp = new Date().toISOString().slice(0, 10);
  saveBlob(`vista-${kind}-${stamp}.${template ? template.file_extension : 'csv'}`, data);
}
