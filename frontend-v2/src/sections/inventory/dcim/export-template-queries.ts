// Query hooks for export templates (DCIM BUILD_PLAN row 5.5): the Settings list
// and editor, the preview, and the per-kind list the Export button offers.
// Every path is in the inventory-service spec and goes through the generated client.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { bulkError } from '../../settings/bulk-import-queries';
import { substrateError } from './substrate-queries';

type S = components['schemas'];
export type ExportTemplate = S['ExportTemplate'];
export type ExportTemplateInput = S['ExportTemplateCreateInput'];

export const exportTemplateKeys = {
  all: () => ['dcim-export-templates'] as const,
  list: (kind?: string) => ['dcim-export-templates', kind ?? 'all'] as const,
};

/** The tenant's templates, or only those offered for `kind`. */
export function useExportTemplates(kind?: string, enabled = true) {
  return useQuery({
    queryKey: exportTemplateKeys.list(kind),
    enabled,
    queryFn: async (): Promise<ExportTemplate[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/export-templates', {
        params: { query: { limit: 1000, ...(kind ? { object_kind: kind } : {}) } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load export templates'));
      return data.data ?? [];
    },
  });
}

export function useExportTemplateWrite() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: exportTemplateKeys.all() });
  const create = useMutation({
    mutationFn: async (body: ExportTemplateInput): Promise<ExportTemplate> => {
      const { data, error } = await clients.inventory.POST('/dcim/export-templates', { body });
      if (error || !data) throw new Error(substrateError(error, 'Failed to create the export template'));
      return data.data;
    },
    onSuccess: () => toast.success('Export template created'),
    onSettled: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Partial<ExportTemplateInput> }): Promise<ExportTemplate> => {
      const { data, error } = await clients.inventory.PATCH('/dcim/export-templates/{id}', { params: { path: { id } }, body });
      if (error || !data) throw new Error(substrateError(error, 'Failed to save the export template'));
      return data.data;
    },
    onSuccess: () => toast.success('Export template saved'),
    onSettled: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await clients.inventory.DELETE('/dcim/export-templates/{id}', { params: { path: { id } } });
      if (error) throw new Error(substrateError(error, 'Failed to delete the export template'));
    },
    onSuccess: () => toast.success('Export template deleted'),
    onSettled: invalidate,
  });
  return { create, update, remove };
}

/** Renders an unsaved template body over the first five rows of `kind`. */
export function usePreviewExportTemplate() {
  return useMutation({
    mutationFn: async ({ kind, template }: { kind: string; template: string }): Promise<{ output: string; rows: number }> => {
      const { data, error } = await clients.inventory.POST('/dcim/export/preview', { body: { kind, template } });
      if (error || !data) throw new Error(bulkError(error, 'The preview failed'));
      return data.data;
    },
  });
}
