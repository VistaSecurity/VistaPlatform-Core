// Query hooks for custom fields (DCIM BUILD_PLAN row 5.1): the tenant's
// definitions and choice sets (`/dcim/custom-fields`,
// `/dcim/custom-field-choice-sets`). <CustomFieldsPanel> reads them to render
// an object's values; Settings → Custom Fields writes them; the query editor
// reads the names for `cf.<name>` autocomplete.
import { useCallback } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import type { inventoryComponents as components } from '@vistasecurity/api-contract';
import { clients } from '../../../lib/clients';
import { substrateError } from './substrate-queries';
import { invalidateAssetDetail } from '../asset-queries';

type S = components['schemas'];
export type CustomField = S['CustomField'];
export type CustomFieldInput = S['CustomFieldCreateInput'];
export type CustomFieldChoiceSet = S['CustomFieldChoiceSet'];
export type CustomFieldChoiceSetInput = S['CustomFieldChoiceSetCreateInput'];
export type CustomFieldType = CustomField['type'];

/** The thirteen types, in the order the type picker lists them. */
export const CUSTOM_FIELD_TYPES: { value: CustomFieldType; label: string }[] = [
  { value: 'text', label: 'Text' }, { value: 'longtext', label: 'Text (long)' },
  { value: 'integer', label: 'Integer' }, { value: 'decimal', label: 'Decimal' },
  { value: 'boolean', label: 'Boolean (true/false)' }, { value: 'date', label: 'Date' },
  { value: 'datetime', label: 'Date & time' }, { value: 'url', label: 'URL' }, { value: 'json', label: 'JSON' },
  { value: 'select', label: 'Selection' }, { value: 'multiselect', label: 'Multiple selection' },
  { value: 'object', label: 'Object' }, { value: 'multiobject', label: 'Multiple objects' },
];

export const customFieldKeys = {
  all: ['dcim-custom-fields'] as const,
  fields: (kind?: ObjectKind) => ['dcim-custom-fields', 'fields', kind ?? '*'] as const,
  sets: () => ['dcim-custom-fields', 'sets'] as const,
};

/** The definitions that apply to `kind` (every definition when omitted). */
export function useCustomFields(kind?: ObjectKind, enabled = true) {
  return useQuery({
    queryKey: customFieldKeys.fields(kind),
    enabled,
    staleTime: 60_000,
    queryFn: async (): Promise<CustomField[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/custom-fields', {
        params: { query: { limit: 1000, ...(kind ? { object_kind: kind } : {}) } },
      });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load custom fields'));
      return data.data ?? [];
    },
  });
}

export function useChoiceSets(enabled = true) {
  return useQuery({
    queryKey: customFieldKeys.sets(),
    enabled,
    staleTime: 60_000,
    queryFn: async (): Promise<CustomFieldChoiceSet[]> => {
      const { data, error } = await clients.inventory.GET('/dcim/custom-field-choice-sets', { params: { query: { limit: 1000 } } });
      if (error || !data) throw new Error(substrateError(error, 'Failed to load choice sets'));
      return data.data ?? [];
    },
  });
}

/** Create, edit or delete a definition; every custom-field read refetches. */
export function useCustomFieldWrite() {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: customFieldKeys.all });
  const create = useMutation({
    mutationFn: async (body: CustomFieldInput): Promise<CustomField> => {
      const { data, error } = await clients.inventory.POST('/dcim/custom-fields', { body });
      if (error || !data) throw new Error(substrateError(error, 'Could not create the field'));
      return data.data;
    },
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: S['CustomFieldUpdateInput'] }): Promise<CustomField> => {
      const { data, error } = await clients.inventory.PATCH('/dcim/custom-fields/{id}', { params: { path: { id } }, body });
      if (error || !data) throw new Error(substrateError(error, 'Could not save the field'));
      return data.data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await clients.inventory.DELETE('/dcim/custom-fields/{id}', { params: { path: { id } } });
      if (error) throw new Error(substrateError(error, 'Could not delete the field'));
    },
    onSuccess: done,
  });
  return { create, update, remove };
}

export function useChoiceSetWrite() {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: customFieldKeys.all });
  const create = useMutation({
    mutationFn: async (body: CustomFieldChoiceSetInput): Promise<CustomFieldChoiceSet> => {
      const { data, error } = await clients.inventory.POST('/dcim/custom-field-choice-sets', { body });
      if (error || !data) throw new Error(substrateError(error, 'Could not create the choice set'));
      return data.data;
    },
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: S['CustomFieldChoiceSetUpdateInput'] }): Promise<CustomFieldChoiceSet> => {
      const { data, error } = await clients.inventory.PATCH('/dcim/custom-field-choice-sets/{id}', { params: { path: { id } }, body });
      if (error || !data) throw new Error(substrateError(error, 'Could not save the choice set'));
      return data.data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const { error } = await clients.inventory.DELETE('/dcim/custom-field-choice-sets/{id}', { params: { path: { id } } });
      if (error) throw new Error(substrateError(error, 'Could not delete the choice set (a field may still use it)'));
    },
    onSuccess: done,
  });
  return { create, update, remove };
}

/** A field's display label: its label, else its name. */
export function fieldLabel(f: Pick<CustomField, 'name' | 'label'>): string {
  return f.label && f.label.trim() ? f.label : f.name;
}

/** Whether a stored value counts as set (null, '' and [] do not). */
export function isSet(v: unknown): boolean {
  if (v === null || v === undefined) return false;
  if (typeof v === 'string') return v.trim() !== '';
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

/** Saves an asset's changed custom fields through PUT /infrastructure-assets
 *  (the asset's own update route, gated assets.update), then refetches it. */
export function useSaveAssetCustomFields(assetId: string) {
  const qc = useQueryClient();
  return useCallback(async (patch: Record<string, unknown>) => {
    const { data, error, response } = await clients.inventory.PUT('/infrastructure-assets/{id}', {
      params: { path: { id: assetId } }, body: { custom_fields: patch },
    });
    if (!response.ok || error || !data) throw new Error(substrateError(error, 'Could not save the custom fields'));
    invalidateAssetDetail(qc, assetId);
  }, [qc, assetId]);
}
