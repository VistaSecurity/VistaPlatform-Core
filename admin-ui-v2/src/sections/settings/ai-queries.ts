// Settings → AI assistant data layer — TanStack Query over the typed
// admin-service client (/admin/ai and friends), plus the pure helpers the page
// renders from.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type PlatformAISettings = adminServiceComponents['schemas']['PlatformAISettings'];
export type PlatformAIProviderUpdate = adminServiceComponents['schemas']['PlatformAIProviderUpdate'];
export type PlatformAITestResult = adminServiceComponents['schemas']['PlatformAIProviderTestResult'];

export const platformAIKey = ['platform', 'ai'] as const;

function messageOf(error: unknown, fallback: string): string {
  const msg = (error as { error?: unknown } | undefined)?.error;
  return typeof msg === 'string' && msg ? msg : fallback;
}

export function usePlatformAI() {
  return useQuery({
    queryKey: platformAIKey,
    staleTime: 30 * 1000,
    queryFn: async (): Promise<PlatformAISettings> => {
      const { data, error } = await clients.admin.GET('/admin/ai', {});
      if (error || !data) throw new Error('Could not read the AI assistant settings');
      return data;
    },
  });
}

export function useSavePlatformAIProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: PlatformAIProviderUpdate): Promise<PlatformAISettings> => {
      const { data, error } = await clients.admin.PUT('/admin/ai/provider', { body });
      if (error || !data) throw new Error(messageOf(error, 'Could not save the provider'));
      return data;
    },
    onSuccess: (data) => qc.setQueryData(platformAIKey, data),
  });
}

export function useClearPlatformAIProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (): Promise<PlatformAISettings> => {
      const { data, error } = await clients.admin.DELETE('/admin/ai/provider', {});
      if (error || !data) throw new Error(messageOf(error, 'Could not clear the provider'));
      return data;
    },
    onSuccess: (data) => qc.setQueryData(platformAIKey, data),
  });
}

export function useTestPlatformAIProvider() {
  return useMutation({
    mutationFn: async (body: PlatformAIProviderUpdate): Promise<PlatformAITestResult> => {
      const { data, error } = await clients.admin.POST('/admin/ai/provider/test', { body });
      if (error || !data) throw new Error(messageOf(error, 'Could not run the test'));
      return data;
    },
  });
}

export function useSavePlatformAITenantPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { tenant_providers_allowed?: boolean; tenant_private_endpoints_allowed?: boolean }): Promise<PlatformAISettings> => {
      const { data, error } = await clients.admin.PUT('/admin/ai/tenant-policy', { body });
      if (error || !data) throw new Error(messageOf(error, 'Could not save the setting'));
      return data;
    },
    onSuccess: (data) => qc.setQueryData(platformAIKey, data),
  });
}

export const PROVIDER_KIND_LABELS: Record<string, string> = {
  anthropic: 'Anthropic',
  openai_compat: 'OpenAI-compatible',
};

export function providerKindLabel(kind?: string): string {
  if (!kind) return '';
  return PROVIDER_KIND_LABELS[kind] ?? kind;
}

/**
 * The sentence under the page title: which provider answers for a tenant that
 * has none of its own, and where it came from.
 *
 * The three sources read differently because they are changed in three
 * different places: this page, the install's values, and nowhere yet.
 */
export function inEffectSummary(s: PlatformAISettings): { text: string; ok: boolean } {
  if (s.provider_kinds.length === 0) {
    return { text: 'This build has no model clients. Connecting a provider is part of Vista Platform Enterprise.', ok: false };
  }
  if (s.in_effect === 'platform' && s.provider) {
    const what = `${providerKindLabel(s.provider.kind)}${s.provider.model ? ` (${s.provider.model})` : ''}`;
    return s.available
      ? { text: `${what}, set on this page, answers for every organization without a provider of its own.${s.environment ? ' It overrides the one set at install.' : ''}`, ok: true }
      : { text: `${what} is set on this page but is not answering.`, ok: false };
  }
  if (s.in_effect === 'environment' && s.environment) {
    const what = `${providerKindLabel(s.environment.kind)}${s.environment.model ? ` (${s.environment.model})` : ''}`;
    return s.available
      ? { text: `${what}, set at install, answers for every organization without a provider of its own. Setting one here overrides it.`, ok: true }
      : { text: `${what} is set at install but is not answering.`, ok: false };
  }
  return { text: 'No default provider is set. Organizations get AI capabilities only if they connect their own.', ok: false };
}

export type ProviderForm = {
  kind: string;
  baseUrl: string;
  model: string;
  apiKey: string;
  allowPrivate: boolean;
};

/** The form as it opens: what is stored, with the key field always empty. */
export function formFrom(s: PlatformAISettings): ProviderForm {
  const kinds = s.provider_kinds;
  const p = s.provider;
  return {
    kind: p && kinds.includes(p.kind) ? p.kind : (kinds[0] ?? 'anthropic'),
    baseUrl: p?.base_url ?? '',
    model: p?.model ?? '',
    apiKey: '',
    allowPrivate: p?.allow_private_endpoints ?? false,
  };
}

/** What the form refuses before asking the server (which checks it all again). */
export function validateForm(form: ProviderForm, hasSavedKey: boolean, canStoreCredentials: boolean): string | null {
  const url = form.baseUrl.trim();
  if (form.kind === 'openai_compat') {
    if (!url) return 'Enter the endpoint’s base URL.';
    if (!form.model.trim()) return 'Enter the model id the endpoint serves.';
  }
  if (url && !/^https?:\/\/[^\s/]+/i.test(url)) return 'The base URL must start with http:// or https:// and name a host.';
  if (form.kind === 'anthropic' && !form.apiKey.trim() && !hasSavedKey) return 'Enter the API key for this provider.';
  if (form.apiKey.trim() && !canStoreCredentials) {
    return 'This deployment has no encryption key (ENCRYPTION_MASTER_KEY), so an API key cannot be stored.';
  }
  return null;
}

/**
 * The request body. A blank key field with a key already stored OMITS api_key
 * ("keep it" — the server allows that only for the same provider and address);
 * a blank field with nothing stored sends "" ("this endpoint needs no key").
 */
export function requestBody(form: ProviderForm, hasSavedKey: boolean): PlatformAIProviderUpdate {
  const body: PlatformAIProviderUpdate = {
    kind: form.kind as PlatformAIProviderUpdate['kind'],
    base_url: form.baseUrl.trim(),
    model: form.model.trim(),
    allow_private_endpoints: form.allowPrivate,
  };
  const key = form.apiKey.trim();
  if (key || !hasSavedKey) body.api_key = key;
  return body;
}
