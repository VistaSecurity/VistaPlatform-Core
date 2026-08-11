// VISTA Operations — Security & Trust: audit/activity typed query+mutation hooks.
// Every call goes through the generated typed client (`clients.audit`,
// @vistasecurity/api-contract); no hand-rolled fetch/axios. Shared by the three
// trust sub-pages that came from the dissolved Audit section: Activity Log,
// Retention, and SIEM Export. (The old Audit Alerts / Alert Rules / Compliance
// Reports sub-views were cut in the Governance re-roll — see.)
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { assertEditionPresent, editionAwareRetry, isEditionUnavailable } from '@vistasecurity/primitives/features';
import type { auditServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type ActivityLog = auditServiceComponents['schemas']['ActivityLog'];
export type RetentionPolicy = auditServiceComponents['schemas']['RetentionPolicy'];
export type RetentionPolicyInput = auditServiceComponents['schemas']['RetentionPolicyInput'];
export type SIEMIntegration = auditServiceComponents['schemas']['SIEMIntegration'];
export type SIEMIntegrationInput = auditServiceComponents['schemas']['SIEMIntegrationInput'];

export function errMsg(e: unknown, fallback = 'Action failed'): string {
  return e instanceof Error ? e.message : fallback;
}

/* ----------------------------- Activity log ------------------------------ */

/**
 * Server-side filter shape for POST /activity-logs/query — the typed `filters`
 * body, derived from the spec (snake_case, all optional). Now that the backend
 * binds these (json tags on ActivityLogFilters), category / user-type / tenant
 * scope / impersonation all filter server-side.
 */
export type ActivityFilters = NonNullable<auditServiceComponents['schemas']['QueryActivityLogsRequest']['filters']>;

/**
 * Filtered + paginated activity logs via POST /activity-logs/query. All filters
 * (incl. tenant scope + impersonation) run server-side through the typed body,
 * so the returned pagination totals reflect the filtered set. Returns
 * { logs, pagination }.
 */
export function useActivityLogs(filters: ActivityFilters) {
  return useQuery({
    queryKey: ['platform', 'audit', 'activity', filters],
    queryFn: async () => {
      const { data, error } = await clients.audit.POST('/activity-logs/query', { body: { filters } });
      if (error || !data) throw new Error('Failed to load audit log');
      return { logs: data.logs ?? [], pagination: data.pagination };
    },
    staleTime: 30 * 1000,
  });
}

/** Export the server-side audit log and trigger a download. */
export async function exportActivityLogs(format: 'csv' | 'json'): Promise<void> {
  const { data, error } = await clients.audit.GET('/activity-logs/export', { params: { query: { format } }, parseAs: 'text' });
  if (error || data == null) throw new Error('Export failed');
  const blob = new Blob([data as string], { type: format === 'csv' ? 'text/csv' : 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `audit-log.${format}`; a.click();
  URL.revokeObjectURL(url);
}

/* ---------------------------------- SIEM --------------------------------- */

// Outbound SIEM forwarding lives in audit-service/ee/siemexport: a Core build
// never mounts /siem/**, so these calls 404 rather than 403. There is no
// `siem_export` entitlement key registered anywhere (auth-service
// `knownFeatures` / the OpenAPI `FeatureFlags` closed shape / the `FeatureName`
// union), and this is the PLATFORM console anyway — it has no tenant context, so
// /tenant/features is not available to it. So the edition is learned from the
// response: a collection-level 404 becomes an EditionUnavailableError, never
// retried, and the page renders an edition notice instead of a red failure.
// Audit event capture and search are Core and unaffected — only forwarding to an
// external SIEM is gated.

export function useSiemTypes() {
  return useQuery({
    queryKey: ['platform', 'audit', 'siem-types'],
    retry: editionAwareRetry(),
    queryFn: async () => {
      const { data, response } = await clients.audit.GET('/siem/types', {});
      assertEditionPresent('SIEM export', response);
      if (!response.ok || !data) throw new Error('Failed to load SIEM types');
      return data.types ?? [];
    },
    staleTime: 5 * 60 * 1000,
  });
}

export function useSiemIntegrations() {
  return useQuery({
    queryKey: ['platform', 'audit', 'siem-integrations'],
    retry: editionAwareRetry(),
    queryFn: async () => {
      const { data, response } = await clients.audit.GET('/siem/integrations', {});
      assertEditionPresent('SIEM export', response);
      if (!response.ok || !data) throw new Error('Failed to load integrations');
      return data.integrations ?? [];
    },
    staleTime: 30 * 1000,
  });
}

/** True when the running audit-service build does not ship SIEM export. */
export function siemEditionUnavailable(...queries: { error: unknown }[]): boolean {
  return queries.some((q) => isEditionUnavailable(q.error));
}

export function useSiemMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'audit', 'siem-integrations'] });
  const create = useMutation({
    mutationFn: async (body: SIEMIntegrationInput) => {
      const { error } = await clients.audit.POST('/siem/integrations', { body });
      if (error) throw new Error('Create failed');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: SIEMIntegrationInput }) => {
      const { error } = await clients.audit.PUT('/siem/integrations/{id}', { params: { path: { id } }, body });
      if (error) throw new Error('Update failed');
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.audit.DELETE('/siem/integrations/{id}', { params: { path: { id } } });
      if (error) throw new Error('Delete failed');
    },
    onSuccess: invalidate,
  });
  const test = useMutation({
    mutationFn: async (body: SIEMIntegrationInput) => {
      const { error } = await clients.audit.POST('/siem/integrations/test', { body });
      if (error) throw new Error('Connection test failed');
    },
  });
  return { create, update, remove, test };
}

/* ------------------------------- Retention ------------------------------- */

export function useRetentionPolicies() {
  return useQuery({
    queryKey: ['platform', 'audit', 'retention'],
    queryFn: async () => {
      const { data, error } = await clients.audit.GET('/retention-policies', {});
      if (error || !data) throw new Error('Failed to load retention policies');
      return data.policies ?? [];
    },
    staleTime: 60 * 1000,
  });
}

export function useRetentionMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'audit', 'retention'] });
  const create = useMutation({
    mutationFn: async (body: RetentionPolicyInput) => {
      const { error } = await clients.audit.POST('/retention-policies', { body });
      if (error) throw new Error('Create failed');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: RetentionPolicyInput }) => {
      const { error } = await clients.audit.PUT('/retention-policies/{id}', { params: { path: { id } }, body });
      if (error) throw new Error('Update failed');
    },
    onSuccess: invalidate,
  });
  return { create, update };
}
