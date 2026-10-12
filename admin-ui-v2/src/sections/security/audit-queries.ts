// VISTA Operations — Security & Trust: audit/activity typed query+mutation hooks.
// Every call goes through the generated typed client (`clients.audit`,
// @vistasecurity/api-contract); no hand-rolled fetch/axios. Shared by the
// trust sub-pages that came from the dissolved Audit section: Activity Log and
// Retention. (SIEM Export moved to its own service and has its own hooks in
// siem-queries.ts; the old Audit Alerts / Alert Rules / Compliance Reports
// sub-views were cut in the Governance re-roll — see.)
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { auditServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { unwrap } from '@vistasecurity/primitives/shared';

export type ActivityLog = auditServiceComponents['schemas']['ActivityLog'];
export type RetentionPolicy = auditServiceComponents['schemas']['RetentionPolicy'];
export type RetentionPolicyInput = auditServiceComponents['schemas']['RetentionPolicyInput'];

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
      const data = unwrap(await clients.audit.POST('/activity-logs/query', { body: { filters } }), 'Failed to load audit log', { requireData: true });
      return { logs: data.logs ?? [], pagination: data.pagination };
    },
    placeholderData: keepPreviousData,
    staleTime: 30 * 1000,
  });
}

/**
 * Export the server-side audit log and trigger a download. `filters` is the
 * Activity page's active filter set (tenant scope, category, user type, search,
 * impersonation, ...); the endpoint applies the same filters as the list, so
 * the file holds exactly the rows the operator is looking at. Paging is the
 * list's concern, not the export's, so it is dropped here.
 */
export async function exportActivityLogs(format: 'csv' | 'json', filters: ActivityFilters = {}): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { page: _page, page_size: _pageSize, ...query } = filters;
  const { data, error } = await clients.audit.GET('/activity-logs/export', {
    params: { query: { ...query, format } },
    parseAs: 'text',
  });
  if (error || data == null) throw new Error('Export failed');
  const blob = new Blob([data as string], { type: format === 'csv' ? 'text/csv' : 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit-log.${format}`;
  // Firefox drops downloads from a detached anchor, and revoking the URL
  // synchronously can cancel the download before it starts.
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
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
      unwrap(await clients.audit.POST('/retention-policies', { body }), 'Create failed');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: RetentionPolicyInput }) => {
      unwrap(await clients.audit.PUT('/retention-policies/{id}', { params: { path: { id } }, body }), 'Update failed');
    },
    onSuccess: invalidate,
  });
  return { create, update };
}
