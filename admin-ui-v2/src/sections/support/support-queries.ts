// VISTA Operations — Support (CS cockpit) typed query+mutation hooks. Every call
// goes through the generated typed client (@vistasecurity/api-contract); no
// hand-rolled fetch/axios. Platform CSRF is automatic (see lib/clients.ts).
//   • Tenant Health  → clients.tenantHealth  (read)
//   • Job Repair     → clients.devices       (retry/cancel; the list is jobs/queries.ts)
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type {
  tenantHealthServiceComponents,
  deviceInterrogationComponents,
} from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { jobsKeys } from '../jobs/queries';
import { unwrap } from '@vistasecurity/primitives/shared';

export type TenantHealthSummary = tenantHealthServiceComponents['schemas']['TenantHealthSummary'];
export type TenantHealth = tenantHealthServiceComponents['schemas']['TenantHealth'];
export type HealthAlert = tenantHealthServiceComponents['schemas']['HealthAlert'];
export type HealthBreakdown = tenantHealthServiceComponents['schemas']['HealthBreakdown'];
export type Recommendation = tenantHealthServiceComponents['schemas']['Recommendation'];
export type AdminInterrogationJob = deviceInterrogationComponents['schemas']['AdminInterrogationJob'];

export function errMsg(e: unknown, fallback = 'Action failed'): string {
  return e instanceof Error ? e.message : fallback;
}

/* --------------------------- Tenant Health ------------------------------- */

/** Cross-tenant health board — the single shared query lives in the tenants section. */
export { useTenantHealthList } from '../tenants/queries';

/** Full health record for one tenant — GET /tenants/{tenantId}. Drawer-only. */
export function useTenantHealthDetail(id: string | null) {
  return useQuery({
    queryKey: ['platform', 'support', 'tenant-health-detail', id],
    enabled: !!id,
    retry: 0,
    staleTime: 30 * 1000,
    queryFn: async (): Promise<TenantHealth> => {
      const { data, error } = await clients.tenantHealth.GET('/tenants/{tenantId}', { params: { path: { tenantId: id! } } });
      if (error || !data) throw new Error('Failed to load tenant health detail');
      return data;
    },
  });
}

/** Active alerts for one tenant — GET /tenants/{tenantId}/alerts. Drawer-only. */
export function useTenantHealthAlerts(id: string | null) {
  return useQuery({
    queryKey: ['platform', 'support', 'tenant-health-alerts', id],
    enabled: !!id,
    retry: 0,
    staleTime: 30 * 1000,
    queryFn: async (): Promise<HealthAlert[]> => {
      const { data, error } = await clients.tenantHealth.GET('/tenants/{tenantId}/alerts', { params: { path: { tenantId: id! } } });
      if (error || !data) throw new Error('Failed to load tenant alerts');
      return data.alerts ?? [];
    },
  });
}

/* ------------------------------ Job Repair ------------------------------- */

/** Retry (failed|cancelled) / cancel (pending|assigned|in_progress) a stuck job. */
export function useJobRepairMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: jobsKeys.all });
  const retry = useMutation({
    mutationFn: async (id: string) => {
      unwrap(await clients.devices.POST('/admin/jobs/{id}/retry', { params: { path: { id } } }), 'Retry failed');
    },
    onSuccess: invalidate,
  });
  const cancel = useMutation({
    mutationFn: async (id: string) => {
      unwrap(await clients.devices.POST('/admin/jobs/{id}/cancel', { params: { path: { id } } }), 'Cancel failed');
    },
    onSuccess: invalidate,
  });
  return { retry, cancel };
}
