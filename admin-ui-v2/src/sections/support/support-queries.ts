// VISTA Operations — Support (CS cockpit) typed query+mutation hooks. Every call
// goes through the generated typed client (@vistasecurity/api-contract); no
// hand-rolled fetch/axios. Platform CSRF is automatic (see lib/clients.ts).
//   • Tenant Health  → clients.tenantHealth  (read)
//   • Impersonation  → clients.auth          (read-only audit trail)
//   • Job Repair     → clients.devices       (list + retry/cancel)
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type {
  tenantHealthServiceComponents,
  authServiceComponents,
  deviceInterrogationComponents,
} from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type TenantHealthSummary = tenantHealthServiceComponents['schemas']['TenantHealthSummary'];
export type TenantHealth = tenantHealthServiceComponents['schemas']['TenantHealth'];
export type HealthAlert = tenantHealthServiceComponents['schemas']['HealthAlert'];
export type HealthBreakdown = tenantHealthServiceComponents['schemas']['HealthBreakdown'];
export type Recommendation = tenantHealthServiceComponents['schemas']['Recommendation'];
export type ImpersonationEvent = authServiceComponents['schemas']['ImpersonationEvent'];
export type AdminInterrogationJob = deviceInterrogationComponents['schemas']['AdminInterrogationJob'];

export function errMsg(e: unknown, fallback = 'Action failed'): string {
  return e instanceof Error ? e.message : fallback;
}

/* --------------------------- Tenant Health ------------------------------- */

/** Cross-tenant health board — GET /tenants (limit 200). */
export function useTenantHealthList() {
  return useQuery({
    queryKey: ['platform', 'support', 'tenant-health'],
    queryFn: async (): Promise<TenantHealthSummary[]> => {
      const { data, error } = await clients.tenantHealth.GET('/tenants', { params: { query: { limit: 200 } } });
      if (error || !data) throw new Error('Failed to load tenant health');
      return data.tenants ?? [];
    },
    staleTime: 60 * 1000,
  });
}

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

/* --------------------------- Impersonation ------------------------------- */

/** Read-only impersonation audit trail — GET /admin/impersonations/audit. */
export function useImpersonationEvents() {
  return useQuery({
    queryKey: ['platform', 'support', 'impersonations'],
    queryFn: async (): Promise<ImpersonationEvent[]> => {
      const { data, error } = await clients.auth.GET('/admin/impersonations/audit', {});
      if (error || !data) throw new Error('Failed to load impersonation history');
      return data.events ?? [];
    },
    staleTime: 30 * 1000,
  });
}

/* ------------------------------ Job Repair ------------------------------- */

/** Platform-wide interrogation jobs — GET /admin/jobs (page_size 100). */
export function useAdminJobs() {
  return useQuery({
    queryKey: ['platform', 'support', 'jobs'],
    queryFn: async (): Promise<AdminInterrogationJob[]> => {
      const { data, error } = await clients.devices.GET('/admin/jobs', { params: { query: { page_size: 100 } } });
      if (error || !data) throw new Error('Failed to load jobs');
      return data.jobs ?? [];
    },
    staleTime: 30 * 1000,
  });
}

/** Retry (failed|cancelled) / cancel (pending|assigned|in_progress) a stuck job. */
export function useJobRepairMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'support', 'jobs'] });
  const retry = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.devices.POST('/admin/jobs/{id}/retry', { params: { path: { id } } });
      if (error) throw new Error('Retry failed');
    },
    onSuccess: invalidate,
  });
  const cancel = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.devices.POST('/admin/jobs/{id}/cancel', { params: { path: { id } } });
      if (error) throw new Error('Cancel failed');
    },
    onSuccess: invalidate,
  });
  return { retry, cancel };
}
