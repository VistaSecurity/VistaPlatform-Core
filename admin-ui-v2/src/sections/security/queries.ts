// Security & Governance data layer — security events/stats/compliance (admin-service),
// platform settings (admin-service), and impersonation audit (auth-service), all via
// the typed clients. No hand-rolled fetch.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { adminServiceComponents, authServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type SecurityEvent = adminServiceComponents['schemas']['SecurityEvent'];
export type ComplianceFrameworkStatus = adminServiceComponents['schemas']['ComplianceFrameworkStatus'];
export type PlatformSettings = adminServiceComponents['schemas']['PlatformSettings'];
export type ImpersonationEvent = authServiceComponents['schemas']['ImpersonationEvent'];

/** Free-form dashboard-stats blob (admin-service returns `data` as a metrics object). */
export interface SecurityDashboardStats {
  total_events?: number;
  events_by_severity?: Record<string, number>;
  events_by_status?: Record<string, number>;
  anomalies_detected?: number;
  high_risk_events?: number;
  [k: string]: unknown;
}

export function errMsg(e: unknown, fallback = 'Action failed'): string {
  if (e instanceof Error) return e.message;
  if (e && typeof e === 'object' && 'error' in e && typeof (e as any).error === 'string') return (e as any).error;
  return fallback;
}

// ── security dashboard reads ───────────────────────────────────────────────────

export function useSecurityStats(timeRange: string) {
  return useQuery({
    queryKey: ['platform', 'security', 'stats', timeRange],
    queryFn: async (): Promise<SecurityDashboardStats> => {
      const { data, error } = await clients.admin.GET('/admin/security/dashboard-stats', { params: { query: { timeRange } } });
      if (error || !data) throw new Error('Failed to load security stats');
      return (data.data ?? {}) as SecurityDashboardStats;
    },
    refetchInterval: 60 * 1000,
    retry: 0,
  });
}

export function useSecurityEvents(limit = 25) {
  return useQuery({
    queryKey: ['platform', 'security', 'events', limit],
    queryFn: async (): Promise<SecurityEvent[]> => {
      const { data, error } = await clients.admin.GET('/admin/security/events', { params: { query: { limit } } });
      if (error || !data) throw new Error('Failed to load security events');
      return data.data ?? [];
    },
    staleTime: 30 * 1000,
    retry: 0,
  });
}

export function useComplianceFrameworks() {
  return useQuery({
    queryKey: ['platform', 'security', 'compliance'],
    queryFn: async (): Promise<ComplianceFrameworkStatus[]> => {
      const { data, error } = await clients.admin.GET('/admin/security/compliance', {});
      if (error || !data) throw new Error('Failed to load compliance frameworks');
      return data.data ?? [];
    },
    staleTime: 5 * 60 * 1000,
    retry: 0,
  });
}

export function useImpersonationAudit() {
  return useQuery({
    queryKey: ['platform', 'security', 'impersonations'],
    queryFn: async (): Promise<ImpersonationEvent[]> => {
      const { data, error } = await clients.auth.GET('/admin/impersonations/audit', {});
      if (error || !data) throw new Error('Failed to load impersonation audit');
      return data.events ?? [];
    },
    staleTime: 60 * 1000,
    retry: 0,
  });
}

// ── platform settings (Policy sub-page) ─────────────────────────────────────────
// NOTE: /admin/settings is also written by the platform Settings section (Email
// Delivery). updatePlatformSettings takes PlatformSettingsInput ("all fields optional;
// only provided ones are persisted") — a partial merge — so writing only the security
// fields here does NOT clobber email_config or other keys.

export function usePlatformSettings() {
  return useQuery({
    queryKey: ['platform', 'settings'],
    queryFn: async (): Promise<PlatformSettings> => {
      const { data, error } = await clients.admin.GET('/admin/settings', {});
      if (error || !data) throw new Error('Failed to load settings');
      return data;
    },
    staleTime: 30 * 1000,
  });
}

export function useUpdateSecuritySettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (patch: Record<string, unknown>) => {
      const { data, error } = await clients.admin.PUT('/admin/settings', { body: patch });
      if (error || !data) throw error ?? new Error('Failed to save settings');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['platform', 'settings'] }),
  });
}
