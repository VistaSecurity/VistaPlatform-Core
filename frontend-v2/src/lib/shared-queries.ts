// One hook per READ ENDPOINT that more than one screen renders.
//
// Dashboard, Findings, Posture, Remediation and Settings each used to copy the
// same `queryFn` inline under their own section-prefixed key, so moving between
// them fetched identical data again and a mutation could only refresh the copy
// it happened to know about. A read that several screens share lives here, once,
// under ONE key (plus params). Add a new shared read here rather than inline.
//
// The keys are rooted at `inventory` / `compliance`, the service that owns the
// data, so the existing `invalidateQueries({ queryKey: ['inventory'] })` after an
// asset or certificate mutation reaches them without a per-key list.
import { queryOptions, useQuery, type QueryClient } from '@tanstack/react-query';
import { primitivesQueryKeys } from '@vistasecurity/primitives/shared';
import { clients } from './clients';

export const SHARED_QUERY_KEYS = {
  riskSummary: ['inventory', 'risk-summary'] as const,
  postureTrend: (days: number) => ['inventory', 'posture-trend', days] as const,
  pqcProgress: ['inventory', 'pqc-progress'] as const,
  frameworksAvailable: ['compliance', 'frameworks-available'] as const,
  scopes: ['cbom', 'scopes'] as const,
};

const STALE_MS = 60_000;

/** Tenant-wide asset risk counts (hero rollup). GET /risk/summary. */
export function useRiskSummary() {
  return useQuery({
    queryKey: SHARED_QUERY_KEYS.riskSummary,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/risk/summary', {});
      if (error || !data) throw new Error('Failed to load risk summary');
      return data.risk_summary;
    },
    staleTime: STALE_MS,
  });
}

/**
 * Day-by-day posture trend (risk index), ADR-0007. New tenants get a flat
 * seeded baseline at their current posture (`seeded: true`) rather than an
 * empty chart. GET /risk/posture/trend.
 */
export function usePostureTrend(days = 30) {
  return useQuery({
    queryKey: SHARED_QUERY_KEYS.postureTrend(days),
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/risk/posture/trend', {
        params: { query: { days } },
      });
      if (error || !data) throw new Error('Failed to load posture trend');
      return data.trend ?? [];
    },
    staleTime: STALE_MS,
  });
}

/**
 * The PQC classifier's full partition (pqc_ready, symmetric_safe, non_pqc,
 * unclassified, per-family breakdown). GET /pqc/progress.
 */
export function usePqcProgress() {
  return useQuery({
    queryKey: SHARED_QUERY_KEYS.pqcProgress,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/pqc/progress', {});
      if (error || !data) throw new Error('Failed to load PQC progress');
      return data.progress;
    },
    staleTime: STALE_MS,
  });
}

/**
 * Every published framework with `is_licensed` and its materialized
 * `preview_score`. GET /frameworks/available. Consumers that want a narrower
 * row type pass `select`, which does not change the cache entry.
 */
async function fetchFrameworksAvailable() {
  const { data, error } = await clients.compliance.GET('/frameworks/available', {});
  if (error || !data) throw new Error('Failed to load frameworks');
  return data.frameworks ?? [];
}
type FrameworkRows = Awaited<ReturnType<typeof fetchFrameworksAvailable>>;

export function useFrameworksAvailable<T = FrameworkRows>(select?: (rows: FrameworkRows) => T) {
  return useQuery({
    queryKey: SHARED_QUERY_KEYS.frameworksAvailable,
    queryFn: fetchFrameworksAvailable,
    select,
    staleTime: STALE_MS,
  });
}

/**
 * Refresh what the viewer is ENTITLED to: the tenant feature map (plan-gated
 * pages) and their effective permissions (role-gated pages). Both are cached
 * for five minutes by the primitives, so a plan change or an edit to one's own
 * role must invalidate them or the upgrade/lock cards stay up for that long.
 */
export function invalidateEntitlements(qc: QueryClient): Promise<unknown> {
  return Promise.all([
    qc.invalidateQueries({ queryKey: primitivesQueryKeys.tenant.features() }),
    qc.invalidateQueries({ queryKey: primitivesQueryKeys.auth.permissions() }),
  ]);
}

/**
 * Tenant CBOM scopes (seeds the system defaults on first read). GET /scopes.
 * Settings -> Scopes and the CBOM scope picker both read it, so a rename or
 * predicate edit made in Settings reaches the picker: invalidate THIS key.
 */
export function scopesQuery() {
  return queryOptions({
    queryKey: SHARED_QUERY_KEYS.scopes,
    queryFn: async () => {
      const { data, error } = await clients.cbom.GET('/scopes', {});
      if (error || !data) throw new Error('Failed to load scopes');
      return data.scopes ?? [];
    },
    staleTime: STALE_MS,
  });
}
