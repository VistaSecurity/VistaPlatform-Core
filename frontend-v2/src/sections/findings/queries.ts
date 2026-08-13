// Live queries for the Risk & Compliance section. Both Findings and Posture
// share these (same queryKeys → one fetch per screenful).
import { useQueries, useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import type { ComplianceFinding, CryptoRisk } from './model';

/** id/name for every published framework, licensed or not. */
export interface PublishedFrameworkSummary {
  id: string;
  name: string;
}

const RISK_PAGE_SIZE = 100; // contract max
const RISK_PAGE_CAP = 5; // stream is capped at 500 rows for now (mock renders ≤200)

/** The full crypto-risk stream, paginated up to the cap. */
export function useCryptoRisks() {
  return useQuery({
    queryKey: ['findings', 'crypto-risks'],
    queryFn: async () => {
      const all: CryptoRisk[] = [];
      let page = 1;
      let totalPages = 1;
      let total = 0;
      do {
        const { data, error } = await clients.inventory.GET('/crypto-risks', {
          params: { query: { page, page_size: RISK_PAGE_SIZE } },
        });
        if (error || !data) throw new Error('Failed to load crypto risks');
        all.push(...(data.risks ?? []));
        totalPages = data.total_pages;
        total = data.total;
        page++;
      } while (page <= totalPages && page <= RISK_PAGE_CAP);
      return { risks: all, total };
    },
    staleTime: 60_000,
  });
}

export function useCryptoRiskSummary() {
  return useQuery({
    queryKey: ['findings', 'crypto-risk-summary'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/crypto-risks/summary', {});
      if (error || !data) throw new Error('Failed to load risk summary');
      return data;
    },
    staleTime: 60_000,
  });
}

/** Licensed frameworks + per-framework control counts + overall score, one call. */
export function useFrameworkContext() {
  return useQuery({
    queryKey: ['findings', 'framework-context'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/context', {});
      if (error || !data) throw new Error('Failed to load framework context');
      return data;
    },
    staleTime: 60_000,
  });
}

/**
 * Per-framework control breakdown + finding summaries. The backend evaluates
 * live and writes findings as a side effect (same call the old workbench made),
 * so keep it cached aggressively and share the key across Posture and Findings.
 */
export function useBatchEvaluate(frameworkIds: string[] | undefined) {
  return useQuery({
    queryKey: ['findings', 'batch-evaluate', frameworkIds],
    enabled: !!frameworkIds && frameworkIds.length > 0,
    queryFn: async () => {
      const { data, error } = await clients.compliance.POST('/frameworks/batch-evaluate', {
        params: { query: { include_details: true } },
        body: { framework_ids: frameworkIds! },
      });
      if (error || !data) throw new Error('Failed to evaluate frameworks');
      return data;
    },
    staleTime: 5 * 60_000,
  });
}

/**
 * Every published framework (id + name), licensed or not (#H-4b). batch-evaluate
 * only evaluates actively-licensed frameworks, so findings against a
 * published-but-unlicensed framework have nowhere else to resolve a framework
 * name from — without this they fall into "Other / retired controls" even
 * though the framework is real and just not activated.
 */
export function useAllPublishedFrameworks(enabled: boolean) {
  return useQuery({
    queryKey: ['findings', 'all-published-frameworks'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/available', {});
      if (error || !data) throw new Error('Failed to load published frameworks');
      return (data.frameworks ?? [])
        .map((f): PublishedFrameworkSummary => ({ id: f.platform_framework.id, name: f.platform_framework.name }));
    },
    staleTime: 5 * 60_000,
  });
}

/**
 * Control id → title for a set of published frameworks' controls, regardless of
 * license — GET /frameworks/published/{id} returns full control detail to every
 * tenant (transparency, ADR-0014), unlike batch-evaluate which skips unlicensed
 * frameworks. Used as the #H-4b fallback so unlicensed frameworks' findings can
 * still resolve a control name.
 */
export function useFrameworkControlNames(frameworkIds: string[]) {
  return useQueries({
    queries: frameworkIds.map((id) => ({
      queryKey: ['findings', 'framework-control-names', id],
      queryFn: async () => {
        const { data, error } = await clients.compliance.GET('/frameworks/published/{id}', {
          params: { path: { id } },
        });
        if (error || !data) throw new Error('Failed to load framework controls');
        const fw = data.framework;
        return {
          fwId: id,
          fwName: fw?.name ?? 'Unknown framework',
          controls: (fw?.controls ?? []).map((c) => ({ id: c.id, name: c.title })),
        };
      },
      staleTime: 5 * 60_000,
    })),
  });
}

/** Tenant-wide asset risk counts (hero rollup). */
export function useRiskSummary() {
  return useQuery({
    queryKey: ['findings', 'risk-summary'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/risk/summary', {});
      if (error || !data) throw new Error('Failed to load risk summary');
      return data.risk_summary;
    },
    staleTime: 60_000,
  });
}

/**
 * Day-by-day posture trend (risk index) for the Dashboard / Posture trend line
 * (ADR-0007). New tenants get a flat seeded baseline at their current posture
 * (each such point has `seeded: true`) rather than an empty chart.
 */
export function usePostureTrend(days = 30) {
  return useQuery({
    queryKey: ['findings', 'posture-trend', days],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/risk/posture/trend', {
        params: { query: { days } },
      });
      if (error || !data) throw new Error('Failed to load posture trend');
      return data.trend ?? [];
    },
    staleTime: 60_000,
  });
}

/**
 * Top exposures — active findings grouped by framework control, ranked
 * worst-severity → count → affected-assets, server-side (ADR-0007 item 4).
 * Reads the materialized compliance_findings table, so it agrees with the
 * Findings page rather than re-evaluating frameworks live.
 */
export function usePostureByControl(limit = 5) {
  return useQuery({
    queryKey: ['findings', 'by-control', limit],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/findings/by-control', {
        params: { query: { limit } },
      });
      if (error || !data) throw new Error('Failed to load top exposures');
      return data.groups ?? [];
    },
    staleTime: 60_000,
  });
}

const FINDINGS_PAGE_SIZE = 200; // contract max
const FINDINGS_PAGE_CAP = 5; // up to 1000 findings client-side

/**
 * Tenant-wide compliance findings (GET /findings) — persisted
 * workflow state (status, assignee) + the joined asset, paginated through.
 */
export function useFindingsList(enabled = true) {
  return useQuery({
    queryKey: ['findings', 'list'],
    enabled,
    queryFn: async () => {
      const all: ComplianceFinding[] = [];
      let page = 1;
      let total = 0;
      do {
        const { data, error } = await clients.compliance.GET('/findings', {
          params: { query: { page, page_size: FINDINGS_PAGE_SIZE } },
        });
        if (error || !data) throw new Error('Failed to load findings');
        all.push(...(data.findings ?? []));
        total = data.total;
        page++;
      } while (all.length < total && page <= FINDINGS_PAGE_CAP);
      return { findings: all, total };
    },
    staleTime: 30_000,
  });
}

/** Tenant members, for the assignee picker. */
export function useTenantUsers(tenantId: string | undefined) {
  return useQuery({
    queryKey: ['findings', 'tenant-users', tenantId],
    enabled: !!tenantId,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/{tenantId}/users', {
        params: { path: { tenantId: tenantId! } },
      });
      if (error || !data) throw new Error('Failed to load tenant members');
      return (data.users ?? []).filter((u) => u.is_active);
    },
    staleTime: 5 * 60_000,
  });
}

/** asset_id → asset attributes, for pivoting compliance findings by env/BU/type. */
export interface AssetFacts {
  hostname: string;
  environment: string;
  businessUnit: string;
  assetType: string;
  riskScore: number;
}
const ASSET_PAGE_CAP = 10; // up to 1000 assets in the pivot map

export function useAssetFacts(enabled = true) {
  return useQuery({
    queryKey: ['findings', 'asset-facts'],
    enabled,
    queryFn: async () => {
      const map = new Map<string, AssetFacts>();
      let page = 1;
      let totalPages = 1;
      do {
        const { data, error } = await clients.inventory.GET('/infrastructure-assets', {
          params: { query: { page, page_size: 100 } },
        });
        if (error || !data) throw new Error('Failed to load assets');
        for (const a of data.assets ?? []) {
          const rec = a as Record<string, unknown>;
          map.set(String(rec.id), {
            hostname: (rec.hostname as string) || '—',
            environment: (rec.environment as string) || 'unspecified',
            businessUnit: (rec.business_unit as string) || 'Unassigned',
            assetType: (rec.asset_type as string) || 'unknown',
            riskScore: typeof rec.risk_score === 'number' ? rec.risk_score : 0,
          });
        }
        totalPages = data.pagination.total_pages;
        page++;
      } while (page <= totalPages && page <= ASSET_PAGE_CAP);
      return map;
    },
    staleTime: 5 * 60_000,
  });
}
