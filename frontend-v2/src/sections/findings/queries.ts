// Live queries for the Risk & Compliance section. Both Findings and Posture
// share these (same queryKeys → one fetch per screenful).
import { useQuery } from '@tanstack/react-query';
import type { complianceEnginePaths } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import type { ComplianceFinding, CryptoRisk } from './model';

export const RISK_PAGE_SIZE = 100; // contract max
export const RISK_PAGE_CAP = 5;

/**
 * The loaded prefix of the crypto-risk stream. `truncated` is part of the
 * result because every Findings-page filter, count, export and bulk action
 * operates on these rows; callers must say when more rows exist.
 */
export function useCryptoRisks() {
  return useQuery({
    queryKey: ['findings', 'crypto-risks'],
    queryFn: async () => {
      const all: CryptoRisk[] = [];
      let page = 1;
      let totalPages: number;
      let total: number;
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
      return { risks: all, total, loaded: all.length, truncated: all.length < total };
    },
    staleTime: 60_000,
  });
}

/**
 * The OPEN findings on one asset, from EVERY producer.
 *
 * The route resolves the asset AND its descendants — the certificates and
 * crypto configurations at its endpoints, its software installs — because most
 * findings are about one of those rather than about the host. Every producer,
 * not only `compliance`: `eol` and `vulnerability` write findings on an asset's
 * software installs (workstreams 3.3/3.4 part 2). The caller reads `producer`
 * on each row rather than assuming, so the tab tells the truth about who has
 * actually looked.
 */
export function useAssetFindings(assetId: string, enabled = true) {
  return useQuery({
    queryKey: ['findings', 'by-asset', assetId],
    enabled: enabled && !!assetId,
    queryFn: async (): Promise<ComplianceFinding[]> => {
      const { data, error } = await clients.compliance.GET('/assets/{assetId}/findings', {
        params: { path: { assetId } },
      });
      if (error || !data) throw new Error('Failed to load findings for this asset');
      return data.findings ?? [];
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
 * Reads the materialized findings, so it agrees with the Findings page rather
 * than re-evaluating frameworks live.
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
 * Tenant-wide findings (GET /findings) — persisted workflow state
 * (status, assignee) + the joined subject object, paginated through.
 *
 * EVERY producer, not only `compliance`. The endpoint carried a
 * compliance-only scope until the `eol` and `vulnerability` producers shipped
 * (workstreams 3.3/3.4 part 2); this page would otherwise have been the one
 * surface in the product that silently omitted them.
 *
 * `producerCounts` is the tally the producer facets render. It comes from the
 * SERVER, computed under the same filters as the list minus the producer one,
 * rather than being counted off `findings` here — the list is capped at
 * FINDINGS_PAGE_CAP pages, so a client-side tally would quietly under-report a
 * big tenant, which is the exact shape of the `has_findings` divergence that
 * cost the facet its first outing.
 */
/**
 * A subject filter: findings about ONE thing.
 *
 * Both halves or neither — the endpoint refuses either alone, because a lone id
 * can collide across subject vocabularies and a lone type is the producer
 * filter under a worse name. This is what a "3 vulnerabilities" cell on the
 * software surfaces links through, so the page it opens has to be exactly the
 * rows the number counted.
 */
export interface FindingSubjectFilter {
  /** Derived from the contract, so a subject type the endpoint does not accept
   *  is a TypeScript error here rather than a 400 and an empty page. */
  subjectType: NonNullable<
    NonNullable<complianceEnginePaths['/findings']['get']['parameters']['query']>['subject_type']
  >;
  subjectId: string;
}

export function useFindingsList(
  enabled = true,
  producer?: string,
  subject?: FindingSubjectFilter,
  /**
   * The free-text term, sent to the SERVER.
   *
   * It used to narrow `findings` in the browser after this hook returned, and
   * this hook stops at FINDINGS_PAGE_CAP pages — so on a tenant with more than
   * a thousand findings the box searched a PREFIX of the stream, and a
   * `?q=<product>` link into the 1,200th finding rendered "no findings match".
   * Which is the same failure as the subject filter above, in the same place,
   * for the same reason: a page-capped list cannot be filtered client-side and
   * still be believed.
   *
   * The cap stays for the UNSEARCHED stream — it is what keeps opening the page
   * from paging a whole estate — and a search narrows server-side first, so the
   * cap is reached far less often and never silently.
   */
  search?: string,
  /**
   * One rung of the severity ladder, sent to the SERVER.
   *
   * This is what the Dashboard's "Critical findings" tile links through
   * (`?severity=critical`), and it is server-side for the same reason the
   * subject filter and the search box are: this hook stops at
   * FINDINGS_PAGE_CAP pages, so narrowing the returned array instead would
   * under-report a tenant whose Criticals sit past the cap — a tile reading
   * "40 critical findings" opening a page that shows twelve. It also keeps
   * `total` and `producerCounts` describing the same set as the rows, because
   * the server applies all three under one predicate.
   */
  severity?: string,
) {
  const q = (search ?? '').trim();
  const sev = (severity ?? '').trim().toLowerCase();
  return useQuery({
    queryKey: ['findings', 'list', producer ?? 'all', subject ? `${subject.subjectType}:${subject.subjectId}` : 'all-subjects', q || 'all-text', sev || 'all-severities'],
    enabled,
    queryFn: async () => {
      const all: ComplianceFinding[] = [];
      let page = 1;
      let total: number;
      let producerCounts: Record<string, number> = {};
      do {
        const { data, error } = await clients.compliance.GET('/findings', {
          params: { query: {
            page, page_size: FINDINGS_PAGE_SIZE,
            ...(producer ? { producer } : {}),
            // Sent SERVER-side, not filtered here: this list is capped at
            // FINDINGS_PAGE_CAP pages, so a subject past the cap would render
            // an empty page under a link that promised N findings.
            ...(subject ? { subject_type: subject.subjectType, subject_id: subject.subjectId } : {}),
            ...(q ? { q } : {}),
            ...(sev ? { severity: sev } : {}),
          } },
        });
        if (error || !data) throw new Error('Failed to load findings');
        all.push(...(data.findings ?? []));
        total = data.total;
        producerCounts = data.producer_counts ?? {};
        page++;
      } while (all.length < total && page <= FINDINGS_PAGE_CAP);
      return { findings: all, total, producerCounts };
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
      let totalPages: number;
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
