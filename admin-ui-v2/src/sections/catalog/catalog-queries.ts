// VISTA Operations — Catalog ▸ End-of-life / Vulnerability feed: typed query +
// mutation hooks. Every call goes through the generated admin-service client
// (`clients.admin`, @vistasecurity/api-contract); no hand-rolled fetch.
//
// These catalogues are PLATFORM data — no tenant_id, every tenant reads the same
// rows — so they live beside Algorithms and Frameworks under Catalog. Reads and
// writes are both gated server-side on `catalogs.manage`.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type EolEntry = adminServiceComponents['schemas']['EolCatalogueEntry'];
export type VulnerabilityEntry = adminServiceComponents['schemas']['VulnerabilityCatalogueEntry'];
export type CatalogFeedStatus = adminServiceComponents['schemas']['CatalogFeedStatus'];
export type CatalogFeedList = adminServiceComponents['schemas']['CatalogFeedListResponse'];
export type CatalogBundleImport = adminServiceComponents['schemas']['CatalogBundleImportResponse'];

export type ProductKind = 'os' | 'software' | 'hardware';
export type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical';
export type FeedName = 'eol' | 'nvd' | 'osv';

export const PAGE_SIZE = 50;

export function errMsg(e: unknown, fallback = 'Action failed'): string {
  return e instanceof Error ? e.message : fallback;
}

/** A page of rows plus the unpaginated total, the shape both tables render. */
export interface Page<T> {
  rows: T[];
  total: number;
  page: number;
  pageSize: number;
}

/* ------------------------------ end-of-life ------------------------------ */

export interface EolFilters {
  search: string;
  kind: ProductKind | '';
  page: number;
}

export function useEolCatalogue(filters: EolFilters) {
  return useQuery({
    // The filters are IN the key, so paging and searching each get their own
    // cache entry and going back a page is instant rather than a refetch.
    queryKey: ['platform', 'catalog', 'eol', filters],
    queryFn: async (): Promise<Page<EolEntry>> => {
      const { data, error } = await clients.admin.GET('/admin/catalogs/eol', {
        params: {
          query: {
            ...(filters.search ? { search: filters.search } : {}),
            ...(filters.kind ? { kind: filters.kind } : {}),
            page: filters.page,
            page_size: PAGE_SIZE,
          },
        },
      });
      if (error || !data) throw new Error('Failed to load the end-of-life catalogue');
      return { rows: data.entries, total: data.total, page: data.page, pageSize: data.page_size };
    },
    staleTime: 60 * 1000,
  });
}

/* ----------------------------- vulnerability ----------------------------- */

export interface VulnFilters {
  search: string;
  severity: Severity | '';
  page: number;
}

export function useVulnerabilityCatalogue(filters: VulnFilters) {
  return useQuery({
    queryKey: ['platform', 'catalog', 'vulnerabilities', filters],
    queryFn: async (): Promise<Page<VulnerabilityEntry>> => {
      const { data, error } = await clients.admin.GET('/admin/catalogs/vulnerabilities', {
        params: {
          query: {
            ...(filters.search ? { search: filters.search } : {}),
            ...(filters.severity ? { severity: filters.severity } : {}),
            page: filters.page,
            page_size: PAGE_SIZE,
          },
        },
      });
      if (error || !data) throw new Error('Failed to load the vulnerability catalogue');
      return {
        rows: data.vulnerabilities,
        total: data.total,
        page: data.page,
        pageSize: data.page_size,
      };
    },
    staleTime: 60 * 1000,
  });
}

/* --------------------------------- feeds --------------------------------- */

/**
 * Feed status. Polls every 10s WHILE a feed reports `running`, and stops when
 * none does — the sync endpoint answers 202 and the outcome only lands in
 * `catalog_feed_state` minutes later, so without this the page would show
 * "running" until someone reloaded it.
 */
export function useCatalogFeeds() {
  return useQuery({
    queryKey: ['platform', 'catalog', 'feeds'],
    queryFn: async (): Promise<CatalogFeedList> => {
      const { data, error } = await clients.admin.GET('/admin/catalogs/feeds', {});
      if (error || !data) throw new Error('Failed to load feed status');
      return data;
    },
    staleTime: 10 * 1000,
    refetchInterval: (query) =>
      query.state.data?.feeds?.some((f) => f.last_status === 'running') ? 10_000 : false,
  });
}

export function useSyncCatalogFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (feed: FeedName) => {
      const { error, response } = await clients.admin.POST('/admin/catalogs/feeds/{feed}/sync', {
        params: { path: { feed } },
      });
      if (error) {
        // Each status means a different thing and has a different fix, so they
        // are not flattened into one "sync failed".
        const detail = (error as { error?: string })?.error;
        if (response?.status === 409) throw new Error(detail ?? 'A sync is already running for this feed');
        if (response?.status === 403) throw new Error('You do not have permission to run catalogue feeds (catalogs.manage required)');
        if (response?.status === 404) throw new Error(`Unknown feed "${feed}"`);
        if (response?.status === 503) throw new Error(detail ?? 'The feed runner is not configured in this deployment');
        throw new Error(detail ?? 'Failed to start the sync');
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'feeds'] }),
  });
}

/**
 * A refused bundle and a half-applied one are different answers.
 *
 * Verification runs before the first row is written, so a 400 really does mean
 * the catalogue is untouched. A failure AFTER verification passed (the server
 * answers 500) means rows are already in — and telling the operator "nothing was
 * applied" there would be the reassuring-but-wrong report this codebase keeps
 * paying for. `applied` carries the distinction to the card.
 */
export class BundleImportError extends Error {
  readonly applied: boolean;
  constructor(message: string, applied: boolean) {
    super(message);
    this.name = 'BundleImportError';
    this.applied = applied;
  }
}

export function useImportCatalogBundle() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (file: File): Promise<CatalogBundleImport> => {
      // Typed multipart: the contract types the part ({ file: binary }); the
      // serializer supplies the real FormData so the browser sets the boundary.
      const { data, error, response } = await clients.admin.POST('/admin/catalogs/import-bundle', {
        body: { file: '' } as never,
        bodySerializer: () => {
          const fd = new FormData();
          fd.append('file', file);
          return fd;
        },
      });
      if (error || !data) {
        // The server's verification failure IS the diagnosis ("sha256 mismatch
        // on vulnerability_catalogue.jsonl") — surface it, don't replace it.
        const detail = (error as { error?: string })?.error;
        if (response?.status === 403) {
          throw new BundleImportError(
            'You do not have permission to import a catalogue bundle (catalogs.manage required)', false);
        }
        // 500 is the server saying verification passed and the apply then
        // failed, so rows ARE written. Anything else refused the bundle whole.
        throw new BundleImportError(detail ?? 'Bundle import failed', response?.status === 500);
      }
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'eol'] });
      void qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'vulnerabilities'] });
      void qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'feeds'] });
    },
  });
}

/* ------------------------------ presentation ----------------------------- */

/** Human label per feed, used by the status card on both pages. */
export const FEED_LABEL: Record<string, string> = {
  eol: 'endoflife.date',
  nvd: 'NVD (NIST)',
  osv: 'OSV (osv.dev)',
};

/** Which feeds fill which catalogue, so each page shows only its own. */
export const FEEDS_FOR: Record<'eol' | 'vulnerability', FeedName[]> = {
  eol: ['eol'],
  vulnerability: ['nvd', 'osv'],
};

/**
 * Days until (positive) or since (negative) a date. Returns null when the date
 * is absent — "no end-of-life date published" is not "0 days left", and the
 * table says so rather than rendering a number nobody can act on.
 */
export function daysUntil(iso: string | null | undefined, now: Date = new Date()): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.round((t - now.getTime()) / 86_400_000);
}

/** Short ISO date, or an em dash when there is nothing to show. */
export function shortDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  return new Date(t).toISOString().slice(0, 10);
}

/** Colour for a CVSS band. Mirrors the qualitative ladder, not a second scale. */
export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--danger)',
  high: 'var(--warn-strong)',
  medium: 'var(--warn)',
  low: 'var(--ok-lime)',
  none: 'var(--info)',
};

/* --------------------------- classification rules ------------------------- */

// Catalog ▸ Classification rules (asset-inventory ADR-0004 D6). The evidence
// behind every class proposal, held as data so the fingerprint catalogue grows
// without a release. Full CRUD, unlike the two mirrored catalogues above: there
// is no upstream feed here — the rules are ours and the admin's.

export type ClassificationRule = adminServiceComponents['schemas']['ClassificationRule'];
export type ClassificationRuleInput = adminServiceComponents['schemas']['ClassificationRuleInput'];
export type ClassificationRuleKind = adminServiceComponents['schemas']['ClassificationRuleKind'];

export interface ClassificationRuleFilters {
  search: string;
  kind: ClassificationRuleKind | '';
  page: number;
}

/** A page of rules plus the kind vocabulary the server served with it. */
export interface ClassificationRulePage extends Page<ClassificationRule> {
  kinds: ClassificationRuleKind[];
}

const RULES_KEY = ['platform', 'catalog', 'classification-rules'] as const;

export function useClassificationRules(filters: ClassificationRuleFilters) {
  return useQuery({
    queryKey: [...RULES_KEY, filters],
    queryFn: async (): Promise<ClassificationRulePage> => {
      const { data, error } = await clients.admin.GET('/admin/catalogs/classification-rules', {
        params: {
          query: {
            ...(filters.search ? { search: filters.search } : {}),
            ...(filters.kind ? { kind: filters.kind } : {}),
            page: filters.page,
            page_size: PAGE_SIZE,
          },
        },
      });
      if (error || !data) throw new Error('Failed to load the classification rules');
      return {
        rows: data.rules,
        total: data.total,
        page: data.page,
        pageSize: data.page_size,
        // The vocabulary comes from the server, never from a constant here: a
        // ninth rule kind must appear in the filter and the form without a
        // frontend change, or it ships invisible.
        kinds: data.kinds,
      };
    },
    staleTime: 60 * 1000,
  });
}

/* ------------------------- the Enricher seam (4.5b) ----------------------- */
//
// ADR-0008's Enricher: the catalogue lookup, the gaps it could not answer, and
// the AI proposals that fill them — each reviewed before anything is written.
//
// Everything below except "Propose with AI" exists in every edition. A Core
// deployment has the lookup, the gap list and the review queue, and an empty
// queue; what it does not have is the thing that fills it.

export type EolProposal = adminServiceComponents['schemas']['EolProposal'];
export type CatalogMiss = adminServiceComponents['schemas']['CatalogMiss'];
export type EolFact = adminServiceComponents['schemas']['EolFact'];
export type EolLookupResult = adminServiceComponents['schemas']['EolLookupResponse'];
export type EnrichAvailability = adminServiceComponents['schemas']['CatalogEnrichAvailability'];
export type ProposalStatus = 'pending' | 'accepted' | 'rejected';

export function useEolProposals(status: ProposalStatus | '', page: number) {
  return useQuery({
    queryKey: ['platform', 'catalog', 'eol-proposals', status, page],
    queryFn: async (): Promise<Page<EolProposal>> => {
      const { data, error } = await clients.admin.GET('/admin/catalogs/eol/proposals', {
        params: { query: { ...(status ? { status } : {}), page, page_size: PAGE_SIZE } },
      });
      if (error || !data) throw new Error('Failed to load the proposal queue');
      return { rows: data.proposals, total: data.total, page: data.page, pageSize: data.page_size };
    },
    staleTime: 30 * 1000,
  });
}

export function useCatalogMisses(page: number) {
  return useQuery({
    queryKey: ['platform', 'catalog', 'eol-misses', page],
    queryFn: async (): Promise<Page<CatalogMiss>> => {
      const { data, error } = await clients.admin.GET('/admin/catalogs/eol/misses', {
        params: { query: { page, page_size: PAGE_SIZE } },
      });
      if (error || !data) throw new Error('Failed to load the gap list');
      return { rows: data.misses, total: data.total, page: data.page, pageSize: data.page_size };
    },
    staleTime: 30 * 1000,
  });
}

/**
 * Turns a write failure into the sentence an admin can act on.
 *
 * The server's validation message IS the diagnosis — "oui rule pattern
 * "00:80:77" must be 6 uppercase hex digits with no separators" tells them what
 * to type next — so it is surfaced verbatim rather than replaced with "save
 * failed". 409 is the one case worth rewording, because the fix is not to
 * change this rule but to go and edit the one that already claims the pattern.
 */
function ruleWriteError(error: unknown, status: number | undefined, fallback: string): Error {
  const detail = (error as { error?: string })?.error;
  if (status === 403) {
    return new Error('You do not have permission to curate classification rules (catalogs.manage required)');
  }
  if (status === 409) {
    return new Error(detail ?? 'A rule with that kind and pattern already exists — edit that one instead');
  }
  if (status === 404) return new Error('That rule no longer exists — it may have been deleted elsewhere');
  return new Error(detail ?? fallback);
}

export function useCreateClassificationRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: ClassificationRuleInput): Promise<ClassificationRule> => {
      const { data, error, response } = await clients.admin.POST('/admin/catalogs/classification-rules', {
        body: input,
      });
      if (error || !data) throw ruleWriteError(error, response?.status, 'Failed to create the rule');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: RULES_KEY }),
  });
}

export function useUpdateClassificationRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (
      { id, input }: { id: string; input: ClassificationRuleInput },
    ): Promise<ClassificationRule> => {
      const { data, error, response } = await clients.admin.PUT('/admin/catalogs/classification-rules/{id}', {
        params: { path: { id } },
        body: input,
      });
      if (error || !data) throw ruleWriteError(error, response?.status, 'Failed to update the rule');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: RULES_KEY }),
  });
}

export function useDeleteClassificationRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await clients.admin.DELETE('/admin/catalogs/classification-rules/{id}', {
        params: { path: { id } },
      });
      if (error) throw ruleWriteError(error, response?.status, 'Failed to delete the rule');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: RULES_KEY }),
  });
}

/** Human label per rule kind, for the filter and the table. */
export const RULE_KIND_LABEL: Record<string, string> = {
  oui: 'MAC OUI',
  sysobjectid: 'SNMP sysObjectID',
  enip: 'EtherNet/IP vendor',
  cloud_type: 'Cloud resource type',
  banner: 'Service banner',
  port_profile: 'Port profile',
  model: 'Model prefix',
  platform: 'Collector platform',
  cdp_capabilities: 'CDP capabilities',
  lldp_capability: 'LLDP capabilities',
  mdns_service: 'Advertised mDNS service',
};

/**
 * What to type in the pattern box, per kind. Shown beside the field rather than
 * left to the server's rejection: a form that only tells you the answer after
 * you get it wrong is a form that gets it wrong repeatedly.
 */
export const RULE_KIND_HINT: Record<string, string> = {
  oui: '6 uppercase hex digits, no separators — e.g. 00000C',
  sysobjectid: 'An OID under 1.3.6.1.4.1 — e.g. 1.3.6.1.4.1.9. Longest prefix wins.',
  enip: 'An ODVA vendor id in decimal — e.g. 1',
  cloud_type: "The provider's own resource type — e.g. aws_s3_bucket",
  banner: 'A Go RE2 regexp, anchored — e.g. (?i)^server:\\s*nginx',
  port_profile: 'Ascending ports, all of which must be open — e.g. 631,9100',
  model: 'A model or product-id prefix — e.g. C9300. Longest prefix wins.',
  platform: 'A collector platform or device profile — e.g. fortios',
  cdp_capabilities: 'Cisco CDP capability names, ascending, ALL of which must be advertised — e.g. router,switch. The most specific matching set wins.',
  lldp_capability: 'IEEE 802.1AB capability names, ascending, ALL of which must be advertised — e.g. bridge,router. The most specific matching set wins.',
  mdns_service: 'A DNS-SD service type, lowercase — e.g. _ipp._tcp',
};

/** Confidence bounds, mirroring the engine's band. */
export const MIN_CONFIDENCE = 0.5;
export const MAX_CONFIDENCE = 0.95;

/**
 * Whether "Propose with AI" is offered at all.
 *
 * Asked before the button is rendered, not after it is clicked — the pattern
 * established for the author seam. A Core build answers
 * `{available:false,reason:"edition"}`; an Enterprise build with no
 * `AI_PROVIDER` answers `no_provider`. Either way the action is not offered,
 * because a button that always errors is worse than no button.
 */
export function useEnrichAvailability() {
  return useQuery({
    queryKey: ['platform', 'catalog', 'enrich-availability'],
    queryFn: async (): Promise<EnrichAvailability> => {
      const { data, error } = await clients.admin.GET('/admin/catalogs/eol/enrich/availability', {});
      if (error || !data) throw new Error('availability unavailable');
      return data;
    },
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

/**
 * Review one proposal.
 *
 * Accepting invalidates the CATALOGUE query as well as the queue: the accept
 * wrote an `eol_catalogue` row, and a Catalogue tab still showing the old page
 * would make a reviewer think the decision had not taken effect.
 */
export function useReviewProposal(action: 'accept' | 'reject') {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const path = action === 'accept'
        ? '/admin/catalogs/eol/proposals/{id}/accept' as const
        : '/admin/catalogs/eol/proposals/{id}/reject' as const;
      const { data, error, response } = await clients.admin.POST(path, { params: { path: { id } } });
      if (error || !data) {
        const detail = (error as { error?: string })?.error;
        // Each status is a different situation with a different fix, so they
        // are not flattened into one "review failed".
        if (response?.status === 409) throw new Error(detail ?? 'That proposal has already been reviewed');
        if (response?.status === 404) throw new Error('That proposal no longer exists');
        if (response?.status === 403) throw new Error('You do not have permission to review proposals (catalogs.manage required)');
        throw new Error(detail ?? `Failed to ${action} the proposal`);
      }
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'eol-proposals'] });
      void qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'eol-misses'] });
      void qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'eol'] });
    },
  });
}

export function useRunEnrichment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.admin.POST('/admin/catalogs/eol/enrich', {});
      if (error) {
        const detail = (error as { error?: string })?.error;
        if (response?.status === 409) throw new Error(detail ?? 'A proposal run is already in flight');
        if (response?.status === 503) throw new Error(detail ?? 'AI proposals are not available on this deployment');
        if (response?.status === 403) throw new Error('You do not have permission to run this (catalogs.manage required)');
        throw new Error(detail ?? 'Failed to start the proposal run');
      }
    },
    // The run answers 202 and its proposals land minutes later, so the queue is
    // invalidated rather than assumed to have changed.
    onSuccess: () => qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'eol-proposals'] }),
  });
}

export interface EolLookupInput {
  product_kind?: ProductKind;
  vendor?: string;
  product: string;
  version?: string;
}

/**
 * Ask what the platform knows about a product.
 *
 * A mutation rather than a query because it has an EFFECT: a lookup that
 * resolves nothing is recorded on the gap list. That is the point of the
 * control — it is how an operator deliberately puts a product in front of the
 * proposal run — and modelling it as a cacheable read would both hide the
 * effect and dedupe away the second ask.
 */
export function useEolLookup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: EolLookupInput): Promise<EolLookupResult> => {
      const { data, error } = await clients.admin.POST('/admin/catalogs/eol/lookup', { body: input });
      if (error || !data) {
        throw new Error((error as { error?: string })?.error ?? 'Lookup failed');
      }
      return data;
    },
    onSuccess: (data) => {
      // Refetch the gap list only when a gap was actually WRITTEN. `!matched`
      // is not the same question: a matched row that publishes no date changes
      // nothing on the list, and a miss the server could not record changes
      // nothing either.
      if (data.miss_recorded) void qc.invalidateQueries({ queryKey: ['platform', 'catalog', 'eol-misses'] });
    },
  });
}

/**
 * How a catalogue row came to exist, for the badge on the End-of-life table.
 *
 * `inferred` is the one that matters: it marks a row a model proposed and a
 * platform admin accepted, and it stays on the row forever. Showing it is what
 * stops an accepted proposal becoming indistinguishable from a mirrored fact.
 */
export const SOURCE_KIND_LABEL: Record<string, string> = {
  measured: 'measured',
  imported: 'mirrored',
  declared: 'declared',
  inferred: 'AI-proposed',
};

export const SOURCE_KIND_COLOR: Record<string, string> = {
  measured: 'var(--ok-lime)',
  imported: 'var(--op-t2)',
  declared: 'var(--info)',
  inferred: 'var(--warn)',
};

/** Human label for why AI proposals are unavailable. */
export function unavailableReason(av: EnrichAvailability | undefined): string {
  if (!av || av.available) return '';
  if (av.reason === 'edition') {
    return 'AI proposals are an Enterprise capability. The catalogue lookup, the gap list and this review queue are Core and work as they are.';
  }
  return 'No model provider is configured on this deployment (AI_PROVIDER), so nothing can be proposed.';
}
