// Typed query hooks for the ADR-0002 asset model.
//
// Everything here goes through the generated inventory-service client, which is
// the only way this UI talks to a backend (CLAUDE.md, "Gateway-First"). Every
// path below exists in the schema — sub-task A2 added `query` to the list and
// the facets, the per-asset endpoint and identifier reads, saved views and the
// merge-proposal endpoints — so there is nothing hand-rolled and nothing cast.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { Asset, inventoryComponents, inventoryPaths } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type AssetHistoryEntry = inventoryComponents['schemas']['AssetHistory'];
export type AssetClassChange = inventoryComponents['schemas']['AssetClassChange'];
export type AssetEndpoint = inventoryComponents['schemas']['AssetEndpoint'];
export type AssetIdentifier = inventoryComponents['schemas']['AssetIdentifier'];
export type AssetFacetBucket = inventoryComponents['schemas']['AssetFacetBucket'];
export type SavedView = inventoryComponents['schemas']['SavedView'];
export type MergeProposal = inventoryComponents['schemas']['MergeProposal'];
export type MergeCandidate = inventoryComponents['schemas']['MergeCandidate'];
export type MergeScoreFactor = inventoryComponents['schemas']['MergeScoreFactor'];
export type IdentificationSettings = inventoryComponents['schemas']['IdentificationSettings'];
export type QueryDiagnostic = inventoryComponents['schemas']['QueryDiagnostic'];

export const ASSETS_PAGE_SIZE = 50;

/**
 * Pull a server-supplied message out of an error envelope.
 *
 * A `query` the server rejects comes back as the structured `QueryError` — the
 * same `{code, message, span, suggestion}` diagnostics the editor renders
 * locally — so its first message is what the user needs to see. A generic
 * "Request failed" would hide the one thing that says how to fix the query.
 */
/**
 * The structured `QueryError` envelope, when that is what came back.
 *
 * The API returns `{ error, query, errors[] }` for a query it refused, where
 * `query` is the text echoed back and each error carries a BYTE span into it
 * (`byteSpanToStringSpan` converts). Pulled out separately from `errorMessage`
 * because the two are different products: the message is what a toast needs,
 * and this is what puts the caret under the offending word.
 *
 * Returns null for any other failure shape, so a caller can fall back to the
 * message rather than rendering an empty diagnostics panel.
 */
export function queryDiagnostics(error: unknown): { query: string; errors: QueryDiagnostic[] } | null {
  if (!error || typeof error !== 'object') return null;
  const e = error as Record<string, unknown>;
  if (typeof e.query !== 'string' || !Array.isArray(e.errors)) return null;
  const errors = e.errors.flatMap((raw): QueryDiagnostic[] => {
    if (!raw || typeof raw !== 'object') return [];
    const d = raw as Record<string, unknown>;
    const span = d.span as Record<string, unknown> | undefined;
    if (typeof d.message !== 'string' || !span) return [];
    if (typeof span.start !== 'number' || typeof span.end !== 'number') return [];
    return [{
      code: typeof d.code === 'string' ? d.code : 'invalid_query',
      message: d.message,
      span: { start: span.start, end: span.end },
      ...(typeof d.suggestion === 'string' ? { suggestion: d.suggestion } : {}),
    }];
  });
  return errors.length > 0 ? { query: e.query, errors } : null;
}

/**
 * An asset read that failed, carrying the server's structured diagnostics when
 * the failure was the QUERY rather than the request.
 *
 * TanStack Query gives a caller whatever the query function threw, and the
 * envelope has to survive that trip: a bare `Error` keeps the first message and
 * discards the spans, the codes, and every problem after the first — which is
 * the whole of what makes the message actionable.
 */
export class AssetQueryError extends Error {
  readonly diagnostics: { query: string; errors: QueryDiagnostic[] } | null;
  constructor(message: string, diagnostics: { query: string; errors: QueryDiagnostic[] } | null) {
    super(message);
    this.name = 'AssetQueryError';
    this.diagnostics = diagnostics;
  }
}

export function errorMessage(error: unknown): string | null {
  if (!error || typeof error !== 'object') return null;
  const e = error as Record<string, unknown>;
  const diagnostics = e.errors;
  if (Array.isArray(diagnostics) && diagnostics.length > 0) {
    const first = diagnostics[0] as Record<string, unknown>;
    const message = typeof first.message === 'string' ? first.message : null;
    const suggestion = typeof first.suggestion === 'string' ? first.suggestion : '';
    if (message) return suggestion ? `${message} — ${suggestion}` : message;
  }
  for (const key of ['message', 'error', 'detail']) {
    const v = e[key];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return null;
}

// ------------------------------------------------------------------ assets --

export interface AssetsPage {
  assets: Asset[];
  total: number;
  page: number;
  pageSize: number;
  /**
   * The predicate that ACTUALLY selected these rows, canonical, as the server
   * echoed it (ADR-0008 D4.4).
   *
   * It is not the string that was sent. The read path adds its own defaults —
   * most visibly the `monitoring`-only status scope a query that names no
   * status inherits — and folds in any deprecated per-field filter, so a user
   * who types `class:server` and counts fewer rows than they expect has no
   * other way to see why. Empty means the server ran no predicate at all.
   */
  appliedQuery: string;
}

/**
 * The server's canonical-query echo, or ''.
 *
 * `query` is OPTIONAL on the envelope and absent means "the predicate was
 * empty" — a real answer, and a different one from "the server did not say".
 * Falling back to the caller's own text would claim the server ran a query it
 * did not, which is the one thing an echo must never do.
 */
export function appliedQueryOf(envelope: { query?: string }): string {
  return typeof envelope.query === 'string' ? envelope.query : '';
}

/**
 * A page of assets for a query string.
 *
 * The query is the ONE predicate (ADR-0006 D2). The deprecated per-field
 * parameters (`search`, `asset_status`, …) are deliberately not sent: the
 * backend still translates them into the same language for one release, but the
 * UI does not use that bridge — two ways to express a filter is how the facet
 * state and the URL drifted apart in the first place.
 */
export function useAssetsQuery(query: string, page: number, enabled = true) {
  return useQuery({
    queryKey: ['inventory', 'assets', 'query', query, page],
    enabled,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<AssetsPage> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets', {
        params: { query: { ...(query ? { query } : {}), page, page_size: ASSETS_PAGE_SIZE } },
      });
      if (error || !data) {
        throw new AssetQueryError(errorMessage(error) ?? 'Failed to load assets', queryDiagnostics(error));
      }
      return {
        assets: data.assets,
        total: data.pagination.total,
        page: data.pagination.page,
        pageSize: data.pagination.page_size,
        appliedQuery: appliedQueryOf(data),
      };
    },
  });
}

/** One asset, full shape — identifiers and endpoints ride along on the single
 *  read (they are omitted from list rows). */
export function useAsset(id: string | undefined) {
  return useQuery({
    queryKey: ['asset-detail', id],
    enabled: !!id,
    queryFn: async (): Promise<Asset> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}', {
        params: { path: { id: id! } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load asset');
      return data.asset;
    },
  });
}

/**
 * The asset's endpoints, most recently seen active first — the same order the
 * list row's primary endpoint is picked in.
 *
 * The single-asset read already embeds them, so this prefers that and only
 * calls the dedicated path when the embedded list is absent. An EMPTY array is
 * a real answer, not an error: an at-rest cloud resource has no endpoint at all.
 */
export function useAssetEndpoints(id: string | undefined, embedded?: AssetEndpoint[] | null) {
  return useQuery({
    queryKey: ['asset-endpoints', id],
    enabled: !!id && !embedded,
    queryFn: async (): Promise<AssetEndpoint[]> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/endpoints', {
        params: { path: { id: id! } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load endpoints');
      return data.endpoints;
    },
    initialData: embedded ?? undefined,
  });
}

/** The asset's identifiers, strongest first, same embedded-first arrangement. */
export function useAssetIdentifiers(id: string | undefined, embedded?: AssetIdentifier[] | null) {
  return useQuery({
    queryKey: ['asset-identifiers', id],
    enabled: !!id && !embedded,
    queryFn: async (): Promise<AssetIdentifier[]> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/identifiers', {
        params: { path: { id: id! } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load identifiers');
      return data.identifiers;
    },
    initialData: embedded ?? undefined,
  });
}

/**
 * The asset's change history, newest first.
 *
 * Ordering is asserted here rather than assumed: a timeline that renders in
 * whatever order the rows arrived is a timeline that will one day read
 * backwards after an index change, and nothing would fail.
 */
export function useAssetHistory(id: string | undefined) {
  return useQuery({
    queryKey: ['asset-history', id],
    enabled: !!id,
    queryFn: async (): Promise<AssetHistoryEntry[]> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/history', {
        params: { path: { id: id! } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load asset history');
      return sortHistory(data.history ?? []);
    },
  });
}

/**
 * The asset's CLASS history — every class it has held, newest first.
 *
 * Separate from the change history above rather than folded into it, because it
 * is a different question. `asset_history` is a log of edits; this answers "was
 * this thing ever something else", which is what somebody looking at a finding
 * written against the old class needs and could not previously ask at all.
 *
 * An empty list means the asset predates the record, NOT that it has always
 * been what it is — the panel says so rather than rendering a clean timeline.
 */
export function useAssetClassHistory(id: string | undefined) {
  return useQuery({
    queryKey: ['asset-class-history', id],
    enabled: !!id,
    queryFn: async (): Promise<AssetClassChange[]> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/class-history', {
        params: { path: { id: id! } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load class history');
      return data.class_history ?? [];
    },
  });
}

/** How a class moved, in the words a reader uses. The keys are the closed
 *  `source` set the API publishes; an unrecognised one renders verbatim rather
 *  than as "Unknown", which would hide a value we simply have no phrase for. */
export const CLASS_CHANGE_SOURCE_LABELS: Record<string, string> = {
  classifier: 'Set at discovery',
  proposal: 'Accepted in Approvals',
  manual: 'Edited by a person',
  import: 'Stated by an import',
};

/** Newest first, with undated rows last — they cannot be placed on a timeline
 *  and putting them at the top would date them to now. */
export function sortHistory(rows: AssetHistoryEntry[]): AssetHistoryEntry[] {
  return [...rows].sort((x, y) => {
    const tx = x.created_at ? new Date(x.created_at).getTime() : NaN;
    const ty = y.created_at ? new Date(y.created_at).getTime() : NaN;
    if (!Number.isFinite(tx) && !Number.isFinite(ty)) return 0;
    if (!Number.isFinite(tx)) return 1;
    if (!Number.isFinite(ty)) return -1;
    return ty - tx;
  });
}

/** The asset's crypto configurations — unchanged behaviour, moved from the
 *  drawer to the page's Cryptography tab. */
export function useAssetConfigs(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['asset-configs', id],
    enabled: !!id && enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/crypto-configurations', {
        params: { query: { asset_id: id!, page: 1, page_size: 100 } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load crypto configurations');
      return data.crypto_implementations ?? [];
    },
  });
}

// ------------------------------------------------------------------ facets --

export type FacetBuckets = Record<string, AssetFacetBucket[]>;

/**
 * Facet counts, plus the levels that did NOT answer.
 *
 * A level has three states, not two: it returned buckets, it returned none, or
 * it failed. Folding the third into the second is how a 500 from the `site`
 * level came to render as the sentence "No sites recorded." — an assertion
 * about the tenant's data made on the strength of a failed request. The rail
 * needs to be able to tell them apart, so the failure is carried rather than
 * swallowed.
 */
export interface FacetData {
  buckets: FacetBuckets;
  /** Server-side level names (`owner_email`, `source`, …) that failed. */
  failed: string[];
}

/**
 * Facet counts for the current query.
 *
 * The facets take the SAME query the list does, so the numbers describe the
 * filtered set — "a rail whose numbers do not move when you filter is a rail
 * nobody trusts twice" (the endpoint's own words).
 */
/**
 * A facet level the server actually serves. Derived from the contract so a
 * level the endpoint does not serve cannot be requested by the rail:
 * TypeScript refuses it here instead of the server answering 400 and the rail
 * drawing a permanently empty section.
 */
export type FacetLevel = NonNullable<
  inventoryPaths['/infrastructure-assets/facets']['get']['parameters']['query']
>['level'];

export function useAssetFacets(query: string, levels: readonly FacetLevel[], enabled = true) {
  return useQuery({
    queryKey: ['inventory', 'assets', 'facets', query, levels.join(',')],
    enabled,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<FacetData> => {
      const out: FacetBuckets = {};
      const failed: string[] = [];
      await Promise.all(levels.map(async (level) => {
        const { data, error } = await clients.inventory.GET('/infrastructure-assets/facets', {
          params: { query: { ...(query ? { query } : {}), level } },
        });
        // One facet failing must not blank the rail: the others are still true.
        // But the failure is RECORDED rather than flattened into an empty
        // bucket list, because the rail's empty state is a sentence about the
        // tenant's data ("No sites recorded.") and a failed request is not
        // evidence for it.
        if (error || !data) {
          failed.push(level);
          out[level] = [];
          return;
        }
        out[level] = data.buckets ?? [];
      }));
      return { buckets: out, failed };
    },
  });
}

/** Turn a bucket list into a value → count map for O(1) lookup in the rail. */
export function bucketMap(buckets: AssetFacetBucket[] | undefined): Record<string, number> {
  const out: Record<string, number> = {};
  for (const b of buckets ?? []) out[b.value] = b.count;
  return out;
}

// ------------------------------------------------------------- saved views --

/** The caller's own views plus every view shared with the tenant. */
export function useSavedViews(target = 'asset', enabled = true) {
  return useQuery({
    queryKey: ['inventory', 'saved-views', target],
    enabled,
    queryFn: async (): Promise<SavedView[]> => {
      const { data, error } = await clients.inventory.GET('/saved-views', {
        params: { query: { target } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load saved views');
      return data.saved_views;
    },
  });
}

export function useCreateSavedView() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: { name: string; query: string; is_shared?: boolean }): Promise<SavedView> => {
      const { data, error } = await clients.inventory.POST('/saved-views', {
        body: { name: input.name, query: input.query, target: 'asset', is_shared: input.is_shared ?? false },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to save the view');
      return data.saved_view;
    },
    onSuccess: (v) => toast.success(`Saved view “${v.name}”`),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to save the view'),
    onSettled: () => { void qc.invalidateQueries({ queryKey: ['inventory', 'saved-views'] }); },
  });
}

export function useDeleteSavedView() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.inventory.DELETE('/saved-views/{id}', { params: { path: { id } } });
      if (error) throw new Error(errorMessage(error) ?? 'Failed to delete the view');
    },
    onSuccess: () => toast.success('View deleted'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to delete the view'),
    onSettled: () => { void qc.invalidateQueries({ queryKey: ['inventory', 'saved-views'] }); },
  });
}

// -------------------------------------------------------- merge proposals --

/**
 * The pending merge proposals.
 *
 * A proposal is an OBSERVATION (a new sighting) plus the candidates its
 * identifiers resolved to, each carrying the identifiers that matched it and
 * the matcher's score. Nothing is ever merged automatically — even an
 * `auto_accepted` proposal leaves its remaining candidates for a person.
 */
export const MERGE_PROPOSALS_PAGE_SIZE = 50;

/** One page of proposals, plus how many there are altogether. */
export interface MergeProposalPage {
  proposals: MergeProposal[];
  /** Every pending proposal in the tenant — NOT the length of `proposals`. */
  total: number;
  limit: number;
  offset: number;
}

/**
 * Read the list envelope.
 *
 * `total` is the count to show. The page stops at the server's limit (50 by
 * default), so `proposals.length` answers "how many did I just fetch", which is
 * the question nobody asked — and using it as the queue count meant a tenant
 * with 132 proposals was told it had 50, on the Approvals page AND in the
 * "awaiting review" banner on Inventory.
 */
export function readMergeProposalPage(data: {
  merge_proposals?: MergeProposal[];
  total?: number;
  limit?: number;
  offset?: number;
} | undefined): MergeProposalPage {
  const proposals = data?.merge_proposals ?? [];
  return {
    proposals,
    // The fallback is for an envelope without the field at all; a real 0 is
    // still 0, because `??` does not treat it as missing.
    total: data?.total ?? proposals.length,
    limit: data?.limit ?? MERGE_PROPOSALS_PAGE_SIZE,
    offset: data?.offset ?? 0,
  };
}

/** "1–50 of 132" — or "" when everything fits on one page. */
export function mergeProposalRangeLabel(page: MergeProposalPage): string {
  if (page.total <= page.proposals.length && page.offset === 0) return '';
  const first = page.offset + 1;
  const last = page.offset + page.proposals.length;
  return `${first}–${last} of ${page.total}`;
}

export function useMergeProposals(enabled = true, offset = 0) {
  return useQuery({
    queryKey: ['discovery', 'merge-proposals', offset],
    enabled,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<MergeProposalPage> => {
      const { data, error } = await clients.inventory.GET('/approvals/merge-proposals', {
        params: { query: { limit: MERGE_PROPOSALS_PAGE_SIZE, offset } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load merge proposals');
      return readMergeProposalPage(data);
    },
  });
}

/**
 * What the matcher merged WITHOUT asking, in the last thirty days.
 *
 * Not a queue — nothing here needs deciding, and everything here already
 * happened. It is the record that makes an unattended capability visible to the
 * human who enabled it. A tenant on the default threshold of zero always gets
 * an empty list, because nothing can have been auto-accepted, so the section it
 * feeds renders only when there is something in it.
 */
export interface AutoAcceptedMerges {
  merges: MergeProposal[];
  /** The window the server actually counted over, so the heading cannot lie. */
  windowDays: number;
}

export const AUTO_ACCEPTED_MERGES_PAGE_SIZE = 20;

export function useAutoAcceptedMerges(enabled = true) {
  return useQuery({
    queryKey: ['discovery', 'auto-accepted-merges'],
    enabled,
    queryFn: async (): Promise<AutoAcceptedMerges> => {
      const { data, error } = await clients.inventory.GET('/approvals/merge-proposals/auto-accepted', {
        params: { query: { limit: AUTO_ACCEPTED_MERGES_PAGE_SIZE } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load auto-accepted merges');
      return { merges: data.merges ?? [], windowDays: data.window_days ?? 30 };
    },
  });
}

/**
 * The tenant's identification settings — today, the auto-accept threshold.
 *
 * Read on Settings → Identification rules, and nowhere else: the threshold is
 * not a display preference, it is a permission, and scattering reads of it
 * would make "who can see what this is set to" a question with several answers.
 */
export function useIdentificationSettings(enabled = true) {
  return useQuery({
    queryKey: ['settings', 'identification'],
    enabled,
    queryFn: async (): Promise<IdentificationSettings> => {
      const { data, error } = await clients.inventory.GET('/settings/identification', {});
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load the identification settings');
      return data.identification;
    },
  });
}

/**
 * Set the auto-accept threshold.
 *
 * Sending 0 is a real act — it turns auto-accept OFF — so the mutation always
 * sends the number rather than omitting a falsy one. Anything that treated 0 as
 * "nothing to send" would leave a tenant who has just switched auto-merge off
 * still auto-merging.
 */
export function useSetAutoAcceptThreshold() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (threshold: number) => {
      const { data, error } = await clients.inventory.PUT('/settings/identification', {
        body: { auto_accept_threshold: threshold },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to save the threshold');
      return data.identification;
    },
    onSuccess: (s) => toast.success(
      s.auto_accept_threshold > 0
        ? `Merges scoring ${Math.round(s.auto_accept_threshold * 100)}% or higher will be accepted automatically`
        : 'Auto-accept is off — every merge proposal waits for a person',
    ),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to save the threshold'),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['settings', 'identification'] });
    },
  });
}

/**
 * Accept a proposal into a chosen survivor, or record that these are different
 * things.
 *
 * `survivorAssetId` is REQUIRED by the server on accept and must be one of the
 * proposal's own candidates: merging is destructive, so neither the server nor
 * this hook picks for the reviewer.
 */
export function useResolveMergeProposal() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input:
      | { action: 'accept'; id: string; survivorAssetId: string }
      | { action: 'keep-separate'; id: string }) => {
      if (input.action === 'accept') {
        const { error } = await clients.inventory.POST('/approvals/merge-proposals/{id}/accept', {
          params: { path: { id: input.id } },
          body: { survivor_asset_id: input.survivorAssetId },
        });
        if (error) throw new Error(errorMessage(error) ?? 'Failed to merge');
      } else {
        const { error } = await clients.inventory.POST('/approvals/merge-proposals/{id}/keep-separate', {
          params: { path: { id: input.id } },
        });
        if (error) throw new Error(errorMessage(error) ?? 'Failed to keep separate');
      }
      return input;
    },
    onSuccess: (r) => toast.success(r.action === 'accept' ? 'Assets merged' : 'Kept separate'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to resolve the proposal'),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'merge-proposals'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'pending-assets'] });
      void qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });
}
