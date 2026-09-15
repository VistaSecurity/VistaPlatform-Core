import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { EolPage } from './eol-page';
import { VulnerabilityPage } from './vulnerability-page';
import { FeedStatusCard } from './feed-status-card';
import { BundleImportError } from './catalog-queries';
import type {
  CatalogBundleImport, CatalogFeedList, CatalogFeedStatus, EolEntry, Page, VulnerabilityEntry,
} from './catalog-queries';

// Every screen state of the two catalogue pages, rendered. These pages are the
// ONLY place an operator can see whether the mirror feeds are working, so the
// states that are easy to leave out — never run, running, failed, disabled,
// empty, error — are the ones pinned here.

const queryState = vi.hoisted(() => ({
  eol: { data: undefined as Page<EolEntry> | undefined, isLoading: false, isError: false, refetch: vi.fn() },
  vulns: { data: undefined as Page<VulnerabilityEntry> | undefined, isLoading: false, isError: false, refetch: vi.fn() },
  feeds: { data: undefined as CatalogFeedList | undefined, isLoading: false, isError: false, refetch: vi.fn() },
  sync: { mutate: vi.fn(), isPending: false },
  importBundle: {
    mutate: vi.fn(), isPending: false, isSuccess: false, isError: false,
    data: undefined as CatalogBundleImport | undefined, error: undefined as Error | undefined,
  },
  inert: { data: undefined, isLoading: false, isError: false, refetch: vi.fn() },
  mutation: { mutate: vi.fn(), isPending: false, isSuccess: false, data: undefined },
}));

vi.mock('./catalog-queries', async (importOriginal) => {
  // The pure presentation helpers (daysUntil, shortDate, the label maps) are
  // part of what these tests assert, so the real module is kept and only the
  // hooks are replaced.
  const actual = await importOriginal<typeof import('./catalog-queries')>();
  return {
    ...actual,
    useEolCatalogue: () => queryState.eol,
    useVulnerabilityCatalogue: () => queryState.vulns,
    useCatalogFeeds: () => queryState.feeds,
    useSyncCatalogFeed: () => queryState.sync,
    useImportCatalogBundle: () => queryState.importBundle,
    // The enricher views are rendered here only to prove the ROUTE picks one
    // view; their own states are pinned in eol-proposals.test.tsx. Inert
    // stand-ins keep this file from needing a QueryClient.
    useEolProposals: () => queryState.inert,
    useCatalogMisses: () => queryState.inert,
    useEnrichAvailability: () => queryState.inert,
    useReviewProposal: () => queryState.mutation,
    useRunEnrichment: () => queryState.mutation,
    useEolLookup: () => queryState.mutation,
  };
});

// The permission gate reads a context this test does not mount; render its
// children so the write controls are asserted. Whether the gate itself works is
// the primitives package's test, not this one's.
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    PlatformPermissionGate: ({ children }: { children: unknown }) => children,
  };
});

const feed = (over: Partial<CatalogFeedStatus> = {}): CatalogFeedStatus => ({
  feed: 'eol',
  cursor: null,
  last_run_at: null,
  last_status: 'never',
  last_error: null,
  row_count: 0,
  ...over,
});

const feedList = (feeds: CatalogFeedStatus[], over: Partial<CatalogFeedList> = {}): CatalogFeedList => ({
  feeds,
  enabled: true,
  interval_seconds: 86400,
  ...over,
});

const eolRow = (over: Partial<EolEntry> = {}): EolEntry => ({
  id: '11111111-1111-4111-8111-111111111111',
  product_kind: 'os',
  vendor: 'Canonical',
  product: 'ubuntu',
  cycle: '22.04',
  release_date: '2022-04-21T00:00:00Z',
  eol_date: '2027-04-01T00:00:00Z',
  extended_support_date: null,
  source_url: 'https://endoflife.date/ubuntu',
  source_kind: 'imported',
  ...over,
});

const vulnRow = (over: Partial<VulnerabilityEntry> = {}): VulnerabilityEntry => ({
  cve_id: 'CVE-2024-3094',
  cvss_version: '3.1',
  cvss_score: 10,
  cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  severity: 'critical',
  published_at: '2024-03-29T17:15:21Z',
  modified_at: '2024-08-14T19:15:10Z',
  description: 'Malicious code was discovered in the upstream tarballs of xz.',
  source_kind: 'imported',
  ...over,
});

beforeEach(() => {
  queryState.eol = { data: undefined, isLoading: false, isError: false, refetch: vi.fn() };
  queryState.vulns = { data: undefined, isLoading: false, isError: false, refetch: vi.fn() };
  queryState.feeds = { data: feedList([feed()]), isLoading: false, isError: false, refetch: vi.fn() };
  queryState.sync = { mutate: vi.fn(), isPending: false };
  queryState.importBundle = {
    mutate: vi.fn(), isPending: false, isSuccess: false, isError: false, data: undefined, error: undefined,
  };
});

describe('Catalog ▸ End-of-life', () => {
  it('renders the loading state', () => {
    queryState.eol.isLoading = true;
    const html = renderToStaticMarkup(createElement(EolPage));
    expect(html).toContain('Loading the end-of-life catalogue…');
  });

  it('renders the error state with a retry', () => {
    queryState.eol.isError = true;
    const html = renderToStaticMarkup(createElement(EolPage));
    // renderToStaticMarkup escapes the apostrophe, so match the unambiguous tail.
    expect(html).toContain('t load the end-of-life catalogue.');
    expect(html).toContain('Retry');
  });

  it('tells an operator how to fill an empty catalogue', () => {
    queryState.eol.data = { rows: [], total: 0, page: 1, pageSize: 50 };
    const html = renderToStaticMarkup(createElement(EolPage));
    expect(html).toContain('The catalogue is empty.');
    expect(html).toContain('import an offline bundle');
  });

  it('renders rows with product, kind, vendor and the support-end date', () => {
    queryState.eol.data = { rows: [eolRow()], total: 1, page: 1, pageSize: 50 };
    const html = renderToStaticMarkup(createElement(EolPage));
    expect(html).toContain('ubuntu');
    expect(html).toContain('Canonical');
    expect(html).toContain('22.04');
    expect(html).toContain('2027-04-01');
    expect(html).toContain('1 cycles');
  });

  // A missing eol_date is "not published", never "0 days". The source says
  // `true` for "ended, date unknown" and `false` for "not announced"; both
  // become NULL, and a fabricated number here would be a precise-looking
  // countdown derived from nothing.
  it('renders a missing end-of-life date as not published, not as zero days', () => {
    queryState.eol.data = { rows: [eolRow({ eol_date: null })], total: 1, page: 1, pageSize: 50 };
    const html = renderToStaticMarkup(createElement(EolPage));
    expect(html).toContain('not published');
    expect(html).not.toContain('in 0d');
    expect(html).not.toContain('0d ago');
  });

  it('renders an unknown vendor as unknown rather than blank', () => {
    queryState.eol.data = { rows: [eolRow({ vendor: null })], total: 1, page: 1, pageSize: 50 };
    const html = renderToStaticMarkup(createElement(EolPage));
    expect(html).toContain('unknown');
  });

  it('shows pagination only when there are rows', () => {
    queryState.eol.data = { rows: [eolRow()], total: 120, page: 2, pageSize: 50 };
    const withRows = renderToStaticMarkup(createElement(EolPage));
    expect(withRows).toContain('Page 2 of 3');

    queryState.eol.data = { rows: [], total: 0, page: 1, pageSize: 50 };
    const empty = renderToStaticMarkup(createElement(EolPage));
    expect(empty).not.toContain('Page 1 of');
  });

  it('attributes the source', () => {
    queryState.eol.data = { rows: [], total: 0, page: 1, pageSize: 50 };
    const html = renderToStaticMarkup(createElement(EolPage));
    expect(html).toContain('endoflife.date');
  });

  // The catalogue, the AI proposal queue and the gap list are three views of
  // one resource, and each is its own LEFT-RAIL sub-route — this console puts
  // sub-navigation in the rail, never in in-page tabs. So the page renders one
  // view, chosen by the route, and does NOT render a tab strip of its own.
  it('renders only the view the route selected, with no in-page tab strip', () => {
    queryState.eol.data = { rows: [eolRow()], total: 1, page: 1, pageSize: 50 };
    const catalogue = renderToStaticMarkup(createElement(EolPage));
    expect(catalogue).toContain('End-of-life catalogue');
    // The other two views' own headings must be absent: an in-page switcher
    // would put all three labels on the page at once, which is the pattern
    // this console does not use.
    expect(catalogue).not.toContain('AI proposals');
    expect(catalogue).not.toContain('Check a product');

    const proposals = renderToStaticMarkup(createElement(EolPage, { view: 'proposals' as const }));
    expect(proposals).toContain('AI proposals');
    expect(proposals).not.toContain('End-of-life catalogue');

    const gaps = renderToStaticMarkup(createElement(EolPage, { view: 'gaps' as const }));
    expect(gaps).toContain('Check a product');
    expect(gaps).not.toContain('End-of-life catalogue');
  });

  // Every view keeps the feed card: all three are views of what the mirror
  // fills, and a Gaps list with no way to see the feed is half a diagnosis.
  it('keeps the feed status card above every view', () => {
    queryState.eol.data = { rows: [], total: 0, page: 1, pageSize: 50 };
    for (const view of ['catalogue', 'proposals', 'gaps'] as const) {
      expect(renderToStaticMarkup(createElement(EolPage, { view })))
        .toContain('End-of-life feed');
    }
  });

  // A row a model proposed and an admin accepted must stay distinguishable
  // from a mirrored one, forever. That is the whole reason accept writes
  // source_kind = inferred rather than imported.
  it('badges how each row came to exist', () => {
    queryState.eol.data = { rows: [eolRow()], total: 1, page: 1, pageSize: 50 };
    expect(renderToStaticMarkup(createElement(EolPage))).toContain('mirrored');

    queryState.eol.data = {
      rows: [eolRow({ source_kind: 'inferred' })], total: 1, page: 1, pageSize: 50,
    };
    expect(renderToStaticMarkup(createElement(EolPage))).toContain('AI-proposed');
  });
});

describe('Catalog ▸ Vulnerability feed', () => {
  it('renders the loading state', () => {
    queryState.vulns.isLoading = true;
    const html = renderToStaticMarkup(createElement(VulnerabilityPage));
    expect(html).toContain('Loading the vulnerability catalogue…');
  });

  it('renders the error state with a retry', () => {
    queryState.vulns.isError = true;
    const html = renderToStaticMarkup(createElement(VulnerabilityPage));
    expect(html).toContain('t load the vulnerability catalogue.');
  });

  it('tells an operator how to fill an empty catalogue', () => {
    queryState.vulns.data = { rows: [], total: 0, page: 1, pageSize: 50 };
    const html = renderToStaticMarkup(createElement(VulnerabilityPage));
    expect(html).toContain('The catalogue is empty.');
  });

  it('renders a scored CVE with its band and ladder version', () => {
    queryState.vulns.data = { rows: [vulnRow()], total: 1, page: 1, pageSize: 50 };
    const html = renderToStaticMarkup(createElement(VulnerabilityPage));
    expect(html).toContain('CVE-2024-3094');
    expect(html).toContain('critical');
    expect(html).toContain('10.0');
    expect(html).toContain('v3.1');
  });

  // OSV publishes a vector and no base score. Showing a blank or a 0 would read
  // as "not serious"; "vector only" says which half is missing and why.
  it('renders an OSV-only CVE as vector only rather than a zero score', () => {
    queryState.vulns.data = {
      rows: [vulnRow({ cvss_score: null, severity: null })], total: 1, page: 1, pageSize: 50,
    };
    const html = renderToStaticMarkup(createElement(VulnerabilityPage));
    expect(html).toContain('vector only');
    expect(html).toContain('unrated');
    expect(html).not.toContain('>0.0<');
  });

  it('notes the NVD rate limit and the CVE-keyed coverage gap', () => {
    queryState.vulns.data = { rows: [], total: 0, page: 1, pageSize: 50 };
    const html = renderToStaticMarkup(createElement(VulnerabilityPage));
    expect(html).toContain('NVD_API_KEY');
    expect(html).toContain('no CVE assigned is not mirrored');
  });
});

describe('the mirror-feed status card', () => {
  const card = (feeds: Parameters<typeof FeedStatusCard>[0]['feeds'] = ['eol']) =>
    renderToStaticMarkup(createElement(FeedStatusCard, { feeds, title: 'End-of-life feed' }));

  it('renders the loading state', () => {
    queryState.feeds = { data: undefined, isLoading: true, isError: false, refetch: vi.fn() };
    expect(card()).toContain('Loading feed status…');
  });

  it('renders the error state with a retry', () => {
    queryState.feeds = { data: undefined, isLoading: false, isError: true, refetch: vi.fn() };
    const html = card();
    expect(html).toContain('t load feed status.');
    expect(html).toContain('Retry');
  });

  // "Never run" is an answer, not an absence. A feed omitted from the list
  // would read as "there is no such feed".
  it('lists a feed that has never run, with a Sync now button', () => {
    queryState.feeds.data = feedList([feed({ feed: 'eol', last_status: 'never' })]);
    const html = card();
    expect(html).toContain('Never run');
    expect(html).toContain('endoflife.date');
    expect(html).toContain('Sync now');
  });

  it('renders a successful run with its row count and bookmark', () => {
    queryState.feeds.data = feedList([
      feed({ feed: 'eol', last_status: 'ok', last_run_at: new Date().toISOString(), row_count: 1842, cursor: '2026-09-11T00:00:00Z' }),
    ]);
    const html = card();
    expect(html).toContain('OK');
    expect(html).toContain('1,842');
    expect(html).toContain('2026-09-11T00:00:00Z');
  });

  it('surfaces a failed run WITH its error and says the bookmark did not move', () => {
    queryState.feeds.data = feedList([
      feed({ feed: 'eol', last_status: 'error', last_error: 'nvd window 2026-09-10..2026-09-11: 403 rate limit exceeded', last_run_at: new Date().toISOString() }),
    ]);
    const html = card();
    expect(html).toContain('403 rate limit exceeded');
    expect(html).toContain('bookmark was not advanced');
  });

  it('disables Sync now while a run is in flight', () => {
    queryState.feeds.data = feedList([feed({ feed: 'eol', last_status: 'running' })]);
    const html = card();
    expect(html).toContain('Running');
    expect(html).toContain('disabled');
  });

  // The kill switch must be VISIBLE. Without this banner an operator watching
  // "last run" never move has no way to tell a broken feed from a switched-off
  // one.
  it('explains the kill switch when the deployment has feeds disabled', () => {
    queryState.feeds.data = feedList([feed()], { enabled: false });
    const html = card();
    expect(html).toContain('CATALOG_FEEDS_ENABLED=false');
    expect(html).toContain('An offline bundle can still be imported.');
    expect(html).toContain('disabled');
  });

  it('offers the offline-bundle import and says verification comes first', () => {
    queryState.feeds.data = feedList([feed()]);
    const html = card();
    expect(html).toContain('Import bundle');
    expect(html).toContain('make build-catalog-bundle');
    expect(html).toContain("SHA-256 and row count is checked before a single row is applied");
  });

  it('reports a successful import with what it applied', () => {
    queryState.feeds.data = feedList([feed()]);
    queryState.importBundle.isSuccess = true;
    queryState.importBundle.data = {
      files: [], eol_rows: 1842, vulnerability_rows: 90210, match_rows: 412000,
      generated_at: '2026-09-10T00:00:00Z', message: 'ok',
    };
    const html = card();
    expect(html).toContain('1,842');
    expect(html).toContain('90,210');
    expect(html).toContain('2026-09-10');
  });

  // The verification failure IS the diagnosis; it must reach the screen.
  it('surfaces a refused bundle verbatim and says nothing was applied', () => {
    queryState.feeds.data = feedList([feed()]);
    queryState.importBundle.isError = true;
    queryState.importBundle.error = new Error('vulnerability_catalogue.jsonl: sha256 mismatch — manifest says abc, bundle contains def');
    const html = card();
    expect(html).toContain('sha256 mismatch');
    expect(html).toContain('Bundle refused.');
    expect(html).toContain('Nothing was applied');
  });

  // A failure AFTER verification passed has already written rows. Rendering
  // "nothing was applied" there sends the operator away believing a
  // half-imported catalogue is an untouched one.
  it('does NOT claim nothing was applied when the apply failed partway', () => {
    queryState.feeds.data = feedList([feed()]);
    queryState.importBundle.isError = true;
    queryState.importBundle.error = new BundleImportError(
      'the bundle verified but applying it failed partway after 1842 end-of-life rows and 0 vulnerabilities: connection reset by peer',
      true,
    );
    const html = card();
    expect(html).toContain('Bundle partly applied.');
    expect(html).toContain('some rows were written');
    expect(html).toContain('import is idempotent');
    expect(html).not.toContain('Nothing was applied');
  });

  it('shows only the feeds that fill the catalogue it sits on', () => {
    queryState.feeds.data = feedList([
      feed({ feed: 'eol' }), feed({ feed: 'nvd' }), feed({ feed: 'osv' }),
    ]);
    const eolOnly = card(['eol']);
    expect(eolOnly).toContain('endoflife.date');
    expect(eolOnly).not.toContain('NVD (NIST)');

    const vulnOnly = card(['nvd', 'osv']);
    expect(vulnOnly).toContain('NVD (NIST)');
    expect(vulnOnly).toContain('OSV (osv.dev)');
    expect(vulnOnly).not.toContain('endoflife.date');
  });

  it('says nothing rather than inventing feeds when the deployment reports none', () => {
    queryState.feeds.data = feedList([]);
    expect(card()).toContain('reports no feeds for this catalogue');
  });
});
