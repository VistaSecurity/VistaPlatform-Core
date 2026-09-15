import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { CatalogGapsTab, EolProposalsTab } from './eol-proposals';
import { unavailableReason } from './catalog-queries';
import type {
  CatalogMiss, EnrichAvailability, EolLookupResult, EolProposal, Page,
} from './catalog-queries';

// Every screen state of the Enricher seam's two views.
//
// The states pinned hardest are the ones that make the review honest: the cited
// URL is a link a reviewer can open, a date the model declined to state reads as
// "not stated" rather than as a blank, and the "Propose with AI" button is
// absent unless the deployment says a run would work.

const queryState = vi.hoisted(() => ({
  proposals: { data: undefined as Page<EolProposal> | undefined, isLoading: false, isError: false, refetch: vi.fn() },
  misses: { data: undefined as Page<CatalogMiss> | undefined, isLoading: false, isError: false, refetch: vi.fn() },
  availability: { data: undefined as EnrichAvailability | undefined, isLoading: false, isError: false },
  accept: { mutate: vi.fn(), isPending: false },
  reject: { mutate: vi.fn(), isPending: false },
  run: { mutate: vi.fn(), isPending: false },
  lookup: {
    mutate: vi.fn(), isPending: false, isSuccess: false,
    data: undefined as EolLookupResult | undefined,
  },
}));

vi.mock('./catalog-queries', async (importOriginal) => {
  // The pure helpers (shortDate, unavailableReason, the label maps) are part of
  // what these tests assert, so the real module is kept and only the hooks are
  // replaced.
  const actual = await importOriginal<typeof import('./catalog-queries')>();
  return {
    ...actual,
    useEolProposals: () => queryState.proposals,
    useCatalogMisses: () => queryState.misses,
    useEnrichAvailability: () => queryState.availability,
    useReviewProposal: (action: 'accept' | 'reject') =>
      (action === 'accept' ? queryState.accept : queryState.reject),
    useRunEnrichment: () => queryState.run,
    useEolLookup: () => queryState.lookup,
  };
});

const proposal = (over: Partial<EolProposal> = {}): EolProposal => ({
  id: '11111111-1111-4111-8111-111111111111',
  product_kind: 'os',
  subject_vendor: 'Cisco',
  subject_product: 'IOS-XE',
  subject_version: '17.9.4a',
  proposed_cycle: '17.9',
  proposed_release_date: '2022-11-14T00:00:00Z',
  proposed_eol_date: '2027-04-30T00:00:00Z',
  proposed_extended_support_date: null,
  source_url: 'https://www.cisco.com/c/en/us/products/eos-eol-notice.html',
  model_id: 'claude-test-1',
  source_kind: 'inferred',
  confidence: 0,
  status: 'pending',
  reviewer_id: null,
  reviewer_email: null,
  reviewed_at: null,
  created_at: '2026-09-11T06:00:00Z',
  updated_at: '2026-09-11T06:00:00Z',
  ...over,
});

const miss = (over: Partial<CatalogMiss> = {}): CatalogMiss => ({
  id: '22222222-2222-4222-8222-222222222222',
  product_kind: 'os',
  vendor: 'Cisco',
  product: 'IOS-XE',
  version: '17.9.4a',
  miss_count: 412,
  first_seen_at: '2026-09-01T00:00:00Z',
  last_seen_at: '2026-09-11T00:00:00Z',
  last_proposed_at: null,
  ...over,
});

const page = <T,>(rows: T[]): Page<T> => ({ rows, total: rows.length, page: 1, pageSize: 50 });

beforeEach(() => {
  queryState.proposals = { data: undefined, isLoading: false, isError: false, refetch: vi.fn() };
  queryState.misses = { data: undefined, isLoading: false, isError: false, refetch: vi.fn() };
  queryState.availability = { data: undefined, isLoading: false, isError: false };
  queryState.accept = { mutate: vi.fn(), isPending: false };
  queryState.reject = { mutate: vi.fn(), isPending: false };
  queryState.run = { mutate: vi.fn(), isPending: false };
  queryState.lookup = { mutate: vi.fn(), isPending: false, isSuccess: false, data: undefined };
});

describe('Catalog ▸ End-of-life ▸ Proposals', () => {
  it('renders the loading state', () => {
    queryState.proposals.isLoading = true;
    expect(renderToStaticMarkup(createElement(EolProposalsTab))).toContain('Loading proposals…');
  });

  it('renders the error state with a retry', () => {
    queryState.proposals.isError = true;
    const html = renderToStaticMarkup(createElement(EolProposalsTab));
    expect(html).toContain('t load the proposal queue.');
    expect(html).toContain('Retry');
  });

  // A Core deployment's steady state, and it must not read as broken.
  it('explains an empty queue rather than showing a bare table', () => {
    queryState.proposals.data = page<EolProposal>([]);
    const html = renderToStaticMarkup(createElement(EolProposalsTab));
    expect(html).toContain('Nothing is waiting for review');
    expect(html).toContain('Gaps');
  });

  it('shows the subject that was asked about beside what came back', () => {
    queryState.proposals.data = page([proposal()]);
    const html = renderToStaticMarkup(createElement(EolProposalsTab));
    expect(html).toContain('Cisco IOS-XE 17.9.4a');
    expect(html).toContain('17.9');
    expect(html).toContain('2027-04-30');
  });

  // Cite or refuse, made checkable: the URL has to be a LINK, because the
  // review is opening it and reading the vendor's own page.
  it('renders the cited source as an openable link, with the model that said it', () => {
    queryState.proposals.data = page([proposal()]);
    const html = renderToStaticMarkup(createElement(EolProposalsTab));
    expect(html).toContain('href="https://www.cisco.com/c/en/us/products/eos-eol-notice.html"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('claude-test-1');
  });

  // An omitted date is the model obeying "never guess a date". A blank cell
  // would read as a value of nothing.
  it('renders a date the model declined to state as "not stated"', () => {
    queryState.proposals.data = page([proposal({ proposed_eol_date: null })]);
    const html = renderToStaticMarkup(createElement(EolProposalsTab));
    expect(html).toContain('not stated');
  });

  it('offers accept and reject only on a pending proposal', () => {
    queryState.proposals.data = page([proposal()]);
    const pending = renderToStaticMarkup(createElement(EolProposalsTab));
    expect(pending).toContain('Accept');
    expect(pending).toContain('Reject');

    queryState.proposals.data = page([proposal({
      status: 'accepted', reviewer_email: 'admin@example.com', reviewed_at: '2026-09-11T08:00:00Z',
    })]);
    const reviewed = renderToStaticMarkup(createElement(EolProposalsTab));
    expect(reviewed).not.toContain('aria-label="Accept the proposal');
    expect(reviewed).toContain('admin@example.com');
  });

  // The reviewer has to be told what accepting does before they do it.
  it('says what accepting writes and what rejecting does not', () => {
    queryState.proposals.data = page<EolProposal>([]);
    const html = renderToStaticMarkup(createElement(EolProposalsTab));
    expect(html).toContain('source_kind = inferred');
    expect(html).toContain('rejecting writes nothing');
  });
});

describe('Catalog ▸ End-of-life ▸ Gaps', () => {
  it('renders the loading state', () => {
    queryState.misses.isLoading = true;
    expect(renderToStaticMarkup(createElement(CatalogGapsTab))).toContain('Loading the gap list…');
  });

  it('renders the error state with a retry', () => {
    queryState.misses.isError = true;
    const html = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(html).toContain('t load the gap list.');
    expect(html).toContain('Retry');
  });

  it('shows each gap with how often it has been asked about', () => {
    queryState.misses.data = page([miss()]);
    const html = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(html).toContain('IOS-XE');
    expect(html).toContain('412');
  });

  // "Never asked" and "asked and got nothing" are different facts about a gap.
  it('distinguishes a gap never asked about from one already proposed against', () => {
    queryState.misses.data = page([miss()]);
    expect(renderToStaticMarkup(createElement(CatalogGapsTab))).toContain('never asked');

    queryState.misses.data = page([miss({ last_proposed_at: '2026-09-10T00:00:00Z' })]);
    const asked = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(asked).toContain('2026-09-10');
    expect(asked).not.toContain('never asked');
  });

  it('renders an empty gap list as an answer, not as a failure', () => {
    queryState.misses.data = page<CatalogMiss>([]);
    expect(renderToStaticMarkup(createElement(CatalogGapsTab)))
      .toContain('No gaps recorded');
  });

  // The availability pattern. A button that always 503s is worse than no
  // button, so it is not rendered until the deployment says a run would work.
  it('hides "Propose with AI" in a Core build and says why', () => {
    queryState.misses.data = page([miss()]);
    queryState.availability.data = { available: false, reason: 'edition', provider: 'none' };
    const html = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(html).not.toContain('Propose with AI');
    expect(html).toContain('Enterprise capability');
  });

  it('hides "Propose with AI" when no provider is configured, with a different reason', () => {
    queryState.misses.data = page([miss()]);
    queryState.availability.data = { available: false, reason: 'no_provider', provider: 'none' };
    const html = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(html).not.toContain('Propose with AI');
    expect(html).toContain('AI_PROVIDER');
  });

  // The inverse polarity: a gate that hid the button unconditionally would pass
  // both tests above and ship a dead capability.
  it('shows "Propose with AI" when the deployment can propose', () => {
    queryState.misses.data = page([miss()]);
    queryState.availability.data = { available: true, provider: 'anthropic' };
    const html = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(html).toContain('Propose with AI');
    expect(html).not.toContain('data-testid="propose-unavailable"');
  });

  // Availability not yet loaded must behave like "no", not like "yes".
  it('does not offer the button before availability is known', () => {
    queryState.misses.data = page([miss()]);
    queryState.availability.data = undefined;
    expect(renderToStaticMarkup(createElement(CatalogGapsTab))).not.toContain('Propose with AI');
  });

  it('offers the lookup that puts a product on the gap list', () => {
    queryState.misses.data = page<CatalogMiss>([]);
    const html = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(html).toContain('Check a product');
    expect(html).toContain('Look up');
  });

  // Provenance is SHOWN. A date with no visible source_kind is
  // indistinguishable from one somebody typed in.
  it('renders a resolved fact with its provenance and its citation', () => {
    queryState.misses.data = page<CatalogMiss>([]);
    queryState.lookup = {
      mutate: vi.fn(), isPending: false, isSuccess: true,
      data: {
        matched: true,
        miss_recorded: false,
        message: 'Resolved from the platform catalogues.',
        facts: [{
          key: 'eol.os.date', value: '2029-05-31',
          source_url: 'https://endoflife.date/ubuntu',
          source_kind: 'imported', source_ref: 'catalog:eol:row-1', confidence: 0,
        }],
      },
    };
    const html = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(html).toContain('eol.os.date');
    expect(html).toContain('2029-05-31');
    expect(html).toContain('imported');
    expect(html).toContain('catalog:eol:row-1');
    expect(html).toContain('href="https://endoflife.date/ubuntu"');
  });

  it('reports a miss as a miss, and says it went on the gap list', () => {
    queryState.misses.data = page<CatalogMiss>([]);
    queryState.lookup = {
      mutate: vi.fn(), isPending: false, isSuccess: true,
      data: {
        matched: false, miss_recorded: true, facts: [],
        message: 'The catalogues have nothing for this product. It has been added to the gap list.',
      },
    };
    expect(renderToStaticMarkup(createElement(CatalogGapsTab)))
      .toContain('added to the gap list');
  });

  // A catalogue row MATCHED and states no date. Zero facts, like a miss, and a
  // different answer: the product is in the catalogue, the upstream source has
  // not announced a date, and nothing went on the gap list. The server picks
  // the sentence; what this pins is that the server's sentence is what shows.
  it('shows a matched-but-dateless answer as its own outcome, not as a gap', () => {
    queryState.misses.data = page<CatalogMiss>([]);
    queryState.lookup = {
      mutate: vi.fn(), isPending: false, isSuccess: true,
      data: {
        matched: true, miss_recorded: false, facts: [],
        message: 'The catalogue has this product but publishes no end-of-life date for it.',
      },
    };
    const html = renderToStaticMarkup(createElement(CatalogGapsTab));
    expect(html).toContain('publishes no end-of-life date');
    expect(html).not.toContain('added to the gap list');
  });
});

describe('unavailableReason', () => {
  it('is empty when the capability is available', () => {
    expect(unavailableReason({ available: true })).toBe('');
    expect(unavailableReason(undefined)).toBe('');
  });

  // The two "no" answers have different fixes, and the copy has to say which.
  it('distinguishes the edition answer from the missing-provider answer', () => {
    const edition = unavailableReason({ available: false, reason: 'edition' });
    const noProvider = unavailableReason({ available: false, reason: 'no_provider' });
    expect(edition).not.toBe(noProvider);
    expect(edition).toContain('Enterprise');
    expect(noProvider).toContain('AI_PROVIDER');
  });
});
