// @vitest-environment jsdom
//
// The Findings list's free-text search, as a REQUEST.
//
// The page's search box used to narrow `findings` after this hook returned, and
// this hook stops at FINDINGS_PAGE_CAP pages (five of 200). On a tenant with
// more than a thousand findings the box was therefore searching a PREFIX of the
// stream: a `?q=<product>` link into the 1,200th finding rendered "no findings
// match", which on screen is indistinguishable from a clean estate. The
// software surfaces emit exactly that link, for a product installed anywhere in
// the catalogue.
//
// So the thing worth pinning is not "the term is in the query key" — it is that
// the term reaches the SERVER. This drives the real hook against a stubbed
// client and reads the query parameters it was called with.
//
// `findings_search_integration_test.go` is the other half: it seeds 1,500
// findings and searches for the one at position 1,200, which is the assertion
// this file cannot make.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// `vi.mock` is hoisted above every top-level binding, so the stub is declared
// with `vi.hoisted` — a factory closing over a plain `const` here would run
// before that const exists.
const { complianceGet } = vi.hoisted(() => ({
  complianceGet: vi.fn(async () => ({
    data: { findings: [], total: 0, page: 1, page_size: 200, producer_counts: {} },
  })),
}));
vi.mock('../../lib/clients', () => ({
  clients: { compliance: { GET: complianceGet } },
}));

import { useFindingsList, type FindingSubjectFilter } from './queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

function Probe({ producer, subject, search }: {
  producer?: string; subject?: FindingSubjectFilter; search?: string;
}) {
  useFindingsList(true, producer, subject, search);
  return null;
}

async function run(props: Parameters<typeof Probe>[0]): Promise<void> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(<QueryClientProvider client={qc}><Probe {...props} /></QueryClientProvider>);
  });
  // The fetch resolves in a microtask; a couple of turns is enough because the
  // stub never suspends.
  for (let i = 0; i < 10 && complianceGet.mock.calls.length === 0; i++) {
    await act(async () => { await Promise.resolve(); });
  }
}

/** The path and query parameters of the first call. */
function firstCall(): { path: string; query: Record<string, unknown> } {
  // The stub is declared with no parameters (it ignores them), so its recorded
  // calls are typed as an empty tuple. Read through `unknown` rather than
  // widening the stub's own signature, which would make the mock's shape
  // depend on the assertion rather than on the client's.
  const calls = complianceGet.mock.calls as unknown as [string, { params: { query: Record<string, unknown> } }][];
  if (calls.length === 0) throw new Error('the hook made no request at all');
  return { path: calls[0][0], query: calls[0][1].params.query };
}

const sentQuery = () => firstCall().query;

beforeEach(() => { complianceGet.mockClear(); });
afterEach(() => {
  act(() => { root?.unmount(); });
  container?.remove();
});

describe('useFindingsList', () => {
  it('sends the search term to the server as `q`', async () => {
    await run({ search: 'openssl' });
    expect(firstCall().path).toBe('/findings');
    expect(sentQuery().q).toBe('openssl');
  });

  it('trims it, so a term that is only whitespace is not a filter', async () => {
    // A box cleared to spaces must widen back to the whole list. Sending
    // `"   "` would filter on nothing and return nothing, which reads as an
    // empty estate.
    await run({ search: '   ' });
    expect(sentQuery()).not.toHaveProperty('q');
  });

  it('omits `q` entirely when nothing was typed', async () => {
    // The other polarity. Sending `q: ''` is harmless today and is exactly the
    // sort of thing a server later treats as "match the empty string".
    await run({});
    expect(sentQuery()).not.toHaveProperty('q');
  });

  it('keeps the page cap for the unsearched stream', async () => {
    // The cap is what stops opening the page from paging a whole estate. A
    // search narrows server-side first, so the cap is reached far less often —
    // it is not replaced by the search.
    await run({});
    expect(sentQuery().page_size).toBe(200);
  });

  it('sends the search ALONGSIDE the other server-side filters', async () => {
    // They compose on the server. A search that dropped the producer (or the
    // reverse) would answer a question the user did not ask, under a heading
    // that says otherwise.
    await run({
      producer: 'eol',
      subject: { subjectType: 'software_install', subjectId: 'aa-bb' },
      search: 'openssl',
    });
    expect(sentQuery()).toMatchObject({
      producer: 'eol',
      subject_type: 'software_install',
      subject_id: 'aa-bb',
      q: 'openssl',
    });
  });
});
