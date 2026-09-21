// @vitest-environment jsdom
//
// The work queue, MOUNTED.
//
// The defect this pins is not visible on screen and produces no error: the
// page used to call GET /tickets with no parameters and treat the response as
// the whole tenant. That endpoint paginates and defaults to twenty rows, so
// "Open work", "Overdue", "Due soon" and "Keeping pace" each described the
// newest twenty tickets while appearing to describe everything — a number that
// is simply wrong, and wronger the more tickets you have.
//
// So the assertions below are deliberately about WHERE a number comes from
// rather than what it says. Each fixture gives the stats endpoint and the list
// endpoint DELIBERATELY DIFFERENT numbers; a card sourced from the rows cannot
// pass, and a card sourced from stats cannot fail. A test that fed both
// endpoints consistent data would pass against the original bug.
//
// Follows rail-drawer.jsdom.test.tsx: jsdom + React's own `act`, no
// testing-library, module-boundary stubs for everything that is not the page.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/** Every GET the page issues, in order, so the REQUEST can be asserted. */
const calls: { path: string; query?: Record<string, unknown> }[] = [];

let statsPayload: unknown = {
  stats: { by_status: { open: 400, in_progress: 40, resolved: 300, closed: 60 }, by_category: {}, overdue: 90, due_soon: 30, total: 800 },
};
let listPayload: unknown = { tickets: [], total: 800, page: 1, page_size: 25 };
let statsFails = false;

vi.mock('../../lib/clients', () => ({
  clients: {
    compliance: {
      GET: vi.fn(async (path: string, opts?: { params?: { query?: Record<string, unknown> } }) => {
        calls.push({ path, query: opts?.params?.query });
        if (path === '/tickets/stats') {
          return statsFails ? { data: undefined, error: { error: 'boom' } } : { data: statsPayload, error: undefined };
        }
        if (path === '/tickets') return { data: listPayload, error: undefined };
        if (path === '/tickets/{id}') return { data: { ticket: null }, error: undefined };
        return { data: undefined, error: undefined };
      }),
    },
    auth: { GET: vi.fn(async () => ({ data: { users: [] }, error: undefined })) },
  },
}));

vi.mock('@vistasecurity/primitives/auth', () => ({ useAuth: () => ({ tenant: { id: 't-1' } }) }));
vi.mock('./ticket-drawer', () => ({ TicketDrawer: () => null }));
vi.mock('./create-ticket-modal', () => ({ CreateTicketModal: () => <div id="create-modal" /> }));

import { QueuePage } from './queue-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

/**
 * Flush until react-query has delivered.
 *
 * A single microtask tick is not enough: the query resolves, then react-query
 * schedules a notification, then React re-renders. Under-flushing leaves every
 * card reading its loading placeholder, and an assertion written against that
 * state would pass for the wrong reason.
 */
async function settle(): Promise<void> {
  for (let i = 0; i < 6; i += 1) {
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  }
}

async function mount(at = '/remediation/queue'): Promise<void> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[at]}><QueuePage /></MemoryRouter>
      </QueryClientProvider>,
    );
  });
  await settle();
}

/** The big number inside the card whose eyebrow reads `label`. */
function cardValue(label: string): string | null {
  const eyebrow = Array.from(container.querySelectorAll('.eyebrow-app'))
    .find((el) => el.textContent?.trim() === label);
  return eyebrow?.parentElement?.querySelector('.mono')?.textContent?.trim() ?? null;
}

const listCalls = () => calls.filter((c) => c.path === '/tickets');
const lastList = () => listCalls()[listCalls().length - 1];

beforeEach(() => {
  calls.length = 0;
  statsFails = false;
  statsPayload = {
    stats: { by_status: { open: 400, in_progress: 40, resolved: 300, closed: 60 }, by_category: {}, overdue: 90, due_soon: 30, total: 800 },
  };
  listPayload = { tickets: [], total: 800, page: 1, page_size: 25 };
});

afterEach(async () => {
  await act(async () => { root.unmount(); });
  container.remove();
  vi.clearAllMocks();
});

describe('the metric cards', () => {
  it('read tenant-wide stats, not the rows on the page', async () => {
    // The list returns an EMPTY page while stats reports a busy tenant. A card
    // computed from rows reads 0 here; a card sourced from stats reads 440.
    await mount();
    expect(cardValue('Open work')).toBe('440');   // 400 open + 40 in progress
    expect(cardValue('Overdue')).toBe('90');
    expect(cardValue('Due soon')).toBe('30');
    expect(cardValue('Resolved')).toBe('360');    // 300 resolved + 60 closed
  });

  it('computes "keeping pace" from the tenant totals', async () => {
    // (440 - 90 - 30) / 440 = 72.7% -> 73
    await mount();
    expect(cardValue('Keeping pace')).toBe('73%');
  });

  it('says it could not load rather than showing a plausible zero', async () => {
    // A stats failure that rendered 0 would be indistinguishable from an empty
    // tenant, which is the worse of the two errors: it reads as "all clear".
    statsFails = true;
    await mount();
    expect(cardValue('Open work')).toBe('—');
    expect(container.textContent).toContain("couldn't load totals");
  });

  it('asks the stats endpoint exactly once, without filters', async () => {
    // The cards are the denominator the filtered list is a slice of, so they
    // must NOT narrow with the filters.
    await mount();
    const statsCalls = calls.filter((c) => c.path === '/tickets/stats');
    expect(statsCalls).toHaveLength(1);
    expect(statsCalls[0].query).toBeUndefined();
  });
});

describe('the list request', () => {
  it('always asks for an explicit page and page size', async () => {
    // The original bug in one assertion: with no page_size the server applies
    // its own default of 20 and the client has no idea it received a page.
    await mount();
    const q = lastList()?.query;
    expect(q?.page).toBe(1);
    expect(typeof q?.page_size).toBe('number');
  });

  it('sends the slice as a server-side status filter', async () => {
    await mount();
    expect(lastList()?.query).toMatchObject({ status: 'open' });
  });

  it('reports the server total, not the number of rows it received', async () => {
    listPayload = { tickets: [], total: 800, page: 1, page_size: 25 };
    await mount();
    expect(container.textContent).toContain('800 items');
  });

  it('offers pagination when the total exceeds one page', async () => {
    await mount();
    expect(container.textContent).toContain('page 1 of 32'); // ceil(800 / 25)
  });

  it('hides pagination when everything fits on one page', async () => {
    listPayload = { tickets: [], total: 3, page: 1, page_size: 25 };
    await mount();
    expect(container.textContent).not.toContain('page 1 of');
  });
});

describe('deep links', () => {
  it('honours ?category= so Progress can drill into one backlog', async () => {
    // Progress links to /remediation/queue?category=<c>. Without this the link
    // lands on an unfiltered queue -- the user clicks "lifecycle: 12 open" and
    // gets everything, with no sign anything was meant to happen.
    await mount('/remediation/queue?category=lifecycle');
    expect(lastList()?.query).toMatchObject({ category: 'lifecycle' });
  });

  it('starts unfiltered when no category is given', async () => {
    await mount();
    expect(lastList()?.query).not.toHaveProperty('category');
  });
});

describe('creating a ticket', () => {
  it('offers a New ticket control', async () => {
    // The whole reason for this change: there was no way to open a general
    // ticket at all, so `general` was a category no user could produce.
    await mount();
    const btn = Array.from(container.querySelectorAll('button'))
      .find((b) => b.textContent?.includes('New ticket'));
    expect(btn).toBeTruthy();
  });

  it('is not permission-gated — reporting is open to any member', async () => {
    // Filing a ticket is reporting, not triage. If this button ever acquires a
    // PermissionGate, a viewer loses the ability to report what only they saw.
    await mount();
    const btn = Array.from(container.querySelectorAll('button'))
      .find((b) => b.textContent?.includes('New ticket'));
    await act(async () => { btn!.click(); });
    expect(container.querySelector('#create-modal')).toBeTruthy();
  });
});
