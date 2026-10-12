// @vitest-environment jsdom
//
// The category chips come from a static list, so choosing one (or getting an
// empty result) never removes the others.
import { act, createElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const post = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({ clients: { audit: { POST: post } } }));

import { ScopeProvider } from '../../app/scope';
import { ActivityPage } from './activity-page';
import { AUDIT_EVENT_CATEGORIES } from './audit-categories';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

const pagination = { page: 1, page_size: 50, total: 0, total_pages: 1, has_prev: false, has_next: false };
const log = { id: '1', action: 'x', event_category: 'asset', user_type: 'platform', occurred_at: '2026-10-01T00:00:00Z' };

beforeEach(() => {
  post.mockReset();
  post.mockImplementation(async (_p: string, opts: { body: { filters: { event_category?: string[] } } }) => {
    const cat = opts.body.filters.event_category?.[0];
    if (cat === 'job') return { data: { logs: [], pagination }, response: new Response(null, { status: 200 }) }; // empty result
    return { data: { logs: [log], pagination: { ...pagination, total: 1 } }, response: new Response(null, { status: 200 }) };
  });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

// Let the mocked request resolve and React Query publish the result.
async function settle() {
  for (let i = 0; i < 5; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
}

const chips = () => Array.from(container.querySelectorAll('button.op-chip')).map((b) => b.textContent);
const chip = (label: string) =>
  Array.from(container.querySelectorAll('button.op-chip')).find((b) => b.textContent === label) as HTMLButtonElement;

describe('ActivityPage category chips', () => {
  it('keeps every category chip after choosing one, including on an empty result', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    await act(async () => {
      root.render(createElement(QueryClientProvider, { client: qc },
        createElement(ScopeProvider, null, createElement(ActivityPage))));
    });
    for (const c of AUDIT_EVENT_CATEGORIES) expect(chips()).toContain(c);

    await act(async () => { chip('asset').click(); });
    await settle();
    for (const c of AUDIT_EVENT_CATEGORIES) expect(chips()).toContain(c);
    expect(chip('asset').className).toContain('active');

    await act(async () => { chip('job').click(); });
    await settle();
    expect(container.textContent).toContain('No matching audit entries');
    for (const c of AUDIT_EVENT_CATEGORIES) expect(chips()).toContain(c);
    expect(chip('job').className).toContain('active');
  });
});
