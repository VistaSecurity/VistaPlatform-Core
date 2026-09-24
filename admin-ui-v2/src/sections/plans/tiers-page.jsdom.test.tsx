// @vitest-environment jsdom
//
// Plans & Pricing ▸ Tiers matrix + plan builder, MOUNTED THROUGH THE REAL PAGE
// over a real QueryClient and the real typed client, with only fetch stubbed.
//
// The regression (admin-UI data review RC-11): a cell edit rebuilt the tier's
// whole composition from the react-query cache and PUT it to an endpoint that
// deleted every row it was not sent. While that tier's composition was still
// loading, or after its load failed, the cache was empty — so one click wiped
// the tier, and every cap fell back to 0. The plan builder had the same hole:
// Save was enabled before the composition loaded and sent every lever blank
// (blank = unlimited), in two PUTs that could half-apply.
//
// Pinned here:
//   - a column is not editable until ITS composition query succeeded
//     (loading → inert, error → inert + Retry);
//   - a cell edit is one single-item PUT, never the multi-item endpoint;
//   - inactive catalogue items are not offered;
//   - the plan builder cannot save until the composition loaded, saves in ONE
//     PUT carrying only the changed levers + the version it opened on, and on
//     409 keeps the admin's edits and re-saves against the new version.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

type Mode = 'ready' | 'pending' | 'error';
const server = {
  mode: { [A]: 'ready', [B]: 'ready' } as Record<string, Mode>,
  version: { [A]: 'vA1', [B]: 'vB1' } as Record<string, string>,
  gets: { [A]: 0, [B]: 0 } as Record<string, number>,
  writes: [] as { method: string; path: string; body: unknown }[],
  tierPutStatus: 200,
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const tier = (id: string, name: string, order: number) => ({
  id, name, display_name: name, max_sensors: null, max_assets: null, max_users: null, retention_days: 30,
  price_cents: 1000, annual_price_cents: null, billing_interval: 'month', billing_method: 'invoice',
  stripe_price_id: null, stripe_price_id_annual: null, features: {}, limits: {}, addon_pricing: {}, metadata: {},
  is_active: true, is_custom: false, owner_tenant_id: null, display_order: order, deprecated_at: null,
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
});
const item = (key: string, display_name: string, kind: string, is_active: boolean, default_value: unknown, sort_order: number) => ({
  id: `00000000-0000-4000-8000-${String(sort_order).padStart(12, '0')}`, key, display_name, category: 'capability', kind,
  default_value, is_addon_eligible: false, is_active, sort_order,
});
const items = [
  item('custom_policies', 'Custom policies', 'boolean', true, { enabled: false }, 1),
  item('max_sensors', 'Max sensors', 'numeric_cap', true, { quantity: 0 }, 2),
  item('retired_lever', 'Retired lever', 'boolean', false, { enabled: false }, 3),
];
const composition = (id: string) => ({
  tier_id: id,
  version: server.version[id],
  entitlements: [
    { item_id: items[0].id, item_key: 'custom_policies', item_display_name: 'Custom policies', item_category: 'capability', item_kind: 'boolean', included_value: { enabled: false } },
    { item_id: items[1].id, item_key: 'max_sensors', item_display_name: 'Max sensors', item_category: 'capacity', item_kind: 'numeric_cap', included_value: { quantity: 25 } },
  ],
});

const fetchStub = vi.fn(async (req: Request) => {
  const path = new URL(req.url).pathname.replace(/^.*\/admin-service/, '');
  const ent = path.match(/^\/admin\/tiers\/([^/]+)\/entitlements$/);
  if (ent && req.method === 'GET') {
    const id = ent[1];
    server.gets[id] += 1;
    if (server.mode[id] === 'pending') return new Promise<Response>(() => {});
    if (server.mode[id] === 'error') return json({ error: 'boom' }, 500);
    return json(composition(id));
  }
  if (req.method !== 'GET') {
    const text = await req.clone().text();
    server.writes.push({ method: req.method, path, body: text ? JSON.parse(text) : null });
    const cell = path.match(/^\/admin\/tiers\/([^/]+)\/entitlements\/([^/]+)$/);
    if (cell && req.method === 'PUT') return json(composition(cell[1]));
    const tierPut = path.match(/^\/admin\/tiers\/([^/]+)$/);
    if (tierPut && req.method === 'PUT') {
      if (server.tierPutStatus === 409) {
        server.version[tierPut[1]] = 'vA2';
        return json({ error: 'tier entitlements changed since they were read', detail: 'Someone else changed this plan.', current_version: 'vA2' }, 409);
      }
      return json({ tier: tier(tierPut[1], 'Alpha', 1), message: 'ok' });
    }
    return json({ error: 'not stubbed' }, 404);
  }
  if (path === '/admin/tiers') return json({ tiers: [tier(A, 'Alpha', 1), tier(B, 'Beta', 2)] });
  if (path === '/admin/billable-items') return json({ items });
  return json({ error: 'not stubbed' }, 404);
});
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}
const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

const toastError = vi.fn();
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: (m: string) => toastError(m) } }));

type PageModule = typeof import('./tiers-page');
let page: PageModule;

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  page = await import('./tiers-page');
});
afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;

beforeEach(() => {
  server.mode = { [A]: 'ready', [B]: 'ready' };
  server.version = { [A]: 'vA1', [B]: 'vB1' };
  server.gets = { [A]: 0, [B]: 0 };
  server.writes.length = 0;
  server.tierPutStatus = 200;
  toastError.mockClear();
});
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
});

async function settle() {
  for (let i = 0; i < 10; i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  }
}
async function until<T>(read: () => T | null | undefined | false, what: string): Promise<T> {
  for (let i = 0; i < 50; i++) {
    const v = read();
    if (v) return v;
    await settle();
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(<QueryClientProvider client={qc}><page.TiersPage /></QueryClientProvider>));
  await until(() => rowFor('max_sensors'), 'the matrix');
}

const rowFor = (key: string) => Array.from(host.querySelectorAll('tbody tr')).find((tr) => tr.textContent?.includes(key));
/** The matrix cell for (item, tier column index: 0 = Alpha, 1 = Beta). */
const cell = (key: string, col: number) => rowFor(key)!.querySelectorAll('td')[1 + col] as HTMLTableCellElement;
const header = (col: number) => host.querySelectorAll('thead th')[1 + col] as HTMLTableCellElement;
const clickables = (el: Element) => Array.from(el.querySelectorAll<HTMLElement>('button, span, input'));

describe('Tiers matrix: a column is editable only once its composition loaded', () => {
  it('leaves a still-loading column inert, and a loaded column writes ONE item', async () => {
    server.mode[B] = 'pending';
    await mount();
    await until(() => header(0).dataset.tierState === 'ready', 'Alpha to load');
    expect(header(1).dataset.tierState).toBe('loading');

    // Beta: nothing to click, and clicking the cell sends nothing.
    for (const key of ['custom_policies', 'max_sensors']) {
      const td = cell(key, 1);
      expect(td.getAttribute('aria-disabled')).toBe('true');
      expect(clickables(td)).toHaveLength(0);
      act(() => td.click());
    }
    await settle();
    expect(server.writes).toHaveLength(0);

    // Alpha: toggling a gate is a single-item PUT naming that item only.
    const chip = cell('custom_policies', 0).querySelector('button')!;
    act(() => chip.click());
    await until(() => server.writes.length === 1, 'the cell write');
    expect(server.writes[0]).toEqual({
      method: 'PUT',
      path: `/admin/tiers/${A}/entitlements/custom_policies`,
      body: { included_value: { enabled: true } },
    });
    await settle();
    expect(server.writes.some((w) => w.path === `/admin/tiers/${A}/entitlements`)).toBe(false);
  });

  it('shows a failed column as an error with Retry, inert until the retry succeeds', async () => {
    server.mode[B] = 'error';
    await mount();
    await until(() => header(1).dataset.tierState === 'error', 'Beta to fail');
    expect(header(1).querySelector('[role="alert"]')?.textContent).toMatch(/Couldn.t load/);
    expect(clickables(cell('max_sensors', 1))).toHaveLength(0);
    act(() => cell('max_sensors', 1).click());
    await settle();
    expect(server.writes).toHaveLength(0);

    server.mode[B] = 'ready';
    const before = server.gets[B];
    act(() => header(1).querySelector<HTMLButtonElement>('[role="alert"] button')!.click());
    await until(() => header(1).dataset.tierState === 'ready', 'Beta to load after Retry');
    expect(server.gets[B]).toBeGreaterThan(before);
    expect(cell('custom_policies', 1).querySelector('button')).not.toBeNull();
    await settle();
    // Retry opened no plan builder and wrote nothing.
    expect(host.textContent).not.toMatch(/Edit plan/);
    expect(server.writes).toHaveLength(0);
  });

  it('does not offer inactive catalogue items', async () => {
    await mount();
    expect(rowFor('retired_lever')).toBeUndefined();
  });
});

async function openBuilder(col: number) {
  act(() => header(col).click());
  return until(() => Array.from(document.querySelectorAll<HTMLButtonElement>('button')).find((b) => /Save plan|Saving/.test(b.textContent ?? '')), 'the plan builder');
}
const saveButton = () => Array.from(document.querySelectorAll<HTMLButtonElement>('button')).find((b) => /Save plan|Saving/.test(b.textContent ?? ''))!;
const lever = (name: string) => document.querySelector<HTMLInputElement>(`input[aria-label="${name}"]`);
function type(input: HTMLInputElement, value: string) {
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  act(() => { set.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true })); });
}

describe('Plan builder: cannot save a composition it has not loaded', () => {
  it('keeps Save disabled while the composition loads, and after it fails', async () => {
    server.mode[B] = 'pending';
    await mount();
    await openBuilder(1);
    expect(saveButton().disabled).toBe(true);
    expect(lever('Max sensors')).toBeNull();
    act(() => saveButton().click());
    await settle();
    expect(server.writes).toHaveLength(0);
  });

  it('offers Retry after a failed load and stays unsaveable until it succeeds', async () => {
    server.mode[B] = 'error';
    await mount();
    await openBuilder(1);
    await until(() => Array.from(document.querySelectorAll('[role="alert"]')).some((el) => /can.t be saved/.test(el.textContent ?? '')), 'the load error');
    expect(saveButton().disabled).toBe(true);

    server.mode[B] = 'ready';
    const retry = Array.from(document.querySelectorAll<HTMLButtonElement>('button')).filter((b) => b.textContent?.includes('Retry')).pop()!;
    act(() => retry.click());
    await until(() => lever('Max sensors'), 'the levers after Retry');
    expect(saveButton().disabled).toBe(false);
  });

  it('saves identity + only the changed lever in ONE versioned PUT, never offering inactive items', async () => {
    await mount();
    await openBuilder(0);
    const input = await until(() => lever('Max sensors'), 'the Max sensors lever');
    expect(document.querySelector('[aria-label="Retired lever"]')).toBeNull();
    type(input, '30');
    act(() => saveButton().click());
    await until(() => server.writes.length === 1, 'the save');
    await settle();
    expect(server.writes).toHaveLength(1);
    const w = server.writes[0];
    expect(w.method).toBe('PUT');
    expect(w.path).toBe(`/admin/tiers/${A}`);
    const body = w.body as Record<string, unknown>;
    expect(body.entitlements_version).toBe('vA1');
    expect(body.entitlements).toEqual([{ item_key: 'max_sensors', included_value: { quantity: 30 } }]);
    expect(body.display_name).toBe('Alpha');
  });

  it('on 409 keeps the edit, reloads the composition and re-saves against the new version', async () => {
    await mount();
    await openBuilder(0);
    const input = await until(() => lever('Max sensors'), 'the Max sensors lever');
    type(input, '31');

    server.tierPutStatus = 409;
    const gets = server.gets[A];
    act(() => saveButton().click());
    await until(() => toastError.mock.calls.length === 1, 'the conflict message');
    expect(toastError.mock.calls[0][0]).toMatch(/Someone else changed this plan/);
    await until(() => server.gets[A] > gets, 'the composition reload');
    await settle();
    expect(lever('Max sensors')!.value).toBe('31');

    server.tierPutStatus = 200;
    act(() => saveButton().click());
    await until(() => server.writes.length === 2, 'the second save');
    const body = server.writes[1].body as Record<string, unknown>;
    expect(body.entitlements_version).toBe('vA2');
    expect(body.entitlements).toEqual([{ item_key: 'max_sensors', included_value: { quantity: 31 } }]);
  });
});
