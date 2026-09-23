// @vitest-environment jsdom
//
// Tenants ▸ row ▸ drawer ▸ "Your own tenant", MOUNTED THROUGH THE REAL PAGE.
//
// operator-tenant-control.jsdom.test.tsx mounts the control alone with a fixed
// prop, so it cannot see how the drawer is fed. This one drives the real
// TenantsPage → TenantDrawer → OperatorTenantControl over a real QueryClient
// and the real typed client, with only fetch stubbed (the stub keeps the
// server's state, so a refetch returns what the PUT saved).
//
// The regression it pins: the drawer used to receive a copy of the row taken
// at click time. After a successful toggle the checkbox snapped back to its
// old value, and the next click re-sent the SAME change ("Mark … as your own
// tenant?" again) — the admin could not unmark without reopening the drawer.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const ID = '44444444-4444-4444-8444-444444444444';
const server = {
  isOperator: false,
  puts: [] as string[],
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const tenantRow = () => ({
  id: ID, name: 'Acme', slug: 'acme', domain: null,
  subscription_tier: null, subscription_tier_id: '00000000-0000-0000-0000-000000000000', trial_ends_at: null,
  billing_email: '', payment_status: 'active', stripe_customer_id: null, sso_enabled: false, is_active: true,
  is_operator: server.isOperator, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z', deleted_at: null,
});
const cap = () => ({
  edition: 'msp', licensed: 10, current: server.isOperator ? 0 : 1, operator: server.isOperator ? 1 : 0,
  grace_started_at: null, grace_days: 30, grace_ends_at: null, state: 'under',
});

const fetchStub = vi.fn(async (req: Request) => {
  const path = new URL(req.url).pathname;
  if (path.endsWith('/admin/platform/edition')) return json({ edition: 'enterprise', capabilities: { msp: true, billing: false } });
  if (path.endsWith('/admin/license/cap')) return json(cap());
  if (path.endsWith(`/admin/tenants/${ID}/operator`) && req.method === 'PUT') {
    const body = await req.clone().text();
    server.puts.push(body);
    server.isOperator = (JSON.parse(body) as { is_operator: boolean }).is_operator;
    return json({ id: ID, is_operator: server.isOperator, cap: cap() });
  }
  if (path.endsWith('/admin/tenants') && req.method === 'GET') return json({ tenants: [tenantRow()], total: 1 });
  // Everything else the drawer reads (stats, health, cost…) is irrelevant here.
  return json({ error: 'not stubbed' }, 404);
});
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}
const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: () => true }) };
});
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

type PageModule = typeof import('./tenants-page');
type ScopeModule = typeof import('../../app/scope');
let page: PageModule;
let scope: ScopeModule;

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  page = await import('./tenants-page');
  scope = await import('../../app/scope');
});
afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;
const confirmStub = vi.fn((_msg?: string) => true);

beforeEach(() => {
  server.isOperator = false;
  server.puts.length = 0;
  confirmStub.mockClear();
  vi.stubGlobal('confirm', confirmStub);
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

async function until<T>(read: () => T | null | undefined, what: string): Promise<T> {
  for (let i = 0; i < 50; i++) {
    const v = read();
    if (v) return v;
    await settle();
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function mountAndOpenDrawer() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(
    <QueryClientProvider client={qc}>
      <scope.ScopeProvider><page.TenantsPage /></scope.ScopeProvider>
    </QueryClientProvider>,
  ));
  const row = await until(() => Array.from(host.querySelectorAll('tr')).find((tr) => tr.textContent?.includes('Acme')), 'the tenant row');
  act(() => row.click());
  return until(() => host.querySelector<HTMLInputElement>('[data-testid="operator-tenant-control"] input'), 'the operator checkbox');
}

const checkbox = () => host.querySelector<HTMLInputElement>('[data-testid="operator-tenant-control"] input')!;

describe('Tenants drawer: "Your own tenant" reflects the saved value', () => {
  it('shows the new value after a toggle, and the next click reverses it', async () => {
    const box = await mountAndOpenDrawer();
    expect(box.checked).toBe(false);

    act(() => checkbox().click());
    await until(() => server.puts.length === 1, 'the first PUT');
    await settle();
    expect(server.puts[0]).toBe('{"is_operator":true}');
    expect(confirmStub.mock.calls[0][0]).toMatch(/^Mark Acme as your own tenant\?/);
    // The drawer shows what was saved — not the row as it was at click time.
    await until(() => checkbox().checked, 'the checkbox to show the saved value');

    act(() => checkbox().click());
    await until(() => server.puts.length === 2, 'the second PUT');
    await settle();
    // The second click is the reverse action, not a repeat of the first.
    expect(confirmStub.mock.calls[1][0]).toMatch(/^Unmark Acme as your own tenant\?/);
    expect(server.puts[1]).toBe('{"is_operator":false}');
    await until(() => !checkbox().checked, 'the checkbox to clear');
  });
});
