// @vitest-environment jsdom
//
// Tenants ▸ Deleted, MOUNTED THROUGH THE REAL PAGE over a real
// QueryClient and the real typed client, with only fetch stubbed.
//
// Pins:
//   - the Deleted view reads ?deleted=only and the live directory never shows a
//     deleted tenant;
//   - Purge stays disabled until the operator types the tenant's exact name,
//     then sends DELETE /purge — remove the name check and the "disabled until
//     typed" assertion goes red;
//   - Restore sends POST /restore after a confirmation.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const LIVE = '55555555-5555-4555-8555-555555555555';
const GONE = '66666666-6666-4666-8666-666666666666';
const calls: string[] = [];

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const row = (id: string, name: string, deletedAt: string | null) => ({
  id, name, slug: name.toLowerCase().replace(/\s+/g, '-'), domain: null,
  subscription_tier: null, subscription_tier_id: '00000000-0000-0000-0000-000000000000', trial_ends_at: null,
  billing_email: '', payment_status: 'active', stripe_customer_id: null, sso_enabled: false, is_active: deletedAt === null,
  is_operator: false, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z', deleted_at: deletedAt,
});

const fetchStub = vi.fn(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;
  if (path.endsWith('/admin/platform/edition')) return json({ edition: 'msp', capabilities: { msp: true, billing: false } });
  if (path.endsWith('/admin/license/cap')) return json({ edition: 'msp', licensed: null, current: 1, operator: 0, grace_started_at: null, grace_days: null, grace_ends_at: null, state: 'uncapped' });
  if (path.endsWith('/admin/tenants') && req.method === 'GET') {
    return url.searchParams.get('deleted') === 'only'
      ? json({ tenants: [row(GONE, 'Old Co', '2026-09-25T17:47:00Z')], total: 1 })
      : json({ tenants: [row(LIVE, 'Live Co', null)], total: 1 });
  }
  if (path.endsWith(`/admin/tenants/${GONE}/restore`) && req.method === 'POST') {
    calls.push('restore');
    return json({ message: 'Tenant restored successfully' });
  }
  if (path.endsWith(`/admin/tenants/${GONE}/purge`) && req.method === 'DELETE') {
    calls.push('purge');
    return json({ message: 'Tenant purged successfully' });
  }
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
  calls.length = 0;
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

async function until<T>(read: () => T | null | undefined | false, what: string): Promise<T> {
  for (let i = 0; i < 50; i++) {
    const v = read();
    if (v) return v;
    await settle();
  }
  throw new Error(`timed out waiting for ${what}`);
}

const rowNamed = (name: string) => Array.from(host.querySelectorAll('tr')).find((tr) => tr.textContent?.includes(name));
const button = (label: string) => Array.from(host.querySelectorAll('button')).find((b) => b.textContent?.includes(label));

async function mountAndOpenDeleted() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(
    <QueryClientProvider client={qc}>
      <scope.ScopeProvider><page.TenantsPage /></scope.ScopeProvider>
    </QueryClientProvider>,
  ));
  await until(() => rowNamed('Live Co'), 'the live tenant row');
  expect(rowNamed('Old Co')).toBeUndefined();

  act(() => button('Deleted')!.click());
  const gone = await until(() => rowNamed('Old Co'), 'the deleted tenant row');
  expect(rowNamed('Live Co')).toBeUndefined();
  act(() => gone.click());
  return until(() => host.querySelector<HTMLInputElement>('#purge-confirm'), 'the deleted-tenant drawer');
}

function type(input: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  act(() => {
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

describe('Tenants ▸ Deleted', () => {
  it('purges only after the exact tenant name is typed', async () => {
    const input = await mountAndOpenDeleted();
    const purge = () => button('Purge permanently')!;
    expect(purge().disabled).toBe(true);

    type(input, 'old co');
    expect(purge().disabled).toBe(true);

    type(input, 'Old Co');
    expect(purge().disabled).toBe(false);
    act(() => purge().click());
    await until(() => calls.includes('purge'), 'the purge request');
    expect(calls).toEqual(['purge']);
  });

  it('restores after a confirmation', async () => {
    await mountAndOpenDeleted();
    act(() => button('Restore tenant')!.click());
    await until(() => calls.includes('restore'), 'the restore request');
    expect(confirmStub.mock.calls[0][0]).toMatch(/^Restore Old Co\?/);
    expect(calls).toEqual(['restore']);
  });
});
