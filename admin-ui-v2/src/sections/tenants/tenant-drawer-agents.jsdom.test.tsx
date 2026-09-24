// @vitest-environment jsdom
//
// Tenants ▸ row ▸ drawer ▸ Usage ▸ Agents, MOUNTED THROUGH THE REAL PAGE over a
// real QueryClient and the real typed client, only fetch stubbed (admin-ui
// review RC-16, tenants-overview-fleet-2 — the owner's original complaint).
//
// The tile read "Sensors 3" for a tenant with one customer sensor and one
// discovery agent: the server counted the two platform-managed rows and missed
// the agent. It is now "Agents 2", with the breakdown under it and the
// platform rows named separately.
//
// Mutations run (each red, then restored green):
//   - value back to stats.sensor_count → "1"; red.
//   - label back to "Sensors" → red.
//   - agentBreakdown drops the platform-managed clause → red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

const ID = '66666666-6666-4666-8666-666666666666';
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const tenantRow = {
  id: ID, name: 'Northwind', slug: 'northwind', domain: null,
  subscription_tier: null, subscription_tier_id: '00000000-0000-0000-0000-000000000000', trial_ends_at: null,
  billing_email: '', payment_status: 'active', stripe_customer_id: null, sso_enabled: false, is_active: true,
  is_operator: false, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z', deleted_at: null,
};
const stats = {
  tenant_id: ID, tenant_name: 'Northwind', user_count: 4, asset_count: 12,
  sensor_count: 1, device_agent_count: 1, agent_count: 2, platform_managed_count: 2,
  created_at: '2026-09-01T00:00:00Z', last_activity: '2026-09-22T00:00:00Z', storage_used: 0, api_requests: 0,
};

const fetchStub = vi.fn(async (req: Request) => {
  const path = new URL(req.url).pathname;
  if (path.endsWith('/admin/platform/edition')) return json({ edition: 'enterprise', capabilities: { msp: true, billing: false } });
  if (path.endsWith(`/admin/tenants/${ID}/stats`)) return json({ stats });
  if (path.endsWith('/admin/tenants') && req.method === 'GET') return json({ tenants: [tenantRow], total: 1 });
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

describe('Tenant drawer Usage ▸ Agents', () => {
  it('shows customer agents with the breakdown, platform rows named apart', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
    host = document.createElement('div');
    document.body.appendChild(host);
    root = createRoot(host);
    act(() => root!.render(
      <QueryClientProvider client={qc}>
        <scope.ScopeProvider><page.TenantsPage /></scope.ScopeProvider>
      </QueryClientProvider>,
    ));
    const row = await until(() => Array.from(host.querySelectorAll('tr')).find((tr) => tr.textContent?.includes('Northwind')), 'the tenant row');
    act(() => row.click());

    const tile = await until(
      () => Array.from(host.querySelectorAll('div')).find((d) => d.firstElementChild?.textContent === 'Agents'),
      'the Agents tile',
    );
    const [, value, sub] = Array.from(tile.children).map((c) => c.textContent);
    expect(value).toBe('2');
    expect(sub).toBe('1 sensor · 1 discovery agent · +2 platform-managed');
    // The old tile is gone rather than shown beside the new one.
    expect(Array.from(host.querySelectorAll('div')).some((d) => d.firstElementChild?.textContent === 'Sensors')).toBe(false);
  });
});
