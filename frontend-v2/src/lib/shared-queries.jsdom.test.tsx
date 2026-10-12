// @vitest-environment jsdom
//
// One cache entry per shared read endpoint, driven through the REAL screens.
//
// Dashboard, Posture, Remediation and Settings each used to carry their own
// copy of these reads under their own key, so moving between them fetched
// identical data again, and a mutation could refresh only the copy it knew.
// These tests mount the real pages against one QueryClient and count requests.
//
// MUTATIONS (recorded in the PR):
//   - give one consumer its own key (e.g. Dashboard's `useRiskSummary` call
//     replaced by an inline useQuery under ['dashboard','risk-summary']): the
//     "one /risk/summary request" test fails with two requests;
//   - point FrameworksPage's refresh() back at a private key: the "activating a
//     framework refetches the shared read" test fails, because the other
//     screen's observer is never told its data is stale.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock('./clients', () => ({ clients: { inventory: api, compliance: api, sensor: api, device: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/auth', () => ({ useAuth: () => ({ user: { id: 'u1' } }) }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  TENANT_PERMISSIONS: new Proxy({}, { get: () => new Proxy({}, { get: (_t, k) => String(k) }) }),
  usePermissions: () => ({ can: () => true }),
}));

import { useFrameworksAvailable } from './shared-queries';
const { DashboardPage } = await import('../sections/dashboard/dashboard-page');
const { PostureOverview } = await import('../sections/posture/posture-overview');
const { FrameworksPage } = await import('../sections/settings/pages-policies');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  api.GET.mockReset(); api.POST.mockReset();
  qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 60_000 } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

const flush = async () => { await act(async () => { await new Promise((r) => setTimeout(r, 30)); }); };
const callsTo = (path: string) => api.GET.mock.calls.filter((c) => c[0] === path).length;
const wrap = (el: React.ReactNode) => <MemoryRouter><QueryClientProvider client={qc}>{el}</QueryClientProvider></MemoryRouter>;

let frameworks: unknown[];
function respond(path: string): { data?: unknown; error?: unknown } {
  switch (path) {
    case '/risk/summary': return { data: { risk_summary: { total_assets: 3 } } };
    case '/risk/posture/trend': return { data: { trend: [] } };
    case '/pqc/progress': return { data: { progress: {} } };
    case '/frameworks/available': return { data: { frameworks } };
    default: return { error: { error: 'not under test' } };
  }
}
beforeEach(() => {
  frameworks = [];
  api.GET.mockImplementation(async (path: string) => respond(path));
});

describe('shared read endpoints', () => {
  it('Dashboard then Posture issue ONE /risk/summary and ONE /risk/posture/trend request', async () => {
    await act(async () => { root.render(wrap(<DashboardPage />)); });
    await flush();
    expect(callsTo('/risk/summary')).toBe(1);

    await act(async () => { root.render(wrap(<PostureOverview />)); });
    await flush();
    expect(callsTo('/risk/summary')).toBe(1);
    expect(callsTo('/risk/posture/trend')).toBe(1);
  });

  it('activating a framework refetches the shared /frameworks/available read', async () => {
    const fw = {
      platform_framework: { id: 'fw1', name: 'Fw One', version: '1', controls_count: 1 },
      is_licensed: false, is_platform_default: false, preview_score: null,
    };
    frameworks = [fw];
    api.POST.mockImplementation(async () => {
      frameworks = [{ ...fw, is_licensed: true }];
      return { response: { ok: true } };
    });
    // A second screen observing the same read (Posture's framework browser, the
    // Dashboard hygiene tile) — it must hear about the change too.
    let seen: unknown[] | undefined;
    function OtherScreen() { seen = useFrameworksAvailable().data; return null; }
    await act(async () => {
      root.render(wrap(<><OtherScreen /><FrameworksPage meta={{ job: 'x' } as never} /></>));
    });
    await flush();
    expect(callsTo('/frameworks/available')).toBe(1);

    const activate = [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Activate'));
    expect(activate).toBeTruthy();
    await act(async () => { activate!.click(); });
    await flush();

    expect(callsTo('/frameworks/available')).toBe(2);
    expect((seen as Array<{ is_licensed: boolean }>)[0].is_licensed).toBe(true);
  });
});
