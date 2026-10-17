// @vitest-environment jsdom
//
// Proposed cables in Discovery → Approvals (DCIM BUILD_PLAN row 3.3), through
// the REAL ApprovalsPage: an LLDP / CDP proposal is listed with both ends and
// Approve / Reject post to the cable's approve / reject routes. Five states:
// the list (default), none pending (empty: the page's own empty state, which
// counts this read), loading, a failed read (never "nothing to review"), and a
// successful approve.
//
// MUTATIONS: drop <ProposedCablesSection> from approvals-page.tsx → default and
// success fail; drop cablesQ from the page's queryNote list → empty-vs-error
// fails (a failed cable read would read as inbox zero).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api, devices: api, sensors: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  TENANT_PERMISSIONS: new Proxy({}, { get: () => new Proxy({}, { get: (_t, k) => String(k) }) }),
}));

const { ApprovalsPage } = await import('./approvals-page');
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ok = (data: unknown) => ({ data, response: { ok: true, status: 200 } });
const NOW = new Date().toISOString();
const SW1 = '11111111-1111-4111-8111-111111111111';
const SW2 = '22222222-2222-4222-8222-222222222222';
const PROPOSAL = {
  id: 'cab-1', tenant_id: 't', type: null, operational_status: 'connected', label: 'lldp', color: null, length: null, length_unit: null,
  business_unit_id: null, source_kind: 'measured', source_ref: 'interrogation:job', custom_fields: {}, external_ids: {},
  description: null, comments: null, status: 'pending', first_seen_at: NOW, last_seen_at: NOW, observation_count: 3,
  lldp_confirmed_at: null, approved_by: null, approved_at: null, created_at: NOW, updated_at: NOW, created_by: null,
  a_terminations: [{ termination_kind: 'interface', termination_id: 'i1', asset_id: SW2, asset_name: 'dist-sw-2', circuit_id: null, name: 'Ethernet1/1' }],
  b_terminations: [{ termination_kind: 'interface', termination_id: 'i2', asset_id: SW1, asset_name: 'core-sw-1', circuit_id: null, name: 'GigabitEthernet1/0/1' }],
};

let cables: () => Promise<unknown>;
let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  cables = async () => ok({ data: [PROPOSAL], pagination: { total: 1, limit: 100, offset: 0, next_offset: null } });
  api.GET.mockReset().mockImplementation(async (path: string) => {
    switch (path) {
      case '/infrastructure-assets': return ok({ assets: [], pagination: { total: 0, page: 1, page_size: 100 } });
      case '/approvals/merge-proposals': return ok({ merge_proposals: [], total: 0 });
      case '/approvals/relationships': return ok({ relationship_proposals: [], total: 0 });
      case '/approvals/classes': return ok({ class_proposals: [], total: 0 });
      case '/approvals/merge-proposals/auto-accepted': return ok({ merges: [], window_days: 30 });
      case '/dcim/cables': return cables();
      default: throw new Error(`unmocked GET ${path}`);
    }
  });
  api.POST.mockReset().mockResolvedValue(ok({ data: { ...PROPOSAL, status: 'active' } }));
  qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

const settle = async () => { await act(async () => { await new Promise((r) => setTimeout(r, 30)); }); };
const render = async () => {
  await act(async () => {
    root.render(<MemoryRouter><QueryClientProvider client={qc}><ApprovalsPage /></QueryClientProvider></MemoryRouter>);
  });
  await settle();
};
const byTest = (id: string) => host.querySelector(`[data-testid="${id}"]`);

it('default: a proposed cable is listed with both ends linked and the protocol that saw it', async () => {
  await render();
  const row = byTest('proposed-cable-row');
  expect(row).not.toBeNull();
  expect(row!.textContent).toContain('dist-sw-2:Ethernet1/1');
  expect(row!.textContent).toContain('core-sw-1:GigabitEthernet1/0/1');
  expect(row!.textContent).toContain('seen by LLDP · 3 observations');
  expect([...row!.querySelectorAll('a')].map((a) => a.getAttribute('href'))).toEqual([`/inventory/assets/${SW2}`, `/inventory/assets/${SW1}`]);
  expect(host.textContent).toContain('Proposed cables (1)');
  // Asked for the pending cables only.
  expect(api.GET).toHaveBeenCalledWith('/dcim/cables', { params: { query: { status: 'pending', limit: 100 } } });
});

it('empty: no proposals → no section, and the queue reads as empty', async () => {
  cables = async () => ok({ data: [], pagination: { total: 0, limit: 100, offset: 0, next_offset: null } });
  await render();
  expect(byTest('proposed-cables-section')).toBeNull();
  expect(host.textContent).toContain('Nothing awaiting review');
});

it('loading: the section says it is loading and the empty state is withheld', async () => {
  cables = () => new Promise(() => {});
  await render();
  expect(byTest('proposed-cables-loading')).not.toBeNull();
  expect(host.textContent).not.toContain('Nothing awaiting review');
});

it('error: a failed read is a banner with Retry, never "nothing awaiting review"', async () => {
  cables = async () => ({ error: { error: { message: 'boom' } }, response: { ok: false, status: 500 } });
  await render();
  expect(byTest('proposed-cables-error')).not.toBeNull();
  expect(host.textContent).not.toContain('Nothing awaiting review');
});

it('success: Approve posts to the approve route, Reject to the reject route', async () => {
  await render();
  await act(async () => { host.querySelector<HTMLButtonElement>('[aria-label^="Approve cable"]')!.click(); });
  await settle();
  expect(api.POST).toHaveBeenCalledWith('/dcim/cables/{id}/approve', { params: { path: { id: 'cab-1' } } });
  await act(async () => { host.querySelector<HTMLButtonElement>('[aria-label^="Reject cable"]')!.click(); });
  await settle();
  expect(api.POST).toHaveBeenCalledWith('/dcim/cables/{id}/reject', { params: { path: { id: 'cab-1' } } });
});
